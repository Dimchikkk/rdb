use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use nix::fcntl::OFlag;
use std::os::unix::io::{AsRawFd, RawFd};
use anyhow::{bail, Result};
use copperline::Copperline;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::ptrace::{attach, cont, detach, traceme, write_user, read_user, setregs, getregs };
use nix::unistd::{execv, fork, ForkResult, pipe2, Pid};
use nix::sys::signal::{kill, Signal};
use nix::libc::{user_regs_struct, user_fpregs_struct};
use registers::{RegisterFormat, RegisterId, RegisterInfo, RegisterType, RegisterValue, Registers};

mod breakpoints;
mod registers;

fn main() -> Result<()> {
    let mut args = std::env::args();

    if args.len() == 1 {
        bail!("\n\nUsage:\nTo attach to process: ./rdb -p <PID>\nTo launch program: ./rdb program_path\n");
    }

    if args.len() == 3 && args.nth(1).unwrap() == "-p" {
        let pid_str = args.nth(0).unwrap();
        let pid_num = pid_str.parse::<i32>().expect("PID should be a number");
        let pid = Pid::from_raw(pid_num);
        let mut process = Process { pid, status: None, terminate_on_end: false };
        process.attach()?;
        main_loop(&mut process)?;
    } else {
        let program_path = args.nth(1).unwrap();
        let mut process = Process::launch(program_path)?;
        main_loop(&mut process)?;
    }
    Ok(())
}

fn main_loop(process: &mut Process) -> Result<()> {
    let mut cl = Copperline::new();
    while let Ok(line) = cl.read_line("rdb> ", copperline::Encoding::Utf8) {
        if !line.is_empty() {
            if line.starts_with("continue") {
                process.resume()?;
                let reason = process.wait_on_signal()?;
                print_stop_reason(process, reason);
            }
        }
        cl.add_history(line);
    }

    Ok(())
}

fn print_help(args: &[&str]) {
    match args {
        ["help"] => {
            println!("Available commands:");
            println!("    continue    - Resume the process");
            println!("    register    - Commands for operating on registers");
        }
        ["help", "register"] => {
            println!("Available register commands:");
            println!("    read");
            println!("    read <register>");
            println!("    read all");
            println!("    write <register> <value>");
        }
        _ => {
            println!("No help available on that");
        }
    }
}

fn format_register_value(value: &RegisterValue) -> String {
    match value {
        RegisterValue::U8(v) => format!("{:#04x}", v),
        RegisterValue::U16(v) => format!("{:#06x}", v),
        RegisterValue::U32(v) => format!("{:#010x}", v),
        RegisterValue::U64(v) => format!("{:#018x}", v),
        RegisterValue::I8(v) => format!("{}", v),
        RegisterValue::I16(v) => format!("{}", v),
        RegisterValue::I32(v) => format!("{}", v),
        RegisterValue::I64(v) => format!("{}", v),
        RegisterValue::F32(v) => format!("{}", v),
        RegisterValue::F64(v) => format!("{}", v),
        RegisterValue::Bytes64(bytes) => format!("{:02x?}", bytes),
        RegisterValue::Bytes128(bytes) => format!("{:02x?}", bytes),
    }
}

fn print_stop_reason(process: &mut Process, reason: StopReason) {
    println!("Process {} ", process.pid.to_string());

    match reason.reason {
        Pstatus::Stopped => println!("stopped with signal {}", reason.signal),
        Pstatus::Running => panic!("unreachable print_stop_reason"),
        Pstatus::Terminated => println!("terminated with signal: {}", reason.signal),
        Pstatus::Exited => println!("exited with status {}", reason.status),
    }
}

#[derive(PartialEq, Eq)]
enum Pstatus {
    Stopped,
    Running,
    Terminated,
    Exited
}

struct StopReason {
    reason: Pstatus,
    status: u8,
    signal: String,
}

pub struct Process {
    pid: Pid,
    status: Option<Pstatus>,
    terminate_on_end: bool,
    // 
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid.as_raw() != 0 {
            if self.terminate_on_end {
                let _ = kill(self.pid, Signal::SIGKILL);
                let _ = waitpid(self.pid, None);
            } else {
                if self.status == Some(Pstatus::Running) {
                    let _ = kill(self.pid, Signal::SIGSTOP);
                    let _ = waitpid(self.pid, None);
                }
                let _ = detach(self.pid, None);
                let _ = kill(self.pid, Signal::SIGCONT);
            }
        }
    }
}

impl Process {
    pub fn attach(&mut self) -> Result<()> {
        let pid = self.pid;
        if pid.as_raw() == 0 {
            bail!("Invalid PID");
        }

        attach(pid)?;
        self.wait_on_signal()?;

        println!("Attached to {}", pid);
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        cont(self.pid, None)?;

        self.status = Some(Pstatus::Running);

        println!("Resumed process: {}", self.pid);
        Ok(())
    }

    pub fn launch(program_path: String) -> Result<Self> {
        let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC)?;

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                nix::unistd::close(write_fd.as_raw_fd())?;

                let mut file = unsafe { File::from_raw_fd(read_fd.as_raw_fd()) };
                let mut error_message = String::new();
                file.read_to_string(&mut error_message)?;

                if !error_message.is_empty() {
                    waitpid(child, None)?;
                    bail!("Error from child: {}", error_message);
                }

                waitpid(child, None)?;
                println!("Launched child process for {}: {}", program_path, child);
                Ok(Process { pid: child, status: Some(Pstatus::Running), terminate_on_end: true })
            }
            Ok(ForkResult::Child) => {
                nix::unistd::close(read_fd.as_raw_fd())?;

                traceme()?;

                let c_path = CString::new(program_path.as_bytes())?;
                if execv(&c_path, &[c_path.clone()]).is_err() {
                    let error_message = "Exec failed".to_string();
                    write_to_pipe(write_fd.as_raw_fd(), &error_message);
                    std::process::exit(1);
                }

                unreachable!();
            }
            Err(_) => bail!("Fork failed"),
        }
    }

    fn wait_on_signal(&mut self) -> Result<StopReason>{
        match waitpid(self.pid, None) {
            Ok(wait_status) => {
                let reason = match wait_status {
                    WaitStatus::Exited(_pid, status) => {
                        self.status = Some(Pstatus::Exited);
                        Ok(StopReason { reason: Pstatus::Exited, status: status as u8, signal: "".to_string() })
                    },
                    WaitStatus::Signaled(_pid, signal, _) => {
                        self.status = Some(Pstatus::Terminated);
                        Ok(StopReason { reason: Pstatus::Terminated, status: 0, signal: signal.to_string() })
                    },
                    WaitStatus::Stopped(_pid, signal) => {
                        self.status = Some(Pstatus::Stopped);
                        Ok(StopReason { reason: Pstatus::Stopped, status: 0, signal: signal.to_string() })
                    },
                    _ => bail!("Process is not stopped: {}", self.pid),
                };
                // TODO: add is_attached as in original code
                if self.terminate_on_end == false && self.status == Some(Pstatus::Stopped) {
                    self.read_all_registers();
                }
                reason
            },
            Err(e) => bail!("waitpid failed {}", e),
        }
    }

    pub fn read_all_registers(&mut self) -> Result<()> {
        // Read general purpose registers
        unsafe {
            match getregs(self.pid) {
                Ok(regs) => self.registers.data.regs = regs,
                Err(e) => bail!("Could not read GPR registers: {}", e),
            }

        // TODO: call from libc directly since nix doesn't have getfpregs
        //     Read floating point registers
        //     match ptrace::getfpregs(self.pid) {
        //         Ok(fpregs) => self.registers.data.i387 = fpregs,
        //         Err(e) => bail!("Could not read FPR registers: {}", e),
        //     }
        }

        // Read debug registers (DR0-DR7)
        for i in 0..8 {
            let id = RegisterId::Dr0 as usize + i;
            let info = registers::register_info_by_id(id.try_into()?);

            unsafe {
                let data = read_user(self.pid, info.offset as *mut _)?;
                self.registers.data.u_debugreg[i] = data;
            }
        }

        Ok(())
    }

    pub fn write_user_area(&self, offset: usize, data: u64) -> Result<()> {
        if write_user(self.pid, offset as _, data as i64).is_err() {
            bail!("Could not write to user area");
        }
        Ok(())
    }

    pub fn write_fprs(&self, fprs: &user_fpregs_struct) -> Result<()> {
//       TODO: call ptrace from libc directly since no setfregs on nix crate
//       if setfpregs(self.pid, fprs).is_err() {
//            bail!("Could not write floating point registers");
//       }
        Ok(())
    }

    pub fn write_gprs(&self, gprs: &user_regs_struct) -> Result<()> {
        if setregs(self.pid, *gprs).is_err() {
            bail!("Could not write general purpose registers");
        }
        Ok(())
    }
}

fn write_to_pipe(write_fd: RawFd, message: &str) {
    let mut file = unsafe { File::from_raw_fd(write_fd) };
    if let Err(e) = file.write_all(message.as_bytes()) {
        eprintln!("Failed to write error message to pipe: {}", e);
    }
}
