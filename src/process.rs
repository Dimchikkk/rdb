use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use nix::fcntl::OFlag;
use std::os::unix::io::{AsRawFd, RawFd};
use anyhow::{bail, Result};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::ptrace::{attach, cont, detach, getregs, setregs, traceme, write_user };
use nix::unistd::{execv, fork, ForkResult, pipe2, Pid};
use nix::sys::signal::{kill, Signal};
use nix::libc::{self, c_long, user_fpregs_struct, user_regs_struct, PTRACE_GETFPREGS, PTRACE_PEEKUSER};
use libc::{ptrace, PTRACE_SETFPREGS, pid_t, c_void};
use std::ptr;

use crate::registers::{register_info_by_id, UserRegisters, DEBUG_REG_IDS};

#[derive(PartialEq, Eq)]
pub enum Pstatus {
    Stopped,
    Running,
    Terminated,
    Exited
}

pub struct StopReason {
    reason: Pstatus,
    status: u8,
    signal: String,
}

pub struct Process {
    pub pid: Pid,
    pub status: Option<Pstatus>,
    pub terminate_on_end: bool,
    pub is_attached: bool,
    pub registers: UserRegisters
}

pub fn print_stop_reason(process: &mut Process, reason: StopReason) {
    println!("Process {} ", process.pid.to_string());

    match reason.reason {
        Pstatus::Stopped => println!("stopped with signal {}", reason.signal),
        Pstatus::Running => panic!("unreachable print_stop_reason"),
        Pstatus::Terminated => println!("terminated with signal: {}", reason.signal),
        Pstatus::Exited => println!("exited with status {}", reason.status),
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid.as_raw() != 0 {
            if self.is_attached {
                if self.status == Some(Pstatus::Running) {
                    let _ = kill(self.pid, Signal::SIGSTOP);
                    let _ = waitpid(self.pid, None);
                }
                let _ = detach(self.pid, None);
                let _ = kill(self.pid, Signal::SIGCONT);
            }

            if self.terminate_on_end {
                let _ = kill(self.pid, Signal::SIGKILL);
                let _ = waitpid(self.pid, None);
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
                let write_raw_fd = write_fd.into_raw_fd();
                nix::unistd::close(write_raw_fd)?;

                let read_raw_fd = read_fd.into_raw_fd();
                let mut file = unsafe { File::from_raw_fd(read_raw_fd) };
                let mut error_message = String::new();
                file.read_to_string(&mut error_message)?;

                if !error_message.is_empty() {
                    waitpid(child, None)?;
                    bail!("Error from child: {}", error_message);
                }

                waitpid(child, None)?;
                println!("Launched child process for {}: {}", program_path, child);
                let user_registers = UserRegisters::new();
                Ok(Process { pid: child, status: Some(Pstatus::Running), terminate_on_end: true, is_attached: false, registers: user_registers })
            }
        Ok(ForkResult::Child) => {
                let read_raw_fd = read_fd.into_raw_fd();
                nix::unistd::close(read_raw_fd)?;

                traceme()?;

                let c_path = CString::new(program_path.as_bytes())?;
                if execv(&c_path, &[c_path.clone()]).is_err() {
                    let error_message = "Exec failed".to_string();
                    let write_raw_fd = write_fd.into_raw_fd();
                    write_to_pipe(write_raw_fd, &error_message);
                    std::process::exit(1);
                }

                unreachable!();
            }
            Err(_) => bail!("Fork failed"),
        }
    }

    pub fn wait_on_signal(&mut self) -> Result<StopReason>{
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
                if self.is_attached == true && self.status == Some(Pstatus::Stopped) {
                    self.read_all_registers();
                }
                reason
            },
            Err(e) => bail!("waitpid failed {}", e),
        }
    }

    pub fn read_all_registers(&mut self) -> Result<()> {
        match getregs(self.pid) {
            Ok(r) => {
                self.registers.regs = r;
            }
            Err(e) => bail!("Could not read GPR registers: {}", e),
        }

        let ret = unsafe {
            ptrace(
                PTRACE_GETFPREGS,
                self.pid.as_raw() as i32,
                ptr::null_mut::<c_void>(),
                &mut self.registers.fp_regs as *mut _ as *mut c_void,
            )
        };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            bail!("Could not read FPR registers: {}", err);
        }

        for (i, reg_id) in DEBUG_REG_IDS.iter().enumerate() {
            let info = register_info_by_id(reg_id.clone());

            unsafe {
                *libc::__errno_location() = 0;
            }

            let data: c_long = unsafe {
                ptrace(
                    PTRACE_PEEKUSER,
                    self.pid.as_raw() as i32,
                    info.offset,
                    ptr::null_mut::<c_void>(),
                )
            };

            // clear errno before the call
            let err_no = unsafe { *libc::__errno_location() };
            if data == -1 && err_no != 0 {
                let err = std::io::Error::from_raw_os_error(err_no);
                bail!("Could not read debug register {}: {}", info.name, err);
            }

            self.registers.debug_regs[i] = data as u64;
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
        unsafe {
            let ret = ptrace(
                PTRACE_SETFPREGS,
                self.pid.as_raw(),
                fprs as *const _ as *mut c_void,
                ptr::null_mut::<c_void>(),
            );
            if ret != 0 {
                bail!("Could not write floating point registers");
            }
        }
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
    unsafe {
        libc::write(
            write_fd,
            message.as_ptr() as *const libc::c_void,
            message.len(),
        );
    }
}
