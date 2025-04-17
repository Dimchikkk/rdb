use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use nix::fcntl::OFlag;
use std::os::unix::io::{AsRawFd, RawFd};
use anyhow::{bail, Result};
use copperline::Copperline;
use nix::sys::wait::waitpid;
use nix::sys::ptrace::{attach, cont, traceme};
use nix::unistd::{execv, fork, ForkResult, pipe2, Pid};

fn main() -> Result<()> {
    let mut args = std::env::args();

    if args.len() == 1 {
        bail!("\n\nUsage:\nTo attach to process: ./rdb -p <PID>\nTo launch program: ./rdb program_path\n");
    }

    if args.len() == 3 && args.nth(1).unwrap() == "-p" {
        let pid_str = args.nth(0).unwrap();
        let pid_num = pid_str.parse::<i32>().expect("PID should be a number");
        let pid = Pid::from_raw(pid_num);
        let mut process = Process { pid, status: None };
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
            }
        }
        cl.add_history(line);
    }

    Ok(())
}

enum Pstatus {
    Stopped,
    Running,
    Terminated,
    Exited
}

pub struct Process {
    pid: Pid,
    status: Option<Pstatus>,
}

impl Process {
    pub fn attach(&mut self) -> Result<()> {
        let pid = self.pid;
        if pid.as_raw() == 0 {
            bail!("Invalid PID");
        }

        attach(pid)?;
        waitpid(pid, None)?;

        self.status = Some(Pstatus::Stopped);

        println!("Attached to {}", pid);
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        let pid = self.pid;
        cont(self.pid, None)?;

        self.status = Some(Pstatus::Running);
        waitpid(pid, None)?;

        println!("Resumed process: {}", self.pid);
        Ok(())
    }

    fn launch(program_path: String) -> Result<Self> {
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
                Ok(Process { pid: child, status: Some(Pstatus::Running) })
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
}

fn write_to_pipe(write_fd: RawFd, message: &str) {
    let mut file = unsafe { File::from_raw_fd(write_fd) };
    if let Err(e) = file.write_all(message.as_bytes()) {
        eprintln!("Failed to write error message to pipe: {}", e);
    }
}
