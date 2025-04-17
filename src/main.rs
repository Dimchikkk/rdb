use std::ffi::CString;

use anyhow::{bail, Result};
use copperline::Copperline;
use nix::sys::wait::waitpid;
use nix::sys::ptrace::{attach, cont, traceme};
use nix::unistd::{execv, fork, ForkResult, Pid};

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
                // TODO: implement printing stop reason
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
    pub fn attach(&mut  self) -> Result<()> {
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
        match unsafe{fork()} {
            Ok(ForkResult::Parent { child, .. }) => {
                waitpid(child, None)?;
                println!("Launched {}: {}", program_path, child);
                Ok(Process { pid: child, status: Some(Pstatus::Running) })
            }
            Ok(ForkResult::Child) => {
                let c_path = CString::new(program_path.as_bytes()).unwrap();
                traceme()?;
                execv(&c_path, &[c_path.clone()])?;

                unreachable!();
            }
            Err(_) => bail!("Fork failed"),
        }
    }
}
