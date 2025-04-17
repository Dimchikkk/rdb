use anyhow::{bail, Result};
use copperline::Copperline;
use nix::sys::wait::waitpid;
use nix::sys::ptrace::{attach, cont};
use nix::unistd::Pid;

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
        process.attach().unwrap();
        main_loop(&mut process).unwrap();
    } else {
        let program_path = args.nth(1).unwrap();
        bail!("Launching program is not implemented yet!: {}", program_path);
    }
    Ok(())
}

fn main_loop(process: &mut Process) -> Result<()> {
    let mut cl = Copperline::new();
    while let Ok(line) = cl.read_line("rdb> ", copperline::Encoding::Utf8) {
        if !line.is_empty() {
            if line.starts_with("continue") {
                process.resume().unwrap();
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

        attach(pid).unwrap();
        waitpid(pid, None).unwrap();

        self.status = Some(Pstatus::Stopped);

        println!("Attached to {}", pid);
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        let pid = self.pid;
        cont(self.pid, None).unwrap();

        self.status = Some(Pstatus::Running);
        waitpid(pid, None).unwrap();

        println!("Resumed process: {}", self.pid);
        Ok(())
    }
}
