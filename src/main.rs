use process::{print_stop_reason, Process};
use anyhow::{bail, Result};
use copperline::Copperline;
use nix::unistd::Pid;

mod process;
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
        let mut process = Process { pid, status: None, terminate_on_end: false, is_attached: true };
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
