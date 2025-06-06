use process::{print_stop_reason, Process};
use anyhow::{bail, Result};
use copperline::Copperline;
use nix::unistd::Pid;
use registers::{register_info_by_name, RegisterType, UserRegisters, REGISTERS};
use registers_io::{format_register_value, parse_register_value};
use stoppoint::StoppointCollection;

mod process;
mod breakpoints;
mod stoppoint;
mod registers;
mod registers_io;

fn main() -> Result<()> {
    let mut args = std::env::args();

    if args.len() == 1 {
        bail!("\n\nUsage:\nTo attach to process: ./rdb -p <PID>\nTo launch program: ./rdb program_path\n");
    }

    if args.len() == 3 && args.nth(1).unwrap() == "-p" {
        let pid_str = args.nth(0).unwrap();
        let pid_num = pid_str.parse::<i32>().expect("PID should be a number");
        let pid = Pid::from_raw(pid_num);
        let user_registers = UserRegisters::new();
        let mut process = Process {
            pid,
            status: None,
            terminate_on_end: false,
            is_attached: true,
            registers: user_registers,
            breakpoint_sites: StoppointCollection::new(),
        };
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
        if !line.trim().is_empty() {
            let args: Vec<&str> = line.split_whitespace().collect();
            let command = args[0];

            if command.starts_with("c") {
                process.resume()?;
                let reason = process.wait_on_signal()?;
                print_stop_reason(process, reason);
            } else if command.starts_with("reg") {
                handle_register_command(process, &args);
            } else if command.starts_with("break") {
                handle_breakpoint_command(process, &args);
            } else if command.starts_with("s") {
                let reason = process.step_instruction()?;
                print_stop_reason(process, reason);
            } else if command.starts_with("help") {
                print_help(&args);
            } else {
                println!("Unknown command");
            }

            cl.add_history(line);
        }
    }

    Ok(())
}

fn handle_breakpoint_command(process: &mut Process, args: &[&str]) {
    todo!()
}

fn handle_register_command(process: &mut Process, args: &[&str]) {
    if args.len() < 2 {
        print_help(&["help", "register"]);
        return;
    }

    if args[1].starts_with("read") {
        handle_register_read(process, args);
    } else if args[1].starts_with("write") {
        handle_register_write(process, args);
    } else {
        print_help(&["help", "register"]);
    }
}

pub fn handle_register_read(process: &Process, args: &[&str]) {
    if args.len() == 2 || (args.len() == 3 && args[2] == "all") {
        for info in REGISTERS.iter() {
            let should_print = (args.len() == 3 || info.register_type == RegisterType::Gpr)
                && info.name.to_lowercase() != "orig_rax";

            if !should_print {
                continue;
            }

            let value = process.registers.read(info);
            let formatted = format_register_value(&value);
            println!("{}:\t{}", info.name, formatted);
        }
    } else if args.len() == 3 {
        let reg_name = args[2];
        match register_info_by_name(reg_name) {
            info => {
                let value = process.registers.read(info);
                let formatted = format_register_value(&value);
                println!("{}:\t{}", info.name, formatted);
            }
        }
    } else {
         print_help(&["help", "register"]);
    }
}

fn handle_register_write(process: &mut Process, args: &[&str]) {
    if args.len() != 4 {
        print_help(&["help", "register"]);
        return;
    }

    let reg_name = args[2];
    let info = register_info_by_name(reg_name);
    let parse_result = parse_register_value(info, args[3]);
    let value = match parse_result {
        Ok(v) => v,
        Err(err_msg) => {
            eprintln!("{}", err_msg);
            return;
        }
    };

    process.write_register(info, value);
}

fn print_help(args: &[&str]) {
    match args {
        ["help"] => {
            println!("Available commands:");
            println!("    breakpoint  - Commands for operating on breakpoints");
            println!("    continue    - Resume the process");
            println!("    register    - Commands for operating on registers");
            println!("    step        - Step over a single instruction");
        }
        ["help", cmd] if cmd.starts_with("breakpoint") => {
            println!("Available breakpoint commands:");
            println!("    list");
            println!("    delete <id>");
            println!("    disable <id>");
            println!("    enable <id>");
            println!("    set <address>");
        }
        ["help", cmd] if cmd.starts_with("register") => {
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
