use process::{print_stop_reason, Process};
use anyhow::{bail, Result};
use copperline::Copperline;
use nix::unistd::Pid;
use registers::{register_info_by_name, RegisterType, RegisterValue, UserRegisters, REGISTERS};
use std::fmt::Write;

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
        let user_registers = UserRegisters::new();
        let mut process = Process {
            pid,
            status: None,
            terminate_on_end: false,
            is_attached: true,
            registers: user_registers
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
        if !line.is_empty() {
            let args: Vec<&str> = line.split_whitespace().collect();
            if line.starts_with("continue") {
                process.resume()?;
                let reason = process.wait_on_signal()?;
                print_stop_reason(process, reason);
            } else if line.starts_with("register") {
                handle_register_command(process, &args);
            } else if line.starts_with("help") {
                print_help(&args);
            }
        }
        cl.add_history(line);
    }

    Ok(())
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

fn format_register_value(value: &RegisterValue) -> String {
    match value {
        RegisterValue::F32(f) => format!("{}", f),
        RegisterValue::F64(f) => format!("{}", f),
        RegisterValue::U8(v) => format!("0x{:02x}", v),
        RegisterValue::U16(v) => format!("0x{:04x}", v),
        RegisterValue::U32(v) => format!("0x{:08x}", v),
        RegisterValue::U64(v) => format!("0x{:016x}", v),
        RegisterValue::I8(v) => format!("0x{:02x}", v),
        RegisterValue::I16(v) => format!("0x{:04x}", v),
        RegisterValue::I32(v) => format!("0x{:08x}", v),
        RegisterValue::I64(v) => format!("0x{:016x}", v),
        RegisterValue::Bytes64(bytes) => {
            let mut s = String::from("[");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                write!(s, "0x{:02x}", b).unwrap();
            }
            s.push(']');
            s
        }
        RegisterValue::Bytes128(bytes) => {
            let mut s = String::from("[");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                write!(s, "0x{:02x}", b).unwrap();
            }
            s.push(']');
            s
        }
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
    todo!()
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
