use process::{handle_stop, Process};
use anyhow::{bail, Result};
use copperline::Copperline;
use nix::unistd::Pid;
use registers::{register_info_by_name, write_register, RegisterType, UserRegisters, REGISTERS};
use registers_io::{format_register_value, parse_register_value};
use stoppoint::{Stoppoint, StoppointCollection, VirtAddr};
use utils::{parse_vector, print_hex_dump};

mod utils;
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
                handle_stop(process, reason);
            } else if command.starts_with("reg") {
                handle_register_command(process, &args);
            } else if command.starts_with("b") {
                handle_breakpoint_command(process, &args)?;
            } else if command.starts_with("s") {
                let reason = process.step_instruction()?;
                handle_stop(process, reason);
            } else if command.starts_with("mem") {
                handle_memory_command(process, &args)?;
            } else if command.starts_with("dis") {
                handle_disassemble_command(process, &args);
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

fn handle_disassemble_command(process: &Process, args: &[&str]) {
    let mut address = process.get_pc().unwrap();
    let mut n_instructions = 5;

    let mut it = 1;
    while it < args.len() {
        match args[it] {
            "-a" if it + 1 < args.len() => {
                it += 1;
                if let Ok(addr) = u64::from_str_radix(args[it], 16) {
                    address = VirtAddr(addr);
                } else {
                    eprintln!("Invalid address format");
                    return;
                }
            }
            "-c" if it + 1 < args.len() => {
                it += 1;
                if let Ok(count) = args[it].parse::<usize>() {
                    n_instructions = count;
                } else {
                    eprintln!("Invalid instruction count");
                    return;
                }
            }
            _ => {
                println!("Usage: dis [-a hex_address] [-c count]");
                return;
            }
        }
        it += 1;
    }

    print_disassembly(process, address, n_instructions);
}

fn handle_memory_command(process: &mut Process, args: &[&str]) -> Result<()> {
    if args.len() < 3 {
        print_help(&["help", "memory"]);
        return Ok(());
    }

    match args[1] {
        cmd if cmd.starts_with("read") => handle_memory_read_command(process, args),
        cmd if cmd.starts_with("write") => handle_memory_write_command(process, args),
        _ => {
            print_help(&["help", "memory"]);
            Ok(())
        }
    }
}

fn handle_memory_write_command(process: &mut Process, args: &[&str]) -> Result<()> {
    if args.len() < 4 {
        print_help(&["help", "memory"]);
        return Ok(());
    }

    let addr_str = args[2].strip_prefix("0x").unwrap_or(args[2]);
    let address = u64::from_str_radix(addr_str, 16)
        .map_err(|_| anyhow::anyhow!("Invalid address format"))?;

    // Join all the rest args (bytes) into one string to parse
    let bytes_str = args[3..].join(" ");

    let bytes = parse_vector(&bytes_str)?;

    process.write_memory(VirtAddr(address), &bytes)?;

    Ok(())
}

fn handle_memory_read_command(process: &Process, args: &[&str]) -> Result<()> {
    let address_str = args[2];
    let address = if let Some(addr_str) = address_str.strip_prefix("0x") {
        u64::from_str_radix(addr_str, 16)
    } else {
        u64::from_str_radix(address_str, 16)
    };

    let address = match address {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("Invalid address format");
            return Ok(());
        }
    };

    let n_bytes = if args.len() >= 4 {
        match args[3].parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("Invalid number of bytes");
                return Ok(());
            }
        }
    } else {
        32
    };

    let bytes = process.read_memory(VirtAddr(address), n_bytes)?;
    print_hex_dump(address, &bytes);

    Ok(())
}

fn handle_breakpoint_command(process: &mut Process, args: &[&str]) -> Result<()> {
    let command = args[1];

    if command.starts_with("list") {
        if process.breakpoint_sites.stoppoints.is_empty() {
            println!("No breakpoints set");
        } else {
            println!("Current breakpoints:");
            for site in &process.breakpoint_sites.stoppoints {
                if site.is_internal {
                    continue;
                }
                println!(
                    "{}: address = {:#x}, {}",
                    site.id,
                    site.address.0,
                    if site.is_enabled { "enabled" } else { "disabled" }
                );
            }
        }
        return Ok(());
    }

    if command.starts_with("set") {
        let addr_str = args[2];
        let addr_trimmed = addr_str.strip_prefix("0x").unwrap_or(addr_str);

        let address = match u64::from_str_radix(addr_trimmed, 16) {
            Ok(addr) => addr,
            Err(_) => {
                eprintln!("Breakpoint command expects address in hexadecimal, prefixed with '0x'");
                return Ok(());
            }
        };

        let is_hardware = args.len() == 4 && args[3] == "-h";
        println!("hardware: {}", is_hardware);
        return process.create_breakpoint_site(VirtAddr(address), is_hardware);
    }

    let id = match args[2].parse::<i32>() {
        Ok(id) => id,
        Err(_) => {
            eprintln!("Command expects breakpoint id");
            return Ok(());
        }
    };

    if command.starts_with("enable") {
        if let Some(site) = process.breakpoint_sites.get_by_id_mut(id) {
            site.enable(&mut process.registers)?;
        } else {
            eprintln!("No breakpoint with id {}", id);
        }
    } else if command.starts_with("disable") {
        if let Some(site) = process.breakpoint_sites.get_by_id_mut(id) {
            site.disable(&mut process.registers)?;
        } else {
            eprintln!("No breakpoint with id {}", id);
        }
    } else if command.starts_with("delete") {
        process.breakpoint_sites.remove_by_id(&mut process.registers, id)?;
    } else {
        print_help(&["help", "breakpoint"]);
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

pub fn handle_register_read(process: &Process, args: &[&str]) {
    if args.len() == 2 || (args.len() == 3 && args[2] == "all") {
        for info in REGISTERS.iter() {
            let should_print = (args.len() == 3 || info.register_type == RegisterType::Gpr)
                && info.name.to_lowercase() != "orig_rax";

            if !should_print {
                continue;
            }

            let value = process.registers.read(info);
            let formatted = format_register_value(info.name, &value);
            println!("{}:\t{}", info.name, formatted);
        }
    } else if args.len() == 3 {
        let reg_name = args[2];
        match register_info_by_name(reg_name) {
            info => {
                let value = process.registers.read(info);
                let formatted = format_register_value(reg_name, &value);
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

    write_register(process.pid, &mut process.registers, info, value);
}

fn print_disassembly(process: &Process, address: VirtAddr, n_instructions: usize) {
    let instructions = process.disassemble(n_instructions, Some(address));
    for instr in instructions {
        println!("{:#018x}: {}", instr.address.0, instr.text);
    }
}

fn print_help(args: &[&str]) {
    match args {
        ["help"] => {
            println!("Available commands:");
            println!("    breakpoint  - Commands for operating on breakpoints");
            println!("    continue    - Resume the process");
            println!("    disassemble - Disassemble instructions from memory");
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
            println!("    set <address> -h");
        }
        ["help", cmd] if cmd.starts_with("register") => {
            println!("Available register commands:");
            println!("    read");
            println!("    read <register>");
            println!("    read all");
            println!("    write <register> <value>");
        }
        ["help", cmd] if cmd.starts_with("disassemble") => {
            println!("Available options:");
            println!("    -c <number of instructions>");
            println!("    -a <start address>");
        }
        _ => {
            println!("No help available on that");
        }
    }
}
