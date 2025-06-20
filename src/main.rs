use std::sync::{LazyLock, Mutex};

use process::{handle_stop, Process};
use anyhow::{bail, Result};
use copperline::Copperline;
use registers::{register_info_by_name, write_register, RegisterType, REGISTERS};
use registers_io::{format_register_value, parse_register_value};
use stoppoint::{Stoppoint, StoppointMode};
use syscall::SyscallCatchPolicy;
use sysnames::Syscalls;
use target::Target;
use types::VirtAddr;
use utils::{parse_vector, print_hex_dump};
use nix::{sys::signal::{kill, SigHandler, Signal::{self, SIGINT}}, unistd::Pid};
use nix::sys::signal::signal;

mod utils;
mod process;
mod breakpoints;
mod syscall;
mod watchpoint;
mod stoppoint;
mod registers;
mod registers_io;
mod elf;
mod types;
mod target;

static G_RDB_PID: LazyLock<Mutex<Option<i32>>> = LazyLock::new(|| Mutex::new(None));

extern "C" fn handle_sigint(_sig: i32) {
    if let Some(pid) = *G_RDB_PID.lock().unwrap() {
        let _ = kill(Pid::from_raw(pid), Signal::SIGSTOP);
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args();

    if args.len() == 1 {
        bail!("\n\nUsage:\nTo attach to process: ./rdb -p <PID>\nTo launch program: ./rdb program_path\n");
    }

    if args.len() == 3 && args.nth(1).unwrap() == "-p" {
        let pid_str = args.nth(0).unwrap();
        let pid_num = pid_str.parse::<i32>().expect("PID should be a number");
        let mut target = Target::attach(pid_num)?;
        main_loop(&mut target)?;
    } else {
        let program_path = args.nth(1).unwrap();
        let mut target = Target::launch(program_path.into())?;
        main_loop(&mut target)?;
    }
    Ok(())
}

fn main_loop(target: &mut Target) -> Result<()> {
    {
        let mut global_pid = G_RDB_PID.lock().unwrap();
        *global_pid = Some(target.process.pid.as_raw());
    }

    unsafe {
        let _ = signal(SIGINT, SigHandler::Handler(handle_sigint));
    }

    let mut cl = Copperline::new();

    while let Ok(line) = cl.read_line("rdb> ", copperline::Encoding::Utf8) {
        if line.trim().is_empty() {
            continue;
        }

        let args: Vec<&str> = line.split_whitespace().collect();
        let command = args[0];

         match command {
            cmd if cmd.starts_with("catch") => {
                let process = &mut target.process;
                handle_catchpoint_command(process, &args)?;
            }
            cmd if cmd.starts_with("c") => {
                let reason = {
                    let process = &mut target.process;
                    process.resume()?;
                    process.wait_on_signal().unwrap()
                };
                handle_stop(target, reason);
            }
            cmd if cmd.starts_with("reg") => {
                let process = &mut target.process;
                handle_register_command(process, &args);
            }
            cmd if cmd.starts_with("b") => {
                let process = &mut target.process;
                handle_breakpoint_command(process, &args)?;
            }
            cmd if cmd.starts_with("s") => {
                let reason = {
                    let process = &mut target.process;
                    process.step_instruction()?
                };
                handle_stop(target, reason);
            }
            cmd if cmd.starts_with("mem") => {
                let process = &mut target.process;
                handle_memory_command(process, &args)?;
            }
            cmd if cmd.starts_with("dis") => {
                let process = &mut target.process;
                handle_disassemble_command(process, &args);
            }
            cmd if cmd.starts_with("watch") => {
                let process = &mut target.process;
                handle_watchpoint_command(process, &args)?;
            }
            cmd if cmd.starts_with("help") => {
                print_help(&args);
            }
            _ => println!("Unknown command"),
        }

        cl.add_history(line);
    }

    Ok(())
}

fn handle_catchpoint_command(process: &mut Process, args: &[&str]) -> Result<()> {
    if args.len() < 2 {
        print_help(&["help", "catch"]);
        return Ok(());
    }

    match args[1] {
        cmd if cmd.starts_with("sys") => {
            // default: catch all
            let mut policy = SyscallCatchPolicy::catch_all();

            if args.len() == 3 && args[2] == "none" {
                policy = SyscallCatchPolicy::catch_none();
            } else if args.len() >= 3 {
                // split comma-separated list
                let items = args[2].split(',').map(str::trim);
                let mut to_catch = Vec::new();
                for item in items {
                    let id = if let Ok(n) = item.parse::<i32>() {
                        n
                    } else {
                        // lookup by name
                        match Syscalls::number(item) {
                            Some(n) => n as i32,
                            None => {
                                eprintln!("Unknown syscall name: {}", item);
                                return Ok(());
                            }
                        }
                    };
                    to_catch.push(id);
                }
                policy = SyscallCatchPolicy::catch_some(to_catch);
            }

            process.syscall_catch_policy = policy;
        }
        _ => print_help(&["help", "catch"]),
    }

    Ok(())
}

fn handle_watchpoint_command(process: &mut Process, args: &[&str]) -> Result<()> {
    let command = args[1];

    if command == "list" {
        if process.watchpoint_sites.stoppoints.is_empty() {
            println!("No watchpoints set");
        } else {
            println!("Current watchpoints:");
            for wp in &process.watchpoint_sites.stoppoints {
                println!(
                    "{}: address = {:#x}, size = {}, mode = {:?}, {}",
                    wp.id,
                    wp.address.0,
                    wp.size,
                    wp.mode,
                    if wp.is_enabled { "enabled" } else { "disabled" }
                );
            }
        }
        return Ok(());
    }

    if command == "set" {
        if args.len() < 3 {
            eprintln!("Usage: watch set <address> [mode] [size]");
            return Ok(());
        }

        let addr_str = args[2].strip_prefix("0x").unwrap_or(args[2]);
        let address = match u64::from_str_radix(addr_str, 16) {
            Ok(a) => a,
            Err(_) => {
                eprintln!("Invalid address format");
                return Ok(());
            }
        };

        let mode = if args.len() >= 4 {
            match args[3].to_lowercase().as_str() {
                "write" => StoppointMode::Write,
                "readwrite" => StoppointMode::ReadWrite,
                "execute" => StoppointMode::Execute,
                _ => {
                    eprintln!("Unknown watchpoint mode. Use: write, readwrite, execute");
                    return Ok(());
                }
            }
        } else {
            StoppointMode::Write // default
        };

        let size = if args.len() >= 5 {
            match args[4].parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("Invalid watchpoint size");
                    return Ok(());
                }
            }
        } else {
            1 // default
        };

        return process.create_watchpoint(VirtAddr(address), mode, size);
    }

    let id = match args.get(2).and_then(|s| s.parse::<i32>().ok()) {
        Some(id) => id,
        None => {
            eprintln!("Expected watchpoint ID");
            return Ok(());
        }
    };

    match command {
        "enable" => {
            if let Some(wp) = process.watchpoint_sites.get_by_id_mut(id) {
                wp.enable(&mut process.registers)?;
            } else {
                eprintln!("No watchpoint with id {}", id);
            }
        }
        "disable" => {
            if let Some(wp) = process.watchpoint_sites.get_by_id_mut(id) {
                wp.disable(&mut process.registers)?;
            } else {
                eprintln!("No watchpoint with id {}", id);
            }
        }
        "delete" => {
            process.watchpoint_sites.remove_by_id(&mut process.registers, id)?;
        }
        _ => {
            print_help(&["help", "watch"]);
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
        print_help(&["help", "mem"]);
        return Ok(());
    }

    match args[1] {
        cmd if cmd.starts_with("read") => handle_memory_read_command(process, args),
        cmd if cmd.starts_with("write") => handle_memory_write_command(process, args),
        _ => {
            print_help(&["help", "mem"]);
            Ok(())
        }
    }
}

fn handle_memory_write_command(process: &mut Process, args: &[&str]) -> Result<()> {
    if args.len() < 4 {
        print_help(&["help", "mem"]);
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
        print_help(&["help", "break"]);
    }

    Ok(())
}

fn handle_register_command(process: &mut Process, args: &[&str]) {
    if args.len() < 2 {
        print_help(&["help", "reg"]);
        return;
    }

    if args[1].starts_with("read") {
        handle_register_read(process, args);
    } else if args[1].starts_with("write") {
        handle_register_write(process, args);
    } else {
        print_help(&["help", "reg"]);
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
         print_help(&["help", "reg"]);
    }
}

fn handle_register_write(process: &mut Process, args: &[&str]) {
    if args.len() != 4 {
        print_help(&["help", "reg"]);
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
            println!("    break - Commands for operating on breakpoints");
            println!("    c     - Resume the process");
            println!("    dis   - Disassemble instructions from memory");
            println!("    reg   - Commands for operating on registers");
            println!("    step  - Step over a single instruction");
            println!("    catch - Catch syscalls");
            println!("    mem   - Read/write memory");
        }
        ["help", cmd] if cmd.starts_with("break") => {
            println!("Available breakpoint commands:");
            println!("    list");
            println!("    delete <id>");
            println!("    disable <id>");
            println!("    enable <id>");
            println!("    set <address>");
            println!("    set <address> -h");
        }
        ["help", cmd] if cmd.starts_with("catch") => {
            println!("Available catchpoint commands:");
            println!("    sys         - Catch all syscalls");
            println!("    sys none    - Catch no syscalls");
            println!("    sys <list>  - Catch specific syscalls by id or name, comma-separated");
        }
        ["help", cmd] if cmd.starts_with("reg") => {
            println!("Available register commands:");
            println!("    read");
            println!("    read <register>");
            println!("    read all");
            println!("    write <register> <value>");
        }
        ["help", cmd] if cmd.starts_with("dis") => {
            println!("Available options:");
            println!("    -c <number of instructions>");
            println!("    -a <start address>");
        }
        ["help", cmd] if cmd.starts_with("mem") => {
            println!("Available memory commands:");
            println!("    mem read <address> [length]");
            println!("    mem write <address> <byte1> [byte2 byte3 ...]");
        }
        _ => {
            println!("No help available on that");
        }
    }
}
