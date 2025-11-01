use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use nix::libc::AT_ENTRY;
use nix::unistd::Pid;

use crate::breakpoint::{Breakpoint, BreakpointCollection, BreakpointKind};
use crate::dwarf::LineTableEntry;
use crate::elf::Elf;
use crate::process::{Process, StopReason};
use crate::registers::UserRegisters;
use crate::stack::Stack;
use crate::stoppoint::StoppointCollection;
use crate::syscall::SyscallCatchPolicy;
use crate::types::VirtAddr;

pub struct Target {
    pub process: Box<Process>,
    pub elf: Box<Elf>,
    pub breakpoints: BreakpointCollection,
    pub stack: Stack,
}

impl Target {
    pub fn launch(path: PathBuf) -> Result<Self> {
        let proc = Box::new(Process::launch(path.to_string_lossy().into_owned())?);
        let elf = create_loaded_elf(&proc, &path).unwrap();

        Ok(Self {
            process: proc,
            elf,
            breakpoints: BreakpointCollection::new(),
            stack: Stack::new(),
        })
    }

    pub fn attach(pid: i32) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{}/exe", pid));

        let user_registers = UserRegisters::new();
        let mut process = Process {
            pid: Pid::from_raw(pid),
            status: None,
            terminate_on_end: false,
            is_attached: true,
            registers: user_registers,
            breakpoint_sites: StoppointCollection::new(),
            watchpoint_sites: StoppointCollection::new(),
            syscall_catch_policy: SyscallCatchPolicy::catch_none(),
            expecting_syscall_exit: false,
            _not_send_or_sync: PhantomData,
        };

        process.attach()?;
        let elf = create_loaded_elf(&process, &path).unwrap();

        Ok(Self {
            process: Box::new(process),
            elf,
            breakpoints: BreakpointCollection::new(),
            stack: Stack::new(),
        })
    }

    pub fn notify_stop(&mut self, _reason: &StopReason) -> Result<()> {
        let pc = self.process.get_pc()?;
        let file_addr = pc.to_file_addr(&self.elf);
        let dwarf = self.elf.dwarf();
        let inline_stack = dwarf.inline_stack_at_address(file_addr)?;
        if std::env::var_os("RDB_DEBUG").is_some() && !inline_stack.is_empty() {
            eprintln!("notify_stop: inline_stack.len() = {}", inline_stack.len());
        }
        self.stack.update_inline_height(&inline_stack, file_addr)?;
        Ok(())
    }

    pub fn create_line_breakpoint(
        &mut self,
        file: PathBuf,
        line: u64,
        is_hardware: bool,
    ) -> Result<&mut Breakpoint> {
        let kind = BreakpointKind::Line { file, line };
        let bp = Breakpoint::new(kind, is_hardware, false);
        Ok(self.breakpoints.push(bp))
    }

    pub fn create_function_breakpoint(
        &mut self,
        name: String,
        is_hardware: bool,
    ) -> Result<&mut Breakpoint> {
        let kind = BreakpointKind::Function { name };
        let bp = Breakpoint::new(kind, is_hardware, false);
        Ok(self.breakpoints.push(bp))
    }

    pub fn create_address_breakpoint(
        &mut self,
        address: VirtAddr,
        is_hardware: bool,
    ) -> Result<&mut Breakpoint> {
        let kind = BreakpointKind::Address { address };
        let bp = Breakpoint::new(kind, is_hardware, false);
        Ok(self.breakpoints.push(bp))
    }

    pub fn line_entry_at_pc(&self) -> Result<Option<LineTableEntry>> {
        let pc = self.process.get_pc()?;
        let file_addr = pc.to_file_addr(&self.elf);
        let dwarf = self.elf.dwarf();

        let debug_line = std::env::var_os("RDB_DEBUG").is_some();
        if debug_line {
            eprintln!(
                "line_entry_at_pc: pc=0x{:x} file=0x{:x}",
                pc.0,
                file_addr.addr()
            );
        }

        if let Some(func) = dwarf.function_containing_address(file_addr)? {
            if let Some(line_table) = func.cu().lines()? {
                if let Some(entry) = line_table.get_entry_by_address(file_addr) {
                    if debug_line {
                        eprintln!(
                            "  entry via function CU: line={} file={:?}",
                            entry.line,
                            entry.file.as_ref().map(|f| f.path.clone())
                        );

                        if let Ok(inline_stack) = dwarf.inline_stack_at_address(file_addr) {
                            if !inline_stack.is_empty() {
                                eprintln!("  inline stack ({} frames):", inline_stack.len());
                                for die in inline_stack {
                                    let name = die
                                        .name()
                                        .ok()
                                        .flatten()
                                        .unwrap_or_else(|| "<unnamed>".to_string());
                                    let low = die.low_pc().map(|addr| addr.addr()).unwrap_or(0);
                                    let high = die.high_pc().map(|addr| addr.addr()).unwrap_or(0);
                                    eprintln!(
                                        "    {} [0x{:x}, 0x{:x})",
                                        name,
                                        low,
                                        high
                                    );
                                }
                            }
                        }
                    }
                    return Ok(Some(entry));
                }
            }
        }

        if let Some(cu) = dwarf.compile_unit_containing_address(file_addr)? {
            if debug_line {
                eprintln!("  found CU containing address");
            }
            if let Some(line_table) = cu.lines()? {
                if let Some(entry) = line_table.get_entry_by_address(file_addr) {
                    if debug_line {
                        eprintln!(
                            "  entry via CU: line={} file={:?}",
                            entry.line,
                            entry.file.as_ref().map(|f| f.path.clone())
                        );
                    }
                    return Ok(Some(entry));
                }
                if debug_line {
                    eprintln!("  no entry via CU line table");
                }
            }
        } else if debug_line {
            eprintln!("  no CU contains address");
        }

        // Fall back to scanning all compile units if the CU root does not expose ranges
        for cu in &dwarf.compile_units {
            if let Some(line_table) = cu.lines()? {
                if let Some(entry) = line_table.get_entry_by_address(file_addr) {
                    if debug_line {
                        eprintln!(
                            "  entry via fallback: line={} file={:?}",
                            entry.line,
                            entry.file.as_ref().map(|f| f.path.clone())
                        );
                    }
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
    }

    pub fn step_in(&mut self) -> Result<StopReason> {
        // Handle inline frames - if we have inline height, just decrement and return
        let inline_height = self.stack.inline_height();
        if std::env::var_os("RDB_DEBUG").is_some() {
            eprintln!("step_in: inline_height = {}", inline_height);
        }
        if inline_height > 0 {
            self.stack.simulate_inlined_step_in();
            // Return a synthetic single-step reason without executing any instructions
            // This simulates stepping into the inline function
            return Ok(StopReason::synthetic_single_step());
        }

        let orig_line = self.line_entry_at_pc()?;

        // Simple approach: just step one instruction and stop at a different line
        // We'll accept runtime code if that's where we land
        let mut last_reason = self.process.step_instruction()?;
        self.notify_stop(&last_reason)?;

        if !last_reason.is_step() {
            return Ok(last_reason);
        }

        // Check if we've entered an inline frame
        if self.stack.inline_height() > 0 {
            self.stack.simulate_inlined_step_in();
            last_reason.mark_as_single_step();
            return Ok(last_reason);
        }

        let current_line = self.line_entry_at_pc()?;

        // If we're still on the same line/address, keep stepping
        const MAX_STEPS: usize = 100;
        let mut steps = 0;

        loop {
            match (&orig_line, &current_line) {
                (Some(orig), Some(curr)) => {
                    // Continue if same address
                    if orig.address != curr.address && !curr.end_sequence {
                        // Different line - stop here
                        break;
                    }
                }
                (Some(_), None) | (None, Some(_)) => {
                    // Changed from having debug info to not having it, or vice versa - stop
                    break;
                }
                (None, None) => {
                    // No debug info - just stop after one step
                    break;
                }
            }

            // Continue stepping
            steps += 1;
            if steps >= MAX_STEPS {
                break;
            }

            last_reason = self.process.step_instruction()?;
            self.notify_stop(&last_reason)?;

            if !last_reason.is_step() {
                return Ok(last_reason);
            }

            // Check if we've entered an inline frame
            if self.stack.inline_height() > 0 {
                self.stack.simulate_inlined_step_in();
                last_reason.mark_as_single_step();
                return Ok(last_reason);
            }

            let _current_line = self.line_entry_at_pc()?;
        }

        last_reason.mark_as_single_step();
        Ok(last_reason)
    }

    pub fn step_over(&mut self) -> Result<StopReason> {
        let pc = self.process.get_pc()?;
        let file_addr = pc.to_file_addr(&self.elf);
        let dwarf = self.elf.dwarf();

        // Check if we're at the start of an inline frame
        let inline_height = self.stack.inline_height();
        if inline_height > 0 {
            // Skip over the inline frame by running to its high_pc
            let inline_stack = dwarf.inline_stack_at_address(file_addr)?;
            if inline_stack.len() >= inline_height as usize {
                let frame_index = inline_stack.len() - inline_height as usize;
                let frame_to_skip = &inline_stack[frame_index];
                let return_address = frame_to_skip.high_pc()?.to_virt_addr();
                return self.run_until_address(return_address);
            }
        }

        // Get current line entry
        let _current_line = match self.line_entry_at_pc()? {
            Some(entry) => entry,
            None => return self.process.step_instruction(),
        };

        // Check if the next line is in the same function
        // If not, we're at the end of the function and should step out
        let current_func = dwarf.function_containing_address(file_addr)?;

        if let Some(cu) = dwarf.compile_unit_containing_address(file_addr)? {
            if let Some(line_table) = cu.lines()? {
                if let Some(next_entry) = line_table.entry_after(file_addr) {
                    let next_addr = next_entry.address;

                    // Check if next entry is in the same function
                    let next_func = dwarf.function_containing_address(next_addr)?;
                    let same_func = match (&current_func, &next_func) {
                        (Some(cf), Some(nf)) => cf.position() == nf.position(),
                        _ => false,
                    };

                    if same_func {
                        // Next line is in same function, run to it
                        return self.run_until_address(next_entry.address.to_virt_addr());
                    }
                }
            }
        }

        // No next line in same function - step out of current function
        // Just step one instruction at a time until we leave this function
        loop {
            let reason = self.process.step_instruction()?;
            if !reason.is_step() {
                return Ok(reason);
            }

            let new_pc = self.process.get_pc()?;
            let new_addr = new_pc.to_file_addr(&self.elf);
            let new_func = dwarf.function_containing_address(new_addr)?;

            // Check if we've left the function
            match (&current_func, &new_func) {
                (Some(cf), Some(nf)) if cf.position() == nf.position() => {
                    // Still in same function, continue stepping
                    continue;
                }
                _ => {
                    // Left the function or entered a new one
                    return Ok(reason);
                }
            }
        }
    }

    fn run_until_address(&mut self, address: VirtAddr) -> Result<StopReason> {
        let mut temp_bp = None;

        if !self.process.breakpoint_sites.contains_address(address) {
            let kind = BreakpointKind::Address { address };
            let mut bp = Breakpoint::new(kind, false, true);
            bp.enable(&mut self.process, &self.elf)?;
            temp_bp = Some(bp);
        }

        self.process.resume()?;
        let mut reason = self.process.wait_on_signal()?;

        // Only try to remove breakpoint if process is still alive
        if let Some(mut bp) = temp_bp {
            if reason.status() != crate::process::Pstatus::Exited {
                bp.remove_sites(&mut self.process)?;
            }
        }

        if reason.is_breakpoint() {
            let pc = self.process.get_pc()?;
            if pc == address {
                reason.mark_as_single_step();
            }
        }

        Ok(reason)
    }

    pub fn step_out(&mut self) -> Result<StopReason> {
        let pc = self.process.get_pc()?;
        let file_addr = pc.to_file_addr(&self.elf);
        let dwarf = self.elf.dwarf();

        // Check if we're in an inline frame
        let inline_stack = dwarf.inline_stack_at_address(file_addr)?;
        let inline_height = self.stack.inline_height();
        let has_inline_frames = inline_stack.len() > 1;
        let at_inline_frame = inline_height < inline_stack.len() as u32 - 1;

        if has_inline_frames && at_inline_frame {
            // Step out of inline frame by running to its high_pc
            let current_frame_index = inline_stack.len() - inline_height as usize - 1;
            let current_frame = &inline_stack[current_frame_index];
            let return_address = current_frame.high_pc()?.to_virt_addr();
            return self.run_until_address(return_address);
        }

        // Step out of regular function
        let initial_func = dwarf.function_containing_address(file_addr)?;

        loop {
            let reason = self.process.step_instruction()?;
            if !reason.is_step() {
                return Ok(reason);
            }

            let new_pc = self.process.get_pc()?;
            let new_file_addr = new_pc.to_file_addr(&self.elf);
            let current_func = dwarf.function_containing_address(new_file_addr)?;

            // Check if we've left the function
            match (initial_func.as_ref(), current_func.as_ref()) {
                (Some(init), Some(curr)) => {
                    if init.position() != curr.position() {
                        return Ok(reason);
                    }
                }
                (Some(_), None) => {
                    return Ok(reason);
                }
                _ => {}
            }
        }
    }
}

fn create_loaded_elf(proc: &Process, path: &Path) -> Result<Box<Elf>> {
    let auxv = proc.get_auxv()?;
    let mut elf = Box::new(Elf::new(path)?);
    elf.init()?;

    if let Some(&entry) = auxv.get(&AT_ENTRY) {
        let load_addr = VirtAddr(entry - elf.header.e_entry);
        elf.notify_loaded(load_addr);
        Ok(elf)
    } else {
        bail!("Missing AT_ENTRY in auxv");
    }
}
