use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use libc::{c_void, ptrace};
use nix::fcntl::OFlag;
use nix::libc::{
    self, c_long, c_ulong, iovec, personality, process_vm_readv, setpgid, ADDR_NO_RANDOMIZE,
    PTRACE_GETFPREGS, PTRACE_O_TRACESYSGOOD, PTRACE_PEEKUSER, PTRACE_SETOPTIONS,
};
use nix::sys::ptrace::{attach, cont, detach, getregs, getsiginfo, step, syscall, traceme};
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{close, execv, fork, pipe2, ForkResult, Pid};
use rustc_demangle::demangle;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::{mem, ptr};
use sysnames::Syscalls;

use crate::breakpoints::BreakpointSite;
use crate::elf::{elf64_st_type, STT_FUNC};
use crate::registers::{
    register_info_by_id, write_register, RegisterId, RegisterValue, UserRegisters, DEBUG_REG_IDS,
};
use crate::stoppoint::{Stoppoint, StoppointCollection, StoppointMode};
use crate::syscall::{CatchPolicyMode, SyscallCatchPolicy, SyscallData, SyscallInformation};
use crate::target::Target;
use crate::types::VirtAddr;
use crate::utils::{print_disassembly, FromBytes};
use crate::watchpoint::Watchpoint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pstatus {
    Stopped,
    Running,
    Terminated,
    Exited,
}

pub struct StopReason {
    reason: Pstatus,
    status: Option<u8>,
    signal: Option<Signal>,
    trap_reason: Option<TrapType>,
    syscall_info: Option<SyscallInformation>,
}

impl StopReason {
    pub fn synthetic_single_step() -> Self {
        StopReason {
            reason: Pstatus::Stopped,
            status: None,
            signal: Some(SIGTRAP),
            trap_reason: Some(TrapType::SingleStep),
            syscall_info: None,
        }
    }

    pub fn is_step(&self) -> bool {
        self.reason == Pstatus::Stopped
            && self.signal == Some(SIGTRAP)
            && self.trap_reason == Some(TrapType::SingleStep)
    }

    pub fn mark_as_single_step(&mut self) {
        self.reason = Pstatus::Stopped;
        self.signal = Some(SIGTRAP);
        self.trap_reason = Some(TrapType::SingleStep);
    }

    pub fn is_breakpoint(&self) -> bool {
        self.reason == Pstatus::Stopped
            && self.signal == Some(SIGTRAP)
            && matches!(
                self.trap_reason,
                Some(TrapType::SoftwareBreak | TrapType::HardwareBreak)
            )
    }

    pub fn trap_reason(&self) -> Option<TrapType> {
        self.trap_reason
    }

    pub fn signal(&self) -> Option<Signal> {
        self.signal
    }

    pub fn status(&self) -> Pstatus {
        self.reason
    }

    pub fn exit_status(&self) -> Option<u8> {
        self.status
    }

    pub fn syscall_info(&self) -> Option<&SyscallInformation> {
        self.syscall_info.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapType {
    SingleStep,
    SoftwareBreak,
    HardwareBreak,
    Syscall,
}

pub struct Process {
    pub pid: Pid,
    pub status: Option<Pstatus>,
    pub terminate_on_end: bool,
    pub is_attached: bool,
    pub registers: UserRegisters,
    pub breakpoint_sites: StoppointCollection<BreakpointSite>,
    pub watchpoint_sites: StoppointCollection<Watchpoint>,
    pub syscall_catch_policy: SyscallCatchPolicy,
    pub expecting_syscall_exit: bool,
    pub _not_send_or_sync: PhantomData<*mut ()>,
}

pub struct Instruction {
    pub address: VirtAddr,
    pub text: String,
}

pub fn handle_stop(target: &mut Target, reason: &StopReason) {
    let rip = match target.process.get_pc() {
        Ok(pc) => pc.0,
        Err(_) => 0,
    };

    println!(
        "Process {} stopped at address 0x{:x}",
        target.process.pid, rip
    );

    match reason.status() {
        Pstatus::Stopped => {
            if let Some(signal) = reason.signal() {
                println!("stopped with signal {}", signal.to_string());
            }
            if reason.signal() == Some(SIGTRAP) {
                get_sigtrap_info(target, reason);
            }
        }
        Pstatus::Running => panic!("unreachable handle_stop"),
        Pstatus::Terminated => {
            if let Some(signal) = reason.signal() {
                println!("terminated with signal: {}", signal.to_string());
            }
        }
        Pstatus::Exited => {
            if let Some(status) = reason.exit_status() {
                println!("exited with status {}", status.to_string());
            }
        }
    }

    if reason.status() == Pstatus::Stopped {
        let process = &mut target.process;
        print_disassembly(process, VirtAddr(rip), 5);
    }
}

fn extract_func_name(s: &str) -> Option<&str> {
    let parts: Vec<&str> = s.split("::").collect();
    if parts.len() == 3 {
        Some(parts[1])
    } else {
        None
    }
}

fn get_sigtrap_info(target: &mut Target, reason: &StopReason) {
    let process = &mut target.process;

    if let Ok(pc) = process.get_pc() {
        if let Some(func) = target.elf.get_symbol_containing_address_virt(pc) {
            if elf64_st_type(func.st_info) == STT_FUNC {
                let mangled = target.elf.get_string(func.st_name as usize);
                let demangled = demangle(mangled).to_string();
                let demangled_simple = extract_func_name(&demangled).unwrap_or("");
                println!("demangled func name: {}", demangled_simple);
            }
        }
    }

    if reason.trap_reason == Some(TrapType::SoftwareBreak) {
        let pc = process.get_pc().unwrap();
        let site = process.breakpoint_sites.get_by_address_mut(pc).unwrap();
        println!(" (breakpoint {})", site.id());
    }

    if reason.trap_reason == Some(TrapType::HardwareBreak) {
        let id = process.get_current_hardware_stoppoint().unwrap();
        match id {
            HardwareStoppoint::Breakpoint(id) => {
                println!(" (breakpoint {})", id);
            }
            HardwareStoppoint::Watchpoint(id) => {
                let point = process.watchpoint_sites.get_by_id_mut(id).unwrap();
                println!(" (watchpoint {})", id);
                if point.data == point.previos_data {
                    println!("Value: {:x}", point.data)
                } else {
                    println!("Value: {:x}", point.previos_data);
                    println!("New value: {:x}", point.data);
                }
            }
        }
    }

    if reason.trap_reason == Some(TrapType::SingleStep) {
        println!(" (single step)");
    }

    if reason.trap_reason == Some(TrapType::Syscall) {
        if let Some(sys) = &reason.syscall_info {
            if sys.entry {
                let name = Syscalls::name(sys.id as u64).unwrap_or_else(|| "unknown");

                // extract the args array
                if let SyscallData::Args(args) = &sys.data {
                    // format each as hex, join with commas
                    let args_str = args
                        .iter()
                        .map(|v| format!("{:#x}", v))
                        .collect::<Vec<_>>()
                        .join(",");

                    println!(" (syscall entry)");
                    println!(" syscall: {}({})", name, args_str);
                }
            } else {
                // exit
                println!(" (syscall exit)");
                if let SyscallData::Ret(r) = sys.data {
                    println!(" syscall returned: {:#x}", r);
                }
            }
        }
    }
}

static NEXT_BREAKPOINT_SITE_ID: AtomicI32 = AtomicI32::new(1);
static NEXT_WATCHPOINT_ID: AtomicI32 = AtomicI32::new(1);

pub enum HardwareStoppoint {
    Breakpoint(i32), // BreakpointSite::Id
    Watchpoint(i32), // Watchpoint::Id
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

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn attach(&mut self) -> Result<()> {
        let pid = self.pid;
        if pid.as_raw() == 0 {
            bail!("Invalid PID");
        }

        attach(pid)?;
        self.wait_on_signal().unwrap();
        set_ptrace_options(pid)?;

        println!("Attached to {}", pid);
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        let pc = self.get_pc()?;
        if self.breakpoint_sites.enabled_stoppoint_at_address(pc) {
            let bp = self.breakpoint_sites.get_by_address_mut(pc).unwrap();
            bp.disable(&mut self.registers)?;
            step(self.pid, None).map_err(|e| anyhow::anyhow!("Failed to single step: {}", e))?;
            waitpid(self.pid, None)?;
            bp.enable(&mut self.registers)?;
        }

        if *self.syscall_catch_policy.mode() == CatchPolicyMode::None {
            cont(self.pid, None).map_err(|e| anyhow::anyhow!("Failed to continue: {}", e))?;
        } else {
            syscall(self.pid, None).map_err(|e| anyhow::anyhow!("Failed to continue: {}", e))?;
        }

        self.status = Some(Pstatus::Running);
        Ok(())
    }

    pub fn launch(program_path: String) -> Result<Self> {
        let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC)?;

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                let write_raw_fd = write_fd.into_raw_fd();
                close(write_raw_fd)?;

                let read_raw_fd = read_fd.into_raw_fd();
                let mut file = unsafe { File::from_raw_fd(read_raw_fd) };
                let mut error_message = String::new();
                file.read_to_string(&mut error_message)?;

                if !error_message.is_empty() {
                    waitpid(child, None)?;
                    bail!("Error from child: {}", error_message);
                }

                println!("Launched child process for {}: {}", program_path, child);
                let user_registers = UserRegisters::new();

                let mut process = Process {
                    pid: child,
                    status: None,
                    terminate_on_end: true,
                    is_attached: true,
                    registers: user_registers,
                    breakpoint_sites: StoppointCollection::new(),
                    watchpoint_sites: StoppointCollection::new(),
                    syscall_catch_policy: SyscallCatchPolicy::catch_none(),
                    expecting_syscall_exit: false,
                    _not_send_or_sync: PhantomData,
                };

                // Wait for the child to stop after exec and properly handle the initial stop
                process.wait_on_signal()?;
                set_ptrace_options(child)?;

                Ok(process)
            }
            Ok(ForkResult::Child) => {
                let read_raw_fd = read_fd.into_raw_fd();
                let write_raw_fd = write_fd.into_raw_fd();

                unsafe {
                    let current = personality(0xffffffff);
                    if current == -1 {
                        let err = "Failed to get personality";
                        write_to_pipe(write_raw_fd, err);
                        std::process::exit(1);
                    }

                    // Add ADDR_NO_RANDOMIZE flag, to disable ASLR
                    if personality((current | ADDR_NO_RANDOMIZE) as c_ulong) == -1 {
                        let err = "Failed to set personality to disable ASLR";
                        write_to_pipe(write_raw_fd, err);
                        std::process::exit(1);
                    }

                    if setpgid(0, 0) < 0 {
                        let err = "Could not set pgid";
                        write_to_pipe(write_raw_fd, err);
                        std::process::exit(1);
                    }
                }

                close(read_raw_fd)?;

                traceme()?;

                let c_path = CString::new(program_path.as_bytes())?;
                if execv(&c_path, &[c_path.clone()]).is_err() {
                    let error_message = "Exec failed".to_string();
                    write_to_pipe(write_raw_fd, &error_message);
                    std::process::exit(1);
                }

                unreachable!();
            }
            Err(_) => bail!("Fork failed"),
        }
    }

    pub fn wait_on_signal(&mut self) -> Result<StopReason> {
        match waitpid(self.pid, None) {
            Ok(wait_status) => {
                let reason = match wait_status {
                    WaitStatus::Exited(_pid, status) => {
                        self.status = Some(Pstatus::Exited);
                        Ok(StopReason {
                            reason: Pstatus::Exited,
                            status: Some(status as u8),
                            signal: None,
                            trap_reason: None,
                            syscall_info: None,
                        })
                    }
                    WaitStatus::Signaled(_pid, signal, _) => {
                        self.status = Some(Pstatus::Terminated);
                        Ok(StopReason {
                            reason: Pstatus::Terminated,
                            status: None,
                            signal: Some(signal),
                            trap_reason: None,
                            syscall_info: None,
                        })
                    }
                    WaitStatus::Stopped(_pid, signal) => {
                        self.status = Some(Pstatus::Stopped);
                        let mut reason = StopReason {
                            reason: Pstatus::Stopped,
                            status: None,
                            signal: Some(signal),
                            trap_reason: None,
                            syscall_info: None,
                        };
                        if self.is_attached == true {
                            self.read_all_registers()?;
                            self.augment_stop_reason(&mut reason)?;

                            let instr_begin = self.get_pc()? - 1;
                            let is_sigtrap = signal == SIGTRAP;
                            let is_software_breakpoint =
                                reason.trap_reason == Some(TrapType::SoftwareBreak);

                            if is_software_breakpoint
                                && is_sigtrap
                                && self
                                    .breakpoint_sites
                                    .enabled_stoppoint_at_address(instr_begin)
                            {
                                self.set_pc(instr_begin)?;
                            }

                            if reason.trap_reason == Some(TrapType::HardwareBreak) {
                                let id = self.get_current_hardware_stoppoint()?;

                                match id {
                                    HardwareStoppoint::Breakpoint(_) => {}
                                    HardwareStoppoint::Watchpoint(id) => {
                                        let (address, size) = {
                                            let watchpoint =
                                                self.watchpoint_sites.get_by_id_mut(id).unwrap();
                                            (watchpoint.address(), watchpoint.size)
                                        };

                                        let memory = self.read_memory(address, size)?;
                                        let watchpoint =
                                            self.watchpoint_sites.get_by_id_mut(id).unwrap();
                                        watchpoint.update_data(&memory);
                                    }
                                }
                            }
                        }
                        Ok(reason)
                    }
                    WaitStatus::PtraceSyscall(_pid) => {
                        self.status = Some(Pstatus::Stopped);
                        let mut reason = StopReason {
                            reason: Pstatus::Stopped,
                            status: None,
                            signal: Some(SIGTRAP),
                            trap_reason: Some(TrapType::Syscall),
                            syscall_info: None,
                        };
                        if self.is_attached == true {
                            self.read_all_registers()?;
                            self.augment_stop_reason(&mut reason)?;
                            if reason.trap_reason == Some(TrapType::Syscall) {
                                reason = self.maybe_resume_from_syscall(reason)?;
                            }
                        }
                        Ok(reason)
                    }
                    e => bail!("Process is not stopped {}: {:?}", self.pid, e),
                };
                reason
            }
            Err(e) => bail!("waitpid failed {}", e),
        }
    }
    pub fn read_all_registers(&mut self) -> Result<()> {
        match getregs(self.pid) {
            Ok(r) => {
                self.registers.data.regs = r;
            }
            Err(e) => bail!("Could not read GPR registers: {}", e),
        }

        let ret = unsafe {
            ptrace(
                PTRACE_GETFPREGS,
                self.pid.as_raw() as i32,
                ptr::null_mut::<c_void>(),
                &mut self.registers.data.i387 as *mut _ as *mut c_void,
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

            self.registers.data.u_debugreg[i] = data as u64;
        }

        Ok(())
    }

    pub fn step_instruction(&mut self) -> Result<StopReason> {
        let mut to_reenable: Option<*mut BreakpointSite> = None;
        let pc = self.get_pc()?;
        println!("Stepping at PC = 0x{:x}", pc.0);

        {
            if self.breakpoint_sites.enabled_stoppoint_at_address(pc) {
                if let Some(bp) = self.breakpoint_sites.get_by_address_mut(pc) {
                    bp.disable(&mut self.registers)?;
                    // Store raw pointer so we can re-enable later
                    to_reenable = Some(bp as *mut _);
                }
            }
        }

        step(self.pid, None).with_context(|| "Could not single step")?;

        let reason = self.wait_on_signal().unwrap();

        if let Some(bp_ptr) = to_reenable {
            unsafe {
                // SAFETY: we only use the pointer after the original borrow ends
                (*bp_ptr).enable(&mut self.registers)?;
            }
        }

        Ok(reason)
    }

    pub fn get_pc(&self) -> Result<VirtAddr> {
        let info = register_info_by_id(RegisterId::RIP);
        let value = self.registers.read(info);
        let pc: u64 = match value {
            RegisterValue::U64(v) => v,
            _ => panic!("Expected RegisterValue::U64 but got {:?}", value),
        };
        Ok(VirtAddr(pc))
    }

    pub fn set_pc(&mut self, addr: VirtAddr) -> Result<()> {
        let info = register_info_by_id(RegisterId::RIP);
        write_register(
            self.pid,
            &mut self.registers,
            info,
            RegisterValue::U64(addr.0),
        );
        Ok(())
    }

    pub fn create_watchpoint(
        &mut self,
        address: VirtAddr,
        mode: StoppointMode,
        size: usize,
    ) -> Result<()> {
        if self.watchpoint_sites.contains_address(address) {
            panic!("Watchpoint already exists at address {:#x}", address.0);
        }

        let id = NEXT_WATCHPOINT_ID.fetch_add(1, Ordering::SeqCst);

        let watchpoint = Watchpoint {
            id,
            pid: self.pid,
            address,
            is_enabled: false,
            hardware_register_index: -1,
            mode,
            size,
            data: 0,
            previos_data: 0,
        };

        self.watchpoint_sites.stoppoints.push(watchpoint);

        let wp = self.watchpoint_sites.stoppoints.last_mut().unwrap();
        wp.enable(&mut self.registers)?;

        println!(
            "Set watchpoint {} at {:#x} (mode = {:?}, size = {})",
            wp.id, wp.address.0, wp.mode, wp.size
        );

        Ok(())
    }

    pub fn create_breakpoint_site(
        &mut self,
        addr: VirtAddr,
        is_hardware: bool,
        is_internal: bool,
        parent_breakpoint_id: Option<i32>,
    ) -> Result<i32> {
        if let Some(existing) = self.breakpoint_sites.get_by_address_mut(addr) {
            if parent_breakpoint_id.is_some() {
                existing.parent_breakpoint_id = parent_breakpoint_id;
            }
            return Ok(existing.id);
        }

        let new_id = NEXT_BREAKPOINT_SITE_ID.fetch_add(1, Ordering::SeqCst);

        let new_site = BreakpointSite {
            id: new_id,
            pid: self.pid,
            address: addr,
            is_enabled: false,
            saved_data: 0,
            is_hardware,
            is_internal,
            hardware_register_index: -1,
            parent_breakpoint_id,
        };

        self.breakpoint_sites.stoppoints.push(new_site);
        Ok(new_id)
    }

    pub fn read_memory(&self, address: VirtAddr, mut amount: usize) -> Result<Vec<u8>> {
        let mut ret = vec![0u8; amount];
        let local_iov = iovec {
            iov_base: ret.as_mut_ptr() as *mut libc::c_void,
            iov_len: ret.len(),
        };

        let mut remote_iovs = Vec::new();
        let mut current_addr = address;

        while amount > 0 {
            let offset = current_addr.0 & 0xfff;
            let up_to_next_page = (0x1000 - offset) as usize;
            let chunk_size = amount.min(up_to_next_page);
            remote_iovs.push(libc::iovec {
                iov_base: current_addr.0 as *mut libc::c_void,
                iov_len: chunk_size,
            });

            amount -= chunk_size;
            current_addr = current_addr + (chunk_size as i64); // Or implement `.add()`
        }

        let result = unsafe {
            process_vm_readv(
                self.pid.as_raw(),
                &local_iov as *const libc::iovec,
                1,
                remote_iovs.as_ptr(),
                remote_iovs.len().try_into().unwrap(),
                0,
            )
        };

        if result < 0 {
            return Err(
                anyhow::anyhow!("Could not read process memory (pid {})", self.pid)
                    .context(std::io::Error::last_os_error()),
            );
        }

        Ok(ret)
    }

    pub fn read_memory_without_traps(&self, address: VirtAddr, amount: usize) -> Result<Vec<u8>> {
        let mut memory = self.read_memory(address, amount)?;

        // Get breakpoint sites in the memory region
        let sites = self
            .breakpoint_sites
            .get_in_region(address, address + amount.try_into().unwrap());

        for site in sites {
            if !site.is_enabled() || site.is_hardware {
                continue;
            }
            let offset = (site.address.0 - address.0) as usize;
            memory[offset] = site.saved_data;
        }

        Ok(memory)
    }

    pub fn from_bytes<T: Copy>(bytes: &[u8]) -> Result<T> {
        if bytes.len() != mem::size_of::<T>() {
            return Err(anyhow::anyhow!(
                "Expected {} bytes, got {}",
                mem::size_of::<T>(),
                bytes.len()
            ));
        }
        let mut value = mem::MaybeUninit::<T>::uninit();
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                value.as_mut_ptr() as *mut u8,
                mem::size_of::<T>(),
            );
            Ok(value.assume_init())
        }
    }

    pub fn read_memory_as<T: FromBytes>(&self, address: VirtAddr) -> Result<T> {
        let data = self.read_memory(address, std::mem::size_of::<T>())?;
        T::from_bytes(&data)
    }

    pub fn write_memory(&self, address: VirtAddr, data: &[u8]) -> Result<()> {
        let mut written = 0;

        while written < data.len() {
            let remaining = data.len() - written;
            let word: u64;

            if remaining >= 8 {
                // Copy 8 bytes directly into u64
                word = u64::from_le_bytes(data[written..written + 8].try_into().unwrap());
            } else {
                // Need to read original memory and merge partial write
                let read = self.read_memory(address + written.try_into().unwrap(), 8)?;
                let mut word_buf = [0u8; 8];
                word_buf[..remaining].copy_from_slice(&data[written..]);
                word_buf[remaining..].copy_from_slice(&read[remaining..]);
                word = u64::from_le_bytes(word_buf);
            }

            // Actually write the word with ptrace
            let result = unsafe {
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    self.pid.as_raw(),
                    (address + written.try_into().unwrap()).0 as *mut libc::c_void,
                    word as *mut libc::c_void,
                )
            };

            if result < 0 {
                return Err(anyhow::anyhow!(
                    "Failed to write memory at {:?}",
                    (address + written.try_into().unwrap()).0
                )
                .context(std::io::Error::last_os_error()));
            }

            written += 8;
        }

        Ok(())
    }

    pub fn disassemble(
        &self,
        n_instructions: usize,
        address: Option<VirtAddr>,
    ) -> Vec<Instruction> {
        let mut result = Vec::with_capacity(n_instructions);
        let addr = address.unwrap_or_else(|| self.get_pc().unwrap());

        let code = self
            .read_memory_without_traps(addr, n_instructions * 15)
            .unwrap();
        if code.is_empty() {
            return result;
        }

        let mut decoder = Decoder::with_ip(64, &code, addr.0, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();

        for _ in 0..n_instructions {
            if !decoder.can_decode() {
                break;
            }

            let instr = decoder.decode();
            let mut text = String::new();
            formatter.format(&instr, &mut text);

            result.push(Instruction {
                address: VirtAddr(instr.ip()),
                text,
            });
        }

        result
    }

    pub fn augment_stop_reason(&mut self, reason: &mut StopReason) -> Result<()> {
        let info =
            getsiginfo(self.pid).map_err(|e| anyhow::anyhow!("Failed to getsiginfo: {}", e))?;

        if reason.trap_reason == Some(TrapType::Syscall) {
            let sys_info = reason
                .syscall_info
                .get_or_insert_with(|| SyscallInformation {
                    id: 0,
                    entry: true,
                    data: SyscallData::Args([0; 6]),
                });

            if self.expecting_syscall_exit {
                sys_info.entry = false;
                sys_info.id = self.read_register_as_u64(RegisterId::ORIG_RAX)? as u16;
                let ret_val = self.read_register_as_u64(RegisterId::RAX)? as i64;
                sys_info.data = SyscallData::Ret(ret_val);
                self.expecting_syscall_exit = false;
            } else {
                sys_info.entry = true;
                sys_info.id = self.read_register_as_u64(RegisterId::ORIG_RAX)? as u16;

                let arg_regs = [
                    RegisterId::RDI,
                    RegisterId::RSI,
                    RegisterId::RDX,
                    RegisterId::R10,
                    RegisterId::R8,
                    RegisterId::R9,
                ];
                let mut args = [0u64; 6];
                for (i, reg) in arg_regs.iter().enumerate() {
                    args[i] = self.read_register_as_u64(reg.clone())?;
                }
                sys_info.data = SyscallData::Args(args);
                self.expecting_syscall_exit = true;
            }

            reason.signal = Some(SIGTRAP);
            reason.trap_reason = Some(TrapType::Syscall);
            return Ok(());
        }

        self.expecting_syscall_exit = false;

        reason.trap_reason = None;

        if reason.signal == Some(SIGTRAP) {
            reason.trap_reason = match info.si_code {
                libc::TRAP_TRACE => Some(TrapType::SingleStep),
                libc::TRAP_BRKPT | libc::SI_KERNEL => Some(TrapType::SoftwareBreak),
                libc::TRAP_HWBKPT => Some(TrapType::HardwareBreak),
                _ => None,
            };
        }

        Ok(())
    }

    pub fn get_current_hardware_stoppoint(&mut self) -> Result<HardwareStoppoint> {
        // Read DR6 (debug status register)
        let dr6_info = register_info_by_id(RegisterId::DR6);
        let status_val = match self.registers.read(dr6_info) {
            RegisterValue::U64(val) => val,
            other => bail!("Unexpected value in DR6: {:?}", other),
        };

        // If no bits set, no hardware stoppoint triggered
        if status_val == 0 {
            bail!("No hardware stoppoint triggered");
        }

        // Find lowest set bit index (corresponds to DRx triggered)
        let index = status_val.trailing_zeros() as usize;
        if index >= DEBUG_REG_IDS.len() {
            bail!("Invalid DRx index from DR6 status: {}", index);
        }

        // Read the corresponding DRx address register
        let dr_id = DEBUG_REG_IDS[index].clone();
        let dr_info = register_info_by_id(dr_id);
        let addr_val = match self.registers.read(dr_info) {
            RegisterValue::U64(val) => val,
            other => bail!("Unexpected value in DRx: {:?}", other),
        };

        let addr = VirtAddr(addr_val);

        // Check if this address corresponds to a breakpoint site
        if self.breakpoint_sites.contains_address(addr) {
            let site_id = self.breakpoint_sites.get_by_address_mut(addr).unwrap().id();
            Ok(HardwareStoppoint::Breakpoint(site_id))
        } else if self.watchpoint_sites.contains_address(addr) {
            let watch_id = self.watchpoint_sites.get_by_address_mut(addr).unwrap().id();
            Ok(HardwareStoppoint::Watchpoint(watch_id))
        } else {
            bail!(
                "Address at DR{} not recognized as breakpoint or watchpoint",
                index
            );
        }
    }

    pub fn read_register_as_u64(&self, reg_id: RegisterId) -> Result<u64> {
        let reg_info = register_info_by_id(reg_id.clone());
        match self.registers.read(reg_info) {
            RegisterValue::U64(val) => Ok(val),
            other => bail!("Unexpected value for {:?}: {:?}", reg_id, other),
        }
    }

    fn maybe_resume_from_syscall(&mut self, reason: StopReason) -> Result<StopReason> {
        if *self.syscall_catch_policy.mode() == CatchPolicyMode::Some {
            let to_catch = self.syscall_catch_policy.to_catch();

            if let Some(sys_info) = &reason.syscall_info {
                if !to_catch.contains(&(sys_info.id as i32)) {
                    self.resume()?;
                    // NOTE: recursive solution chosen for simplicity, will be refactored later
                    return self.wait_on_signal();
                }
            }
        }

        Ok(reason)
    }

    pub fn get_auxv(&self) -> Result<HashMap<u64, u64>> {
        let path = format!("/proc/{}/auxv", self.pid);
        let mut file = File::open(Path::new(&path))?;

        let mut ret = HashMap::new();
        let mut buf = [0u8; 16]; // 2 x u64 = 16 bytes

        while file.read_exact(&mut buf).is_ok() {
            let id = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
            let value = u64::from_ne_bytes(buf[8..16].try_into().unwrap());

            const AT_NULL: u64 = 0;
            if id == AT_NULL {
                break;
            }

            ret.insert(id, value);
        }

        Ok(ret)
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

fn set_ptrace_options(pid: Pid) -> Result<()> {
    let res = unsafe {
        ptrace(
            PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<c_void>(),
            PTRACE_O_TRACESYSGOOD,
        )
    };

    if res < 0 {
        bail!("Failed to set TRACESYSGOOD option");
    }
    Ok(())
}
