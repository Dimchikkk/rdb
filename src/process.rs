use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::atomic::{AtomicI32, Ordering};
use nix::fcntl::OFlag;
use nix::sys::signal::Signal::SIGTRAP;
use std::os::unix::io::RawFd;
use anyhow::{bail, Context, Result};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::ptrace::{attach, cont, detach, getregs, step, traceme };
use nix::unistd::{close, execv, fork, pipe2, ForkResult, Pid};
use nix::sys::signal::{kill, Signal};
use nix::libc::{self, c_long, c_ulong, iovec, personality, process_vm_readv, ADDR_NO_RANDOMIZE, PTRACE_GETFPREGS, PTRACE_PEEKUSER};
use libc::{ptrace, c_void};
use std::{mem, ptr};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

use crate::breakpoints::BreakpointSite;
use crate::print_disassembly;
use crate::registers::{register_info_by_id, write_register, RegisterId, RegisterValue, UserRegisters, DEBUG_REG_IDS};
use crate::stoppoint::{Stoppoint, StoppointCollection, StoppointMode, VirtAddr};
use crate::utils::FromBytes;
use crate::watchpoint::Watchpoint;

#[derive(PartialEq, Eq)]
pub enum Pstatus {
    Stopped,
    Running,
    Terminated,
    Exited
}

pub struct StopReason {
    reason: Pstatus,
    status: u8,
    signal: String,
}

pub struct Process {
    pub pid: Pid,
    pub status: Option<Pstatus>,
    pub terminate_on_end: bool,
    pub is_attached: bool,
    pub registers: UserRegisters,
    pub breakpoint_sites: StoppointCollection<BreakpointSite>,
    pub watchpoint_sites: StoppointCollection<Watchpoint>,
}

pub struct Instruction {
    pub address: VirtAddr,
    pub text: String,
}

pub fn handle_stop(process: &mut Process, reason: StopReason) {
    let rip = process.get_pc().unwrap().0;

    println!("Process {} stopped at address 0x{:x}", process.pid, rip);

    match reason.reason {
        Pstatus::Stopped => println!("stopped with signal {}", reason.signal),
        Pstatus::Running => panic!("unreachable print_stop_reason"),
        Pstatus::Terminated => println!("terminated with signal: {}", reason.signal),
        Pstatus::Exited => println!("exited with status {}", reason.status),
    }

    if reason.reason == Pstatus::Stopped {
        print_disassembly(&process, VirtAddr(rip), 5);
    }
}

static NEXT_BREAKPOINT_ID: AtomicI32 = AtomicI32::new(1);
static NEXT_WATCHPOINT_ID: AtomicI32 = AtomicI32::new(1);

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

impl Process {
    pub fn attach(&mut self) -> Result<()> {
        let pid = self.pid;
        if pid.as_raw() == 0 {
            bail!("Invalid PID");
        }

        attach(pid)?;
        self.wait_on_signal()?;

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

        cont(self.pid, None).map_err(|e| anyhow::anyhow!("Failed to continue: {}", e))?;
        self.status = Some(Pstatus::Running);
        println!("Resumed process: {}", self.pid);
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

                waitpid(child, None)?;
                println!("Launched child process for {}: {}", program_path, child);
                let user_registers = UserRegisters::new();
                Ok(Process {
                    pid: child,
                    status: Some(Pstatus::Running),
                    terminate_on_end: true,
                    is_attached: true,
                    registers: user_registers,
                    breakpoint_sites: StoppointCollection::new(),
                    watchpoint_sites: StoppointCollection::new(),
                })
            }
            Ok(ForkResult::Child) => {
                let read_raw_fd = read_fd.into_raw_fd();
                let write_raw_fd = write_fd.into_raw_fd();

                // Disable ASLR by setting personality flag
                unsafe {
                    let current = personality(0xffffffff);
                    if current == -1 {
                        let err = "Failed to get personality";
                        write_to_pipe(write_raw_fd, err);
                        std::process::exit(1);
                    }

                    // Add ADDR_NO_RANDOMIZE flag
                    if personality((current | ADDR_NO_RANDOMIZE) as c_ulong) == -1 {
                        let err = "Failed to set personality to disable ASLR";
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
                        Ok(StopReason { reason: Pstatus::Exited, status: status as u8, signal: "".to_string() })
                    },
                    WaitStatus::Signaled(_pid, signal, _) => {
                        self.status = Some(Pstatus::Terminated);
                        Ok(StopReason { reason: Pstatus::Terminated, status: 0, signal: signal.to_string() })
                    },
                    WaitStatus::Stopped(_pid, signal) => {
                        self.status = Some(Pstatus::Stopped);
                        if self.is_attached == true {
                            self.read_all_registers()?;

                            let instr_begin = self.get_pc()? - 1;
                            let is_sigtrap = signal == SIGTRAP;
                            if is_sigtrap && self.breakpoint_sites.enabled_stoppoint_at_address(instr_begin) {
                                self.set_pc(instr_begin)?;
                            }
                        }
                        Ok(StopReason { reason: Pstatus::Stopped, status: 0, signal: signal.to_string() })
                    },
                    _ => bail!("Process is not stopped: {}", self.pid),
                };
                reason
            },
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

        let reason = self.wait_on_signal()?;

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
        write_register(self.pid, &mut self.registers, info, RegisterValue::U64(addr.0));
        Ok(())
    }

    pub fn create_watchpoint(&mut self, address: VirtAddr, mode: StoppointMode, size: usize) -> Result<()> {
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

    pub fn create_breakpoint_site(&mut self, addr: VirtAddr, is_hardware: bool) -> Result<()> {
        if self.breakpoint_sites.contains_address(addr) {
            panic!("Breakpoint site already created at address {:#x}", addr.0);
        }

        let new_id = NEXT_BREAKPOINT_ID.fetch_add(1, Ordering::SeqCst);

        let new_site = BreakpointSite {
            id: new_id,
            pid: self.pid,
            address: addr,
            is_enabled: false,
            saved_data: 0,
            is_internal: false,
            hardware_register_index: -1,
            is_hardware,
        };

        self.breakpoint_sites.stoppoints.push(new_site);

        let breakpoint = self.breakpoint_sites.stoppoints.last_mut().unwrap();
        breakpoint.enable(&mut self.registers)
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
            return Err(anyhow::anyhow!("Could not read process memory (pid {})", self.pid)
                       .context(std::io::Error::last_os_error()));
        }

        Ok(ret)
    }

    pub fn read_memory_without_traps(
        &self,
        address: VirtAddr,
        amount: usize,
    ) -> Result<Vec<u8>> {
        let mut memory = self.read_memory(address, amount)?;

        // Get breakpoint sites in the memory region
        let sites = self.breakpoint_sites.get_in_region(address, address + amount.try_into().unwrap());

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

    pub fn read_memory_as<T: FromBytes>(self, address: VirtAddr) -> Result<T> {
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
                return Err(anyhow::anyhow!("Failed to write memory at {:?}", (address + written.try_into().unwrap()).0)
                           .context(std::io::Error::last_os_error()));
            }

            written += 8;
        }

        Ok(())
    }

    pub fn disassemble(&self, n_instructions: usize, address: Option<VirtAddr>) -> Vec<Instruction> {
        let mut result = Vec::with_capacity(n_instructions);
        let addr = address.unwrap_or_else(|| self.get_pc().unwrap());

        let code = self.read_memory_without_traps(addr, n_instructions * 15).unwrap();
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
