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
use nix::sys::ptrace::{attach, cont, detach, getregs, setregs, step, traceme, write_user };
use nix::unistd::{close, execv, fork, pipe2, ForkResult, Pid};
use nix::sys::signal::{kill, Signal};
use nix::libc::{self, c_long, c_ulong, personality, user_fpregs_struct, user_regs_struct, ADDR_NO_RANDOMIZE, PTRACE_GETFPREGS, PTRACE_PEEKUSER, PTRACE_SETFPREGS};
use libc::{ptrace, c_void};
use std::ptr;
use std::io::Error;

use crate::breakpoints::BreakpointSite;
use crate::registers::{register_info_by_id, RegisterId, RegisterInfo, RegisterType, RegisterValue, UserRegisters, DEBUG_REG_IDS};
use crate::stoppoint::{Stoppoint, StoppointCollection, VirtAddr};

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
}

pub fn print_stop_reason(process: &mut Process, reason: StopReason) {
    println!("Process {} ", process.pid.to_string());

    match reason.reason {
        Pstatus::Stopped => println!("stopped with signal {}", reason.signal),
        Pstatus::Running => panic!("unreachable print_stop_reason"),
        Pstatus::Terminated => println!("terminated with signal: {}", reason.signal),
        Pstatus::Exited => println!("exited with status {}", reason.status),
    }
}

static NEXT_BREAKPOINT_ID: AtomicI32 = AtomicI32::new(0);

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
        let maybe_bp_id = {
            if let Some(bp) = self.breakpoint_sites.get_by_address_mut(pc) {
                if !bp.is_enabled {
                    None
                } else {
                    bp.disable(self.pid)?;
                    Some(bp.id)
                }
            } else {
                None
            }
        };

        if let Some(bpid) = maybe_bp_id {
            step(self.pid, None).map_err(|e| anyhow::anyhow!("Failed to single step: {}", e))?;

            waitpid(self.pid, None)?;
            if let Some(bp) = self.breakpoint_sites.get_by_id_mut(bpid) {
                bp.enable(self.pid)?;
            }
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
                self.registers.regs = r;
            }
            Err(e) => bail!("Could not read GPR registers: {}", e),
        }

        let ret = unsafe {
            ptrace(
                PTRACE_GETFPREGS,
                self.pid.as_raw() as i32,
                ptr::null_mut::<c_void>(),
                &mut self.registers.fp_regs as *mut _ as *mut c_void,
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

            self.registers.debug_regs[i] = data as u64;
        }

        Ok(())
    }

    pub fn write_user_area(&self, offset: usize, data: u64) -> Result<()> {
        if write_user(self.pid, offset as _, data as i64).is_err() {
            bail!("Could not write to user area");
        }
        Ok(())
    }

    pub fn write_fprs(&self, fprs: &user_fpregs_struct) -> Result<()> {
        unsafe {
            let ret = ptrace(
                PTRACE_SETFPREGS,
                self.pid.as_raw(),
                ptr::null_mut::<c_void>(),
                fprs as *const _ as *mut c_void,
            );
            if ret != 0 {
                let err = Error::last_os_error();
                bail!("Could not write floating point registers: {}", err);
            }
        }
        Ok(())
    }

    pub fn write_gprs(&self, gprs: &user_regs_struct) -> Result<()> {
        if setregs(self.pid, *gprs).is_err() {
            bail!("Could not write general purpose registers");
        }
        Ok(())
    }

    pub fn write_register(&mut self, info: &RegisterInfo, val: RegisterValue) {
        self.registers.write_raw(info, val);

        if info.register_type == RegisterType::Fpr {
            self.write_fprs(&self.registers.fp_regs)
                .unwrap_or_else(|e| panic!("Failed to write FPR registers: {}", e));
        } else {
            // align offset down to 8 bytes and write that word
            let aligned_offset = info.offset & !0b111;
            let aligned_value = unsafe {
                let aligned_ptr = (&self.registers.regs as *const _ as *const u8)
                    .add(aligned_offset);
                aligned_ptr.cast::<u64>().read()
            };
            self.write_user_area(aligned_offset, aligned_value)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to write GPR/debug at offset {}: {}",
                        aligned_offset, e
                    )
                });
        }
    }

    pub fn step_instruction(&mut self) -> Result<StopReason> {
        let mut to_reenable: Option<*mut BreakpointSite> = None;
        let pc = self.get_pc()?;
        println!("Stepping at PC = 0x{:x}", pc.0);

        {
            if self.breakpoint_sites.enabled_stoppoint_at_address(pc) {
                if let Some(bp) = self.breakpoint_sites.get_by_address_mut(pc) {
                    bp.disable(self.pid)?;
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
                (*bp_ptr).enable(self.pid)?;
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
        self.write_register(info, RegisterValue::U64(addr.0));
        Ok(())
    }

    pub fn create_breakpoint_site(&mut self, addr: VirtAddr) -> &mut BreakpointSite {
        if self.breakpoint_sites.contains_address(addr) {
            panic!("Breakpoint site already created at address {:#x}", addr.0);
        }

        let new_id = NEXT_BREAKPOINT_ID.fetch_add(1, Ordering::SeqCst);

        let new_site = BreakpointSite {
            id: new_id,
            address: addr,
            is_enabled: false,
            saved_data: 0,
        };

        self.breakpoint_sites.stoppoints.push(new_site);

        self.breakpoint_sites.stoppoints.last_mut().unwrap()
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
