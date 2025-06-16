use std::path::{Path, PathBuf};
use std::marker::PhantomData;

use anyhow::{Result, bail};
use nix::libc::AT_ENTRY;
use nix::unistd::Pid;

use crate::elf::Elf;
use crate::process::Process;
use crate::stoppoint::StoppointCollection;
use crate::syscall::SyscallCatchPolicy;
use crate::types::VirtAddr;
use crate::registers::UserRegisters;

pub struct Target {
    pub process: Box<Process>,
    pub elf: Box<Elf>,
}

impl Target {
    pub fn launch(path: PathBuf) -> Result<Self> {
        let proc = Box::new(Process::launch(path.to_string_lossy().into_owned())?);
        let elf = create_loaded_elf(&proc, &path).unwrap();

        Ok(Self { process: proc, elf })
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
        })
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
