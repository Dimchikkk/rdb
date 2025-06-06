use nix::{libc::{self, c_long, PTRACE_PEEKDATA, PTRACE_POKEDATA}, unistd::Pid};
use anyhow::Result;
use libc::{ptrace, c_void};
use std::ptr;
use std::io::Error;

use crate::stoppoint::{Stoppoint, VirtAddr};

pub struct BreakpointSite {
    pub id: i32,
    pub address: VirtAddr,
    pub is_enabled: bool,
    pub saved_data: u8,
}

impl Stoppoint for BreakpointSite {
    type Id = i32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn at_address(&self, addr: VirtAddr) -> bool {
        self.address == addr
    }

    fn in_range(&self, low: VirtAddr, high: VirtAddr) -> bool {
        self.address >= low && self.address <= high
    }

    fn enable(&mut self, pid: Pid) -> Result<()> {
        if self.is_enabled {
            return Ok(());
        }

        unsafe {
            *libc::__errno_location() = 0;
        }

        let data = unsafe {
            ptrace(
                PTRACE_PEEKDATA,
                pid,
                self.address.0 as *mut c_void,
                ptr::null_mut::<c_void>(),
            )
        };

        let err_no = unsafe { *libc::__errno_location() };
        if data == -1 && err_no != 0 {
            anyhow::bail!(Error::from_raw_os_error(err_no));
        }

        self.saved_data = (data & 0xff) as u8;

        let data_with_int3 = (data & !0xff) | 0xcc;

        let ret = unsafe {
            ptrace(
                PTRACE_POKEDATA,
                pid,
                self.address.0 as *mut c_void,
                data_with_int3 as c_long,
            )
        };

        if ret == -1 {
            anyhow::bail!(Error::last_os_error());
        }

        self.is_enabled = true;
        Ok(())
    }

    fn disable(&mut self, pid: Pid) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }

        // Clear errno before ptrace call
        unsafe {
            *libc::__errno_location() = 0;
        }

        // Read original data at breakpoint address
        let data = unsafe {
            ptrace(
                PTRACE_PEEKDATA,
                pid,
                self.address.0 as *mut c_void,
                ptr::null_mut::<c_void>(),
            )
        };

        let err_no = unsafe { *libc::__errno_location() };
        if data == -1 && err_no != 0 {
            anyhow::bail!(Error::from_raw_os_error(err_no));
        }

        // Restore lowest byte with saved_data
        let restored_data = ((data as u64) & !0xff) | (self.saved_data as u64);

        // Write restored data back
        let ret = unsafe {
            ptrace(
                PTRACE_POKEDATA,
                pid,
                self.address.0 as *mut c_void,
                restored_data as c_long,

            )
        };

        if ret == -1 {
            anyhow::bail!(Error::last_os_error());
        }

        self.is_enabled = false;
        Ok(())
    }
}
