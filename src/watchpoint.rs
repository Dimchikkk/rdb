use nix::unistd::Pid;
use anyhow::Result;

use crate::{stoppoint::{Stoppoint, StoppointMode}, types::VirtAddr};

#[derive(Clone)]
pub struct Watchpoint {
    pub id: i32,
    pub pid: Pid,
    pub address: VirtAddr,
    pub is_enabled: bool,
    pub hardware_register_index: i32,
    pub mode: StoppointMode,
    pub size: usize,
    pub data: u64,
    pub previos_data: u64,
}

impl Watchpoint {
    pub fn update_data(&mut self, memory: &[u8]) {
        let mut new_data = 0u64;
        let bytes_to_copy = self.size.min(size_of::<u64>());

        // Safety: Copy up to 8 bytes into new_data
        unsafe {
            std::ptr::copy_nonoverlapping(
                memory.as_ptr(),
                &mut new_data as *mut u64 as *mut u8,
                bytes_to_copy,
            );
        }

        self.previos_data = std::mem::replace(&mut self.data, new_data);
    }
}

impl Stoppoint for Watchpoint {
    type Id = i32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn pid(&self) -> Pid {
       self.pid
    }

    fn address(&self) -> VirtAddr {
        self.address
    }

    fn is_enabled(&self) -> bool {
        return self.is_enabled;
    }

    fn enable(&mut self, registers: &mut crate::registers::UserRegisters) -> Result<()> {
        if self.is_enabled {
            return Ok(());
        }

        self.hardware_register_index = self.set_hardware_stoppoint(registers, self.address, self.mode.clone(), self.size);

        self.is_enabled = true;
        Ok(())
    }

    fn disable(&mut self, registers: &mut crate::registers::UserRegisters) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }

        self.clear_hardware_stoppoint(registers, self.hardware_register_index as usize);
        self.hardware_register_index = -1;

        self.is_enabled = false;
        Ok(())
    }
}
