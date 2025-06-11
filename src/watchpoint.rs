use nix::unistd::Pid;
use anyhow::Result;

use crate::stoppoint::{Stoppoint, StoppointMode, VirtAddr};

pub struct Watchpoint {
    pub id: i32,
    pub pid: Pid,
    pub address: VirtAddr,
    pub is_enabled: bool,
    pub hardware_register_index: i32,
    pub mode: StoppointMode,
    pub size: usize,
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
