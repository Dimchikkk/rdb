use nix::{libc::{self, c_long, PTRACE_PEEKDATA, PTRACE_POKEDATA}, unistd::Pid};
use anyhow::Result;
use libc::{ptrace, c_void};
use std::ptr;
use std::io::Error;

use crate::{registers::{register_info_by_id, write_register, RegisterId, RegisterValue, UserRegisters, DEBUG_REG_IDS}, stoppoint::{Stoppoint, StoppointMode, VirtAddr}};

pub struct BreakpointSite {
    pub id: i32,
    pub pid: Pid,
    pub address: VirtAddr,
    pub is_enabled: bool,
    pub saved_data: u8,
    pub is_hardware: bool,
    pub is_internal: bool,
    pub hardware_register_index: i32,
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

    fn enable(&mut self, registers: &mut UserRegisters) -> Result<()> {
        if self.is_enabled {
            return Ok(());
        }

        if self.is_hardware {
            self.hardware_register_index = self.set_hardware_stoppoint(registers, self.address, StoppointMode::Execute, 1);
        } else {
            unsafe {
                *libc::__errno_location() = 0;
            }

            let data = unsafe {
                ptrace(
                    PTRACE_PEEKDATA,
                    self.pid,
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
                    self.pid,
                    self.address.0 as *mut c_void,
                    data_with_int3 as c_long,
                )
            };

            if ret == -1 {
                anyhow::bail!(Error::last_os_error());
            }
        }

        self.is_enabled = true;
        Ok(())
    }

    fn disable(&mut self, registers: &mut UserRegisters) -> Result<()> {
        if !self.is_enabled {
            return Ok(());
        }

        if self.is_hardware && self.hardware_register_index != -1 {
            self.clear_hardware_stoppoint(registers, self.hardware_register_index as usize);
            self.hardware_register_index = -1;
        } else {
            // Clear errno before ptrace call
            unsafe {
                *libc::__errno_location() = 0;
            }

            // Read original data at breakpoint address
            let data = unsafe {
                ptrace(
                    PTRACE_PEEKDATA,
                    self.pid,
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
                    self.pid,
                    self.address.0 as *mut c_void,
                    restored_data as c_long,

                )
            };

            if ret == -1 {
                anyhow::bail!(Error::last_os_error());
            }
        }


        self.is_enabled = false;
        Ok(())
    }

    fn clear_hardware_stoppoint(&mut self, registers: &mut UserRegisters, index: usize) {
        // Get DRx register id
        let dr_id = DEBUG_REG_IDS[index].clone();
        let dr_info = register_info_by_id(dr_id);

        // Clear the hardware address
        write_register(self.pid, registers, dr_info, RegisterValue::U64(0));

        // Read DR7 control register
        let dr7_info = register_info_by_id(RegisterId::DR7);
        let control = match registers.read(dr7_info) {
            RegisterValue::U64(val) => val,
            other => panic!("Unexpected value in DR7: {:?}", other),
        };

        // Clear the enable and condition bits for the given index
        let clear_mask = (0b11 << (index * 2)) | (0b1111 << (index * 4 + 16));
        let masked = control & !clear_mask;

        // Write back the updated DR7 value
        write_register(self.pid, registers, dr7_info, RegisterValue::U64(masked));
    }

    fn set_hardware_stoppoint(
        &mut self,
        registers: &mut UserRegisters,
        address: VirtAddr,
        mode: StoppointMode,
        size: usize,
    ) -> i32 {
        // Read current DR7 value
        let dr7_info = register_info_by_id(RegisterId::DR7);
        let control = match registers.read(dr7_info) {
            RegisterValue::U64(val) => val,
            other => panic!("Unexpected value in DR7: {:?}", other),
        };

        // Find a free debug register index (0 to 3)
        let free_index = find_free_stoppoint_register(control);

        // Write the address into DRx
        let dr_id = DEBUG_REG_IDS[free_index].clone();
        let dr_info = register_info_by_id(dr_id);
        write_register(self.pid, registers, dr_info, RegisterValue::U64(address.0));

        let mode_flag = encode_hardware_stoppoint_mode(mode);
        let size_flag = encode_hardware_stoppoint_size(size);

        let enable_bit = 1u64 << (free_index * 2);
        let mode_bits = mode_flag << (free_index * 4 + 16);
        let size_bits = size_flag << (free_index * 4 + 18);

        let clear_mask = (0b11u64 << (free_index * 2)) | (0b1111u64 << (free_index * 4 + 16));
        let mut masked = control & !clear_mask;

        masked |= enable_bit | mode_bits | size_bits;

        // Write updated DR7
        write_register(self.pid, registers, dr7_info, RegisterValue::U64(masked));

        println!("Setting hardware breakpoint:");
        println!("  DR{} = {:#018x}", free_index, address.0);
        println!("  DR7 = {:#018x}", masked);

        free_index as i32
    }
}

/// Encode the breakpoint/watchpoint mode into the 2-bit DR7 flags.
pub fn encode_hardware_stoppoint_mode(mode: StoppointMode) -> u64 {
    match mode {
        StoppointMode::Write     => 0b01,
        StoppointMode::ReadWrite => 0b11,
        StoppointMode::Execute   => 0b00,
    }
}

/// Encode the watched data size into the 2-bit DR7 flags.
pub fn encode_hardware_stoppoint_size(size: usize) -> u64 {
    match size {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,
        _ => panic!("Invalid stoppoint size: {}", size),
    }
}

/// Find an unused DRx slot (0..3) by checking its enable bits in DR7.
/// Panics if none are free.
pub fn find_free_stoppoint_register(control_register: u64) -> usize {
    for i in 0..4 {
        let mask = 0b11 << (i * 2);
        if (control_register & mask) == 0 {
            return i;
        }
    }
    panic!("No remaining hardware debug registers");
}
