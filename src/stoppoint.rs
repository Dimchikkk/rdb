use anyhow::Result;
use nix::unistd::Pid;

use crate::{
    registers::{
        register_info_by_id, write_register, RegisterId, RegisterValue, UserRegisters,
        DEBUG_REG_IDS,
    },
    types::VirtAddr,
};

#[derive(Clone, Debug)]
pub enum StoppointMode {
    Write,
    ReadWrite,
    Execute,
}

pub trait Stoppoint {
    type Id: PartialEq + Copy;

    fn id(&self) -> Self::Id;
    fn pid(&self) -> Pid;
    fn address(&self) -> VirtAddr;

    fn is_enabled(&self) -> bool;
    fn enable(&mut self, registers: &mut UserRegisters) -> Result<()>;
    fn disable(&mut self, registers: &mut UserRegisters) -> Result<()>;

    fn at_address(&self, addr: VirtAddr) -> bool {
        self.address() == addr
    }

    fn in_range(&self, low: VirtAddr, high: VirtAddr) -> bool {
        self.address() >= low && self.address() <= high
    }

    fn clear_hardware_stoppoint(&mut self, registers: &mut UserRegisters, index: usize) {
        // Get DRx register id
        let dr_id = DEBUG_REG_IDS[index].clone();
        let dr_info = register_info_by_id(dr_id);

        // Clear the hardware address
        write_register(self.pid(), registers, dr_info, RegisterValue::U64(0));

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
        write_register(self.pid(), registers, dr7_info, RegisterValue::U64(masked));
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
        write_register(
            self.pid(),
            registers,
            dr_info,
            RegisterValue::U64(address.0),
        );

        let mode_flag = encode_hardware_stoppoint_mode(mode);
        let size_flag = encode_hardware_stoppoint_size(size);

        let enable_bit = 1u64 << (free_index * 2);
        let mode_bits = mode_flag << (free_index * 4 + 16);
        let size_bits = size_flag << (free_index * 4 + 18);

        let clear_mask = (0b11u64 << (free_index * 2)) | (0b1111u64 << (free_index * 4 + 16));
        let mut masked = control & !clear_mask;

        masked |= enable_bit | mode_bits | size_bits;

        // Write updated DR7
        write_register(self.pid(), registers, dr7_info, RegisterValue::U64(masked));

        println!("Setting hardware breakpoint:");
        println!("  DR{} = {:#018x}", free_index, address.0);
        println!("  DR7 = {:#018x}", masked);

        free_index as i32
    }
}

#[derive(Clone)]
pub struct StoppointCollection<T: Stoppoint> {
    pub stoppoints: Vec<T>,
}

impl<T: Stoppoint> StoppointCollection<T> {
    pub fn new() -> Self {
        Self {
            stoppoints: Vec::new(),
        }
    }

    pub fn contains_id(&self, id: T::Id) -> bool {
        self.stoppoints.iter().any(|sp| sp.id() == id)
    }

    pub fn contains_address(&self, addr: VirtAddr) -> bool {
        self.stoppoints.iter().any(|sp| sp.at_address(addr))
    }

    pub fn enabled_stoppoint_at_address(&self, addr: VirtAddr) -> bool {
        self.stoppoints
            .iter()
            .any(|sp| sp.at_address(addr) && sp.is_enabled())
    }

    pub fn get_by_id_mut(&mut self, id: T::Id) -> Option<&mut T> {
        self.stoppoints.iter_mut().find(|sp| sp.id() == id)
    }

    pub fn get_by_id(&self, id: T::Id) -> Option<&T> {
        self.stoppoints.iter().find(|sp| sp.id() == id)
    }

    pub fn get_by_address_mut(&mut self, addr: VirtAddr) -> Option<&mut T> {
        self.stoppoints.iter_mut().find(|sp| sp.at_address(addr))
    }

    pub fn get_by_address(&self, addr: VirtAddr) -> Option<&T> {
        self.stoppoints.iter().find(|sp| sp.at_address(addr))
    }

    pub fn remove_by_id(&mut self, registers: &mut UserRegisters, id: T::Id) -> Result<()> {
        if let Some(pos) = self.stoppoints.iter().position(|sp| sp.id() == id) {
            self.stoppoints[pos].disable(registers)?;
            self.stoppoints.remove(pos);
        }
        Ok(())
    }

    pub fn remove_by_address(
        &mut self,
        registers: &mut UserRegisters,
        addr: VirtAddr,
    ) -> Result<()> {
        if let Some(pos) = self.stoppoints.iter().position(|sp| sp.at_address(addr)) {
            self.stoppoints[pos].disable(registers)?;
            self.stoppoints.remove(pos);
        }
        Ok(())
    }

    pub fn get_in_region(&self, low: VirtAddr, high: VirtAddr) -> Vec<&T> {
        self.stoppoints
            .iter()
            .filter(|site| site.in_range(low, high))
            .collect()
    }
}

/// Encode the breakpoint/watchpoint mode into the 2-bit DR7 flags.
pub fn encode_hardware_stoppoint_mode(mode: StoppointMode) -> u64 {
    match mode {
        StoppointMode::Write => 0b01,
        StoppointMode::ReadWrite => 0b11,
        StoppointMode::Execute => 0b00,
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
