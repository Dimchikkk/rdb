use std::ops::{Add, AddAssign, Sub, SubAssign};
use anyhow::Result;

use crate::registers::UserRegisters;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub u64);

impl Add<i64> for VirtAddr  {
    type Output = Self;

    fn add(self, offset: i64) -> Self {
        VirtAddr((self.0 as i64 + offset) as u64)
    }
}

impl Sub<i64> for VirtAddr  {
    type Output = Self;

    fn sub(self, offset: i64) -> Self {
        VirtAddr((self.0 as i64 - offset) as u64)
    }
}

impl AddAssign<i64> for VirtAddr {
    fn add_assign(&mut self, offset: i64) {
        self.0 = (self.0 as i64 + offset) as u64;
    }
}

impl SubAssign<i64> for VirtAddr {
    fn sub_assign(&mut self, offset: i64) {
        self.0 = (self.0 as i64 - offset) as u64;
    }
}

pub enum StoppointMode {
    Write,
    ReadWrite,
    Execute,
}

pub trait Stoppoint {
    type Id: PartialEq + Copy;

    fn id(&self) -> Self::Id;
    fn is_enabled(&self) -> bool;
    fn enable(&mut self, registers: &mut UserRegisters) -> Result<()>;
    fn disable(&mut self, registers: &mut UserRegisters) -> Result<()>;

    fn clear_hardware_stoppoint(&mut self, registers: &mut UserRegisters, index: usize);
    fn set_hardware_stoppoint(&mut self, registers: &mut UserRegisters, address: VirtAddr, mode: StoppointMode, size: usize) -> i32;

    fn at_address(&self, addr: VirtAddr) -> bool;
    fn in_range(&self, low: VirtAddr, high: VirtAddr) -> bool;
}

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

    pub fn get_by_address_mut(&mut self, addr: VirtAddr) -> Option<&mut T> {
        self.stoppoints.iter_mut().find(|sp| sp.at_address(addr))
    }

    pub fn remove_by_id(&mut self, registers: &mut UserRegisters, id: T::Id) -> Result<()> {
        if let Some(pos) = self.stoppoints.iter().position(|sp| sp.id() == id) {
            self.stoppoints[pos].disable(registers)?;
            self.stoppoints.remove(pos);
        }
        Ok(())
    }

    pub fn remove_by_address(&mut self, registers: &mut UserRegisters, addr: VirtAddr) -> Result<()>{
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
