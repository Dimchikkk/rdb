use std::{
    cmp::Ordering,
    ops::{Add, AddAssign, Sub, SubAssign},
};

use crate::elf::Elf;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    pub fn to_file_addr(&self, obj: &Elf) -> FileAddr {
        // Calculate file address offset by subtracting load bias. Even if the
        // section lookup fails (e.g. stripped binaries or linker generated
        // thunks), mapping through the load bias still yields the correct file
        // relative address for DWARF queries.
        FileAddr::from(obj, self.0 - obj.load_bias.0)
    }
}

impl Add<i64> for VirtAddr {
    type Output = Self;

    fn add(self, offset: i64) -> Self {
        VirtAddr((self.0 as i64 + offset) as u64)
    }
}

impl Sub<i64> for VirtAddr {
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

#[derive(Copy, Clone, Debug)]
pub struct FileAddr {
    elf: *const Elf,
    addr: u64,
}

impl FileAddr {
    pub fn from(elf: &Elf, addr: u64) -> Self {
        FileAddr {
            elf: elf as *const Elf,
            addr,
        }
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    /// Returns `None` if elf pointer is null
    pub fn elf_file(&self) -> Option<&Elf> {
        unsafe { self.elf.as_ref() }
    }

    pub fn to_virt_addr(&self) -> VirtAddr {
        let elf = self
            .elf_file()
            .expect("to_virt_addr called on null address");
        if elf.get_section_containing_addr(*self).is_none() {
            return VirtAddr(0);
        }
        VirtAddr(self.addr + elf.load_bias.0)
    }
}

// Arithmetic impls with wrapping for safety
impl Add<i64> for FileAddr {
    type Output = Self;

    fn add(self, offset: i64) -> Self {
        let new_addr = (self.addr as i64).wrapping_add(offset) as u64;
        FileAddr {
            elf: self.elf,
            addr: new_addr,
        }
    }
}

impl Sub<i64> for FileAddr {
    type Output = Self;

    fn sub(self, offset: i64) -> Self {
        self + (-offset)
    }
}

impl AddAssign<i64> for FileAddr {
    fn add_assign(&mut self, offset: i64) {
        self.addr = (self.addr as i64).wrapping_add(offset) as u64;
    }
}

impl SubAssign<i64> for FileAddr {
    fn sub_assign(&mut self, offset: i64) {
        self.addr = (self.addr as i64).wrapping_sub(offset) as u64;
    }
}

// Equality compares pointer *and* address
impl PartialEq for FileAddr {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.elf == other.elf
    }
}
impl Eq for FileAddr {}

// Ordering compares only if elf pointers are same, else panics (like your asserts)
impl PartialOrd for FileAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        assert!(
            self.elf == other.elf,
            "Comparing FileAddr from different ELF files"
        );
        Some(self.addr.cmp(&other.addr))
    }
}
impl Ord for FileAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        assert!(
            self.elf == other.elf,
            "Comparing FileAddr from different ELF files"
        );
        self.addr.cmp(&other.addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOffset {
    elf: *const Elf,
    off: u64,
}

#[allow(dead_code)]
impl FileOffset {
    pub fn new(elf: *const Elf, off: u64) -> Self {
        Self { elf, off }
    }

    pub fn off(&self) -> u64 {
        self.off
    }

    pub fn elf_file(&self) -> *const Elf {
        self.elf
    }

    pub fn is_null(&self) -> bool {
        self.elf.is_null()
    }
}
