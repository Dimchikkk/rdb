use std::ops::{Add, AddAssign, Sub, SubAssign};


#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(u64);

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

pub struct BreakpointSite {
    id: i32,
    address: VirtAddr,
    is_enabled: bool,
    saved_data: u8,
}

impl BreakpointSite {
    // implement enable / disable / at_address / in_range
}
