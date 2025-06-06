use crate::stoppoint::{Stoppoint, VirtAddr};

pub struct BreakpointSite {
    id: i32,
    address: VirtAddr,
    is_enabled: bool,
    saved_data: u8,
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

    fn enable(&mut self) {
        self.enable();
    }

    fn disable(&mut self) {
        self.disable();
    }
}

impl BreakpointSite {
    pub fn enable(&mut self) {
        self.is_enabled = true;
        // TODO: implement enable
    }

    pub fn disable(&mut self) {
        self.is_enabled = false;
        // TODO: implement disable
    }
}
