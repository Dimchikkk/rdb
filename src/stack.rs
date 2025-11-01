use anyhow::Result;

use crate::dwarf::Die;
use crate::types::FileAddr;

pub struct Stack {
    inline_height: u32,
}

impl Stack {
    pub fn new() -> Self {
        Self { inline_height: 0 }
    }

    pub fn inline_height(&self) -> u32 {
        self.inline_height
    }

    pub fn simulate_inlined_step_in(&mut self) {
        if self.inline_height > 0 {
            self.inline_height -= 1;
        }
    }

    pub fn update_inline_height(&mut self, inline_stack: &[Die], pc: FileAddr) -> Result<()> {
        let mut height = 0;
        // Skip the base function (index 0) and only count inline frames
        // The inline stack has: [base_function, inline_frame1, inline_frame2, ...]
        for die in inline_stack.iter().skip(1).rev() {
            if die.low_pc()? == pc {
                height += 1;
            } else {
                break;
            }
        }
        self.inline_height = height;
        Ok(())
    }
}
