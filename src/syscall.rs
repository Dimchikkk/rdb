#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatchPolicyMode {
    None,
    Some,
    All,
}

#[derive(Clone, Debug)]
pub struct SyscallCatchPolicy {
    mode: CatchPolicyMode,
    to_catch: Vec<i32>,
}

impl SyscallCatchPolicy {
    pub fn catch_all() -> Self {
        Self {
            mode: CatchPolicyMode::All,
            to_catch: Vec::new(),
        }
    }

    pub fn catch_none() -> Self {
        Self {
            mode: CatchPolicyMode::None,
            to_catch: Vec::new(),
        }
    }

    pub fn catch_some(to_catch: Vec<i32>) -> Self {
        Self {
            mode: CatchPolicyMode::Some,
            to_catch,
        }
    }

    pub fn mode(&self) -> &CatchPolicyMode {
        &self.mode
    }

    pub fn to_catch(&self) -> &Vec<i32> {
        &self.to_catch
    }
}

#[derive(Debug, Clone)]
pub struct SyscallInformation {
    pub id: u16,
    pub entry: bool,
    pub data: SyscallData,
}

#[derive(Debug, Clone)]
pub enum SyscallData {
    Args([u64; 6]),
    Ret(i64),
}
