use std::mem::{offset_of, zeroed};
use anyhow::{bail, Result};
use nix::sys::ptrace::{setregs, write_user };
use nix::unistd::Pid;
use nix::libc::{self, user, user_fpregs_struct, user_regs_struct, PTRACE_SETFPREGS};
use libc::{ptrace, c_void};
use std::ptr;
use std::io::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterType {
    Gpr,
    SubGpr,
    Fpr,
    Dr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterFormat {
    Uint,
    Float,
    Double,
    LongDouble,
    Vector,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegisterId {
    // General Purpose Registers
    RAX, RDX, RCX, RBX, RSI, RDI, RBP, RSP,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP, EFLAGS, CS, FS, GS, SS, DS, ES, ORIG_RAX,

    // Sub-registers
    EAX, EDX, ECX, EBX, ESI, EDI, EBP, ESP,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
    AX, DX, CX, BX, SI, DI, BP, SP,
    R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
    AH, DH, CH, BH,
    AL, DL, CL, BL, SIL, DIL, BPL, SPL,
    R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,

    // Floating Point
    FCW, FSW, FTW, FOP, FRIP, FRDP, MXCSR, MXCSRMASK,
    ST0, ST1, ST2, ST3, ST4, ST5, ST6, ST7,
    MM0, MM1, MM2, MM3, MM4, MM5, MM6, MM7,
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,

    // Debug Registers
    DR0, DR1, DR2, DR3, DR4, DR5, DR6, DR7,
}

pub const DEBUG_REG_IDS: [RegisterId; 8] = [
    RegisterId::DR0,
    RegisterId::DR1,
    RegisterId::DR2,
    RegisterId::DR3,
    RegisterId::DR4,
    RegisterId::DR5,
    RegisterId::DR6,
    RegisterId::DR7,
];

#[derive(Debug, Clone)]
pub struct UserRegisters {
    pub data: user,
}

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub id: RegisterId,
    pub name: &'static str,
    pub dwarf_id: i32,
    pub size: usize,
    pub offset: usize,
    pub register_type: RegisterType,
    pub format: RegisterFormat,
}

macro_rules! define_registers {
    ($($reg:expr),* $(,)?) => {
        &[$($reg),*]
    };
}

macro_rules! gpr_offset {
    (RAX) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rax) };
    (RBX) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rbx) };
    (RCX) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rcx) };
    (RDX) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rdx) };
    (RSI) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rsi) };
    (RDI) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rdi) };
    (RBP) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rbp) };
    (RSP) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rsp) };
    (R8)  => { offset_of!(user, regs) + offset_of!(user_regs_struct, r8) };
    (R9)  => { offset_of!(user, regs) + offset_of!(user_regs_struct, r9) };
    (R10) => { offset_of!(user, regs) + offset_of!(user_regs_struct, r10) };
    (R11) => { offset_of!(user, regs) + offset_of!(user_regs_struct, r11) };
    (R12) => { offset_of!(user, regs) + offset_of!(user_regs_struct, r12) };
    (R13) => { offset_of!(user, regs) + offset_of!(user_regs_struct, r13) };
    (R14) => { offset_of!(user, regs) + offset_of!(user_regs_struct, r14) };
    (R15) => { offset_of!(user, regs) + offset_of!(user_regs_struct, r15) };
    (RIP) => { offset_of!(user, regs) + offset_of!(user_regs_struct, rip) };
    (EFLAGS) => { offset_of!(user, regs) + offset_of!(user_regs_struct, eflags) };
    (CS) => { offset_of!(user, regs) + offset_of!(user_regs_struct, cs) };
    (SS) => { offset_of!(user, regs) + offset_of!(user_regs_struct, ss) };
    (DS) => { offset_of!(user, regs) + offset_of!(user_regs_struct, ds) };
    (ES) => { offset_of!(user, regs) + offset_of!(user_regs_struct, es) };
    (FS) => { offset_of!(user, regs) + offset_of!(user_regs_struct, fs) };
    (GS) => { offset_of!(user, regs) + offset_of!(user_regs_struct, gs) };
    (ORIG_RAX) => { offset_of!(user, regs) + offset_of!(user_regs_struct, orig_rax) };
}

macro_rules! dr_offset {
    ($n:expr) => {
        offset_of!(user, u_debugreg) + ($n * 8)
    };
}

macro_rules! define_register {
    ($name:ident, $dwarf:expr, $size:expr, $offset:expr, $type:ident, $format:ident) => {
        RegisterInfo {
            id: RegisterId::$name,
            name: stringify!($name),
            dwarf_id: $dwarf,
            size: $size,
            offset: $offset,
            register_type: RegisterType::$type,
            format: RegisterFormat::$format,
        }
    };
}

macro_rules! define_gpr_64 {
    ($name:ident, $dwarf:expr) => {
        define_register!($name, $dwarf, 8, gpr_offset!($name), Gpr, Uint)
    };
}

macro_rules! define_gpr_32 {
    ($name:ident, $super:ident) => {
        define_register!($name, -1, 4, gpr_offset!($super), SubGpr, Uint)
    };
}

macro_rules! define_gpr_16 {
    ($name:ident, $super:ident) => {
        define_register!($name, -1, 2, gpr_offset!($super), SubGpr, Uint)
    };
}

macro_rules! define_gpr_8h {
    ($name:ident, $super:ident) => {
        define_register!($name, -1, 1, gpr_offset!($super) + 1, SubGpr, Uint)
    };
}

macro_rules! define_gpr_8l {
    ($name:ident, $super:ident) => {
        define_register!($name, -1, 1, gpr_offset!($super), SubGpr, Uint)
    };
}

macro_rules! fpr_offset {
    (cwd)       => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, cwd) };
    (swd)       => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, swd) };
    (ftw)       => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, ftw) };
    (fop)       => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, fop) };
    (rip)       => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, rip) };
    (rdp)       => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, rdp) };
    (mxcsr)     => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, mxcsr) };
    (mxcr_mask) => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, mxcr_mask) };
    (st_space)  => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, st_space) };
    (xmm_space) => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, xmm_space) };
    (padding)   => { offset_of!(user, i387) + offset_of!(user_fpregs_struct, padding) };
}

macro_rules! fpr_size {
    (cwd)       => { core::mem::size_of::<u16>() };
    (swd)       => { core::mem::size_of::<u16>() };
    (ftw)       => { core::mem::size_of::<u16>() };
    (fop)       => { core::mem::size_of::<u16>() };
    (rip)       => { core::mem::size_of::<u64>() };
    (rdp)       => { core::mem::size_of::<u64>() };
    (mxcsr)     => { core::mem::size_of::<u32>() };
    (mxcr_mask) => { core::mem::size_of::<u32>() };
    (st_space)  => { core::mem::size_of::<[u32; 32]>() };
    (xmm_space) => { core::mem::size_of::<[u32; 64]>() };
    (padding)   => { core::mem::size_of::<[u32; 24]>() };
}

macro_rules! define_fpr {
    ($name:ident, $dwarf:expr, $field:ident) => {
        RegisterInfo {
            id: RegisterId::$name,
            name: stringify!($name),
            dwarf_id: $dwarf,
            size: fpr_size!($field),
            offset: fpr_offset!($field),
            register_type: RegisterType::Fpr,
            format: RegisterFormat::Uint,
        }
    };
}

macro_rules! define_fp_st {
    ($n:expr) => {
        RegisterInfo {
            id: match $n {
                0 => RegisterId::ST0,
                1 => RegisterId::ST1,
                2 => RegisterId::ST2,
                3 => RegisterId::ST3,
                4 => RegisterId::ST4,
                5 => RegisterId::ST5,
                6 => RegisterId::ST6,
                7 => RegisterId::ST7,
                _ => panic!("Invalid FP stack register number"),
            },
            name: match $n {
                0 => "st0",
                1 => "st1",
                2 => "st2",
                3 => "st3",
                4 => "st4",
                5 => "st5",
                6 => "st6",
                7 => "st7",
                _ => panic!("Invalid FP stack register number"),
            },
            dwarf_id: 33 + $n,
            size: 16,
            offset: fpr_offset!(st_space) + ($n * 16),
            register_type: RegisterType::Fpr,
            format: RegisterFormat::LongDouble,
        }
    };
}

macro_rules! define_fp_mm {
    ($n:expr) => {
        RegisterInfo {
            id: match $n {
                0 => RegisterId::MM0,
                1 => RegisterId::MM1,
                2 => RegisterId::MM2,
                3 => RegisterId::MM3,
                4 => RegisterId::MM4,
                5 => RegisterId::MM5,
                6 => RegisterId::MM6,
                7 => RegisterId::MM7,
                _ => panic!("Invalid MM register number"),
            },
            name: match $n {
                0 => "mm0",
                1 => "mm1",
                2 => "mm2",
                3 => "mm3",
                4 => "mm4",
                5 => "mm5",
                6 => "mm6",
                7 => "mm7",
                _ => panic!("Invalid MM register number"),
            },
            dwarf_id: 41 + $n,
            size: 8,
            offset: fpr_offset!(st_space) + ($n * 16),
            register_type: RegisterType::Fpr,
            format: RegisterFormat::Vector,
        }
    };
}

macro_rules! define_fp_xmm {
    ($n:expr) => {
        RegisterInfo {
            id: match $n {
                0 => RegisterId::XMM0,
                1 => RegisterId::XMM1,
                2 => RegisterId::XMM2,
                3 => RegisterId::XMM3,
                4 => RegisterId::XMM4,
                5 => RegisterId::XMM5,
                6 => RegisterId::XMM6,
                7 => RegisterId::XMM7,
                8 => RegisterId::XMM8,
                9 => RegisterId::XMM9,
                10 => RegisterId::XMM10,
                11 => RegisterId::XMM11,
                12 => RegisterId::XMM12,
                13 => RegisterId::XMM13,
                14 => RegisterId::XMM14,
                15 => RegisterId::XMM15,
                _ => panic!("Invalid XMM register number"),
            },
            name: match $n {
                0 => "xmm0",
                1 => "xmm1",
                2 => "xmm2",
                3 => "xmm3",
                4 => "xmm4",
                5 => "xmm5",
                6 => "xmm6",
                7 => "xmm7",
                8 => "xmm8",
                9 => "xmm9",
                10 => "xmm10",
                11 => "xmm11",
                12 => "xmm12",
                13 => "xmm13",
                14 => "xmm14",
                15 => "xmm15",
                _ => panic!("Invalid XMM register number"),
            },
            dwarf_id: 17 + $n,
            size: 16,
            offset: fpr_offset!(xmm_space) + ($n * 16),
            register_type: RegisterType::Fpr,
            format: RegisterFormat::Vector,
        }
    };
}

macro_rules! define_dr {
    ($n:expr) => {
        RegisterInfo {
            id: match $n {
                0 => RegisterId::DR0,
                1 => RegisterId::DR1,
                2 => RegisterId::DR2,
                3 => RegisterId::DR3,
                4 => RegisterId::DR4,
                5 => RegisterId::DR5,
                6 => RegisterId::DR6,
                7 => RegisterId::DR7,
                _ => panic!("Invalid debug register number"),
            },
            name: match $n {
                0 => "dr0",
                1 => "dr1",
                2 => "dr2",
                3 => "dr3",
                4 => "dr4",
                5 => "dr5",
                6 => "dr6",
                7 => "dr7",
                _ => panic!("Invalid debug register number"),
            },
            dwarf_id: -1,
            size: 8,
            offset: dr_offset!($n),
            register_type: RegisterType::Dr,
            format: RegisterFormat::Uint,
        }
    };
}

pub const REGISTERS: &[RegisterInfo] = define_registers![
    // General Purpose Registers (64-bit)
    define_gpr_64!(RAX, 0),
    define_gpr_64!(RDX, 1),
    define_gpr_64!(RCX, 2),
    define_gpr_64!(RBX, 3),
    define_gpr_64!(RSI, 4),
    define_gpr_64!(RDI, 5),
    define_gpr_64!(RBP, 6),
    define_gpr_64!(RSP, 7),
    define_gpr_64!(R8, 8),
    define_gpr_64!(R9, 9),
    define_gpr_64!(R10, 10),
    define_gpr_64!(R11, 11),
    define_gpr_64!(R12, 12),
    define_gpr_64!(R13, 13),
    define_gpr_64!(R14, 14),
    define_gpr_64!(R15, 15),
    define_gpr_64!(RIP, 16),
    define_gpr_64!(EFLAGS, 49),
    define_gpr_64!(CS, 51),
    define_gpr_64!(FS, 54),
    define_gpr_64!(GS, 55),
    define_gpr_64!(SS, 52),
    define_gpr_64!(DS, 53),
    define_gpr_64!(ES, 50),
    define_gpr_64!(ORIG_RAX, -1),

    // 32-bit subregisters
    define_gpr_32!(EAX, RAX),
    define_gpr_32!(EDX, RDX),
    define_gpr_32!(ECX, RCX),
    define_gpr_32!(EBX, RBX),
    define_gpr_32!(ESI, RSI),
    define_gpr_32!(EDI, RDI),
    define_gpr_32!(EBP, RBP),
    define_gpr_32!(ESP, RSP),
    define_gpr_32!(R8D, R8),
    define_gpr_32!(R9D, R9),
    define_gpr_32!(R10D, R10),
    define_gpr_32!(R11D, R11),
    define_gpr_32!(R12D, R12),
    define_gpr_32!(R13D, R13),
    define_gpr_32!(R14D, R14),
    define_gpr_32!(R15D, R15),

    // 16-bit subregisters
    define_gpr_16!(AX, RAX),
    define_gpr_16!(DX, RDX),
    define_gpr_16!(CX, RCX),
    define_gpr_16!(BX, RBX),
    define_gpr_16!(SI, RSI),
    define_gpr_16!(DI, RDI),
    define_gpr_16!(BP, RBP),
    define_gpr_16!(SP, RSP),
    define_gpr_16!(R8W, R8),
    define_gpr_16!(R9W, R9),
    define_gpr_16!(R10W, R10),
    define_gpr_16!(R11W, R11),
    define_gpr_16!(R12W, R12),
    define_gpr_16!(R13W, R13),
    define_gpr_16!(R14W, R14),
    define_gpr_16!(R15W, R15),

    // 8-bit subregisters
    define_gpr_8h!(AH, RAX),
    define_gpr_8h!(DH, RDX),
    define_gpr_8h!(CH, RCX),
    define_gpr_8h!(BH, RBX),

    define_gpr_8l!(AL, RAX),
    define_gpr_8l!(DL, RDX),
    define_gpr_8l!(CL, RCX),
    define_gpr_8l!(BL, RBX),
    define_gpr_8l!(SIL, RSI),
    define_gpr_8l!(DIL, RDI),
    define_gpr_8l!(BPL, RBP),
    define_gpr_8l!(SPL, RSP),
    define_gpr_8l!(R8B, R8),
    define_gpr_8l!(R9B, R9),
    define_gpr_8l!(R10B, R10),
    define_gpr_8l!(R11B, R11),
    define_gpr_8l!(R12B, R12),
    define_gpr_8l!(R13B, R13),
    define_gpr_8l!(R14B, R14),
    define_gpr_8l!(R15B, R15),

    // Floating Point Control Registers
    define_fpr!(FCW, 65, cwd),
    define_fpr!(FSW, 66, swd),
    define_fpr!(FTW, -1, ftw),
    define_fpr!(FOP, -1, fop),
    define_fpr!(FRIP, -1, rip),
    define_fpr!(FRDP, -1, rdp),
    define_fpr!(MXCSR, 64, mxcsr),
    define_fpr!(MXCSRMASK, -1, mxcr_mask),

    // FP Stack Registers
    define_fp_st!(0),
    define_fp_st!(1),
    define_fp_st!(2),
    define_fp_st!(3),
    define_fp_st!(4),
    define_fp_st!(5),
    define_fp_st!(6),
    define_fp_st!(7),

    // MM Registers
    define_fp_mm!(0),
    define_fp_mm!(1),
    define_fp_mm!(2),
    define_fp_mm!(3),
    define_fp_mm!(4),
    define_fp_mm!(5),
    define_fp_mm!(6),
    define_fp_mm!(7),

    // XMM Registers
    define_fp_xmm!(0),
    define_fp_xmm!(1),
    define_fp_xmm!(2),
    define_fp_xmm!(3),
    define_fp_xmm!(4),
    define_fp_xmm!(5),
    define_fp_xmm!(6),
    define_fp_xmm!(7),
    define_fp_xmm!(8),
    define_fp_xmm!(9),
    define_fp_xmm!(10),
    define_fp_xmm!(11),
    define_fp_xmm!(12),
    define_fp_xmm!(13),
    define_fp_xmm!(14),
    define_fp_xmm!(15),

    // Debug Registers
    define_dr!(0),
    define_dr!(1),
    define_dr!(2),
    define_dr!(3),
    define_dr!(4),
    define_dr!(5),
    define_dr!(6),
    define_dr!(7),
];

pub fn register_info_by<F>(f: F) -> &'static RegisterInfo
where
    F: FnMut(&&RegisterInfo) -> bool
{
    REGISTERS.iter()
        .find(f)
        .unwrap_or_else(|| panic!("Can't find register info"))
}

pub fn register_info_by_id(id: RegisterId) -> &'static RegisterInfo {
    register_info_by(|reg| reg.id == id)
}

pub fn register_info_by_name(name: &str) -> &'static RegisterInfo {
    register_info_by(|reg| reg.name.to_lowercase() == name.to_lowercase())
}

pub fn register_info_by_dwarf(dwarf_id: i32) -> &'static RegisterInfo {
    register_info_by(|reg| reg.dwarf_id == dwarf_id)
}

#[derive(Debug)]
pub enum RegisterValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bytes64([u8; 8]),
    Bytes128([u8; 16]),
}

impl RegisterValue {
    fn byte_size(&self) -> usize {
        match self {
            RegisterValue::U8(_) | RegisterValue::I8(_) => 1,
            RegisterValue::U16(_) | RegisterValue::I16(_) => 2,
            RegisterValue::U32(_) | RegisterValue::I32(_) | RegisterValue::F32(_) => 4,
            RegisterValue::U64(_) | RegisterValue::I64(_) | RegisterValue::F64(_)
            | RegisterValue::Bytes64(_) => 8,
            RegisterValue::Bytes128(_) => 16,
        }
    }
}

impl UserRegisters {
    pub fn new() -> Self {
        unsafe {
            UserRegisters {
                data: zeroed(),
            }
        }
    }

    pub fn read(&self, info: &RegisterInfo) -> RegisterValue {
        let base_ptr = &self.data as *const _ as *const u8;

        unsafe {
            let ptr = base_ptr.add(info.offset);
            match (info.size, info.format.clone()) {
                (1, RegisterFormat::Uint) => RegisterValue::U8(ptr.read()),
                (2, RegisterFormat::Uint) => RegisterValue::U16(ptr.cast::<u16>().read()),
                (4, RegisterFormat::Uint) => RegisterValue::U32(ptr.cast::<u32>().read()),
                (8, RegisterFormat::Uint) => RegisterValue::U64(ptr.cast::<u64>().read()),
                (1, _) => RegisterValue::I8(ptr.cast::<i8>().read()),
                (2, _) => RegisterValue::I16(ptr.cast::<i16>().read()),
                (4, RegisterFormat::Float) => RegisterValue::F32(ptr.cast::<f32>().read()),
                (4, _) => RegisterValue::I32(ptr.cast::<i32>().read()),
                (8, RegisterFormat::Double) => RegisterValue::F64(ptr.cast::<f64>().read()),
                (8, RegisterFormat::Vector) => {
                    let mut bytes = [0u8; 8];
                    ptr.copy_to_nonoverlapping(bytes.as_mut_ptr(), 8);
                    RegisterValue::Bytes64(bytes)
                }
                (8, _) => RegisterValue::I64(ptr.cast::<i64>().read()),
                (16, RegisterFormat::LongDouble) => {
                    // read 16 bytes for an 80-bit "long double" slot
                    let mut bytes = [0u8; 16];
                    ptr.copy_to_nonoverlapping(bytes.as_mut_ptr(), 16);
                    RegisterValue::Bytes128(bytes)
                }
                (16, RegisterFormat::Vector) => {
                    let mut bytes = [0u8; 16];
                    ptr.copy_to_nonoverlapping(bytes.as_mut_ptr(), 16);
                    RegisterValue::Bytes128(bytes)
                }
                (size, format) => panic!("Unsupported register (size, format): ({} , {:?})", size, format),
            }
        }
    }

    pub fn write_raw(&mut self, info: &RegisterInfo, val: RegisterValue) {
        let base_ptr: *mut u8 = &mut self.data as *mut _ as *mut u8;

        unsafe {
            let ptr = base_ptr.add(info.offset);

            match (val, info.size) {
                (RegisterValue::U8(v), 1) => ptr.write(v),
                (RegisterValue::I8(v), 1) => ptr.cast::<i8>().write(v),
                (RegisterValue::U16(v), 2) => ptr.cast::<u16>().write(v),
                (RegisterValue::I16(v), 2) => ptr.cast::<i16>().write(v),
                (RegisterValue::U32(v), 4) => ptr.cast::<u32>().write(v),
                (RegisterValue::I32(v), 4) => ptr.cast::<i32>().write(v),
                (RegisterValue::F32(v), 4) => ptr.cast::<f32>().write(v),
                (RegisterValue::U64(v), 8) => ptr.cast::<u64>().write(v),
                (RegisterValue::I64(v), 8) => ptr.cast::<i64>().write(v),
                (RegisterValue::F64(v), 8) => ptr.cast::<f64>().write(v),
                (RegisterValue::Bytes64(bytes), 8) => {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, 8);
                }

                (RegisterValue::Bytes128(bytes), 16) => {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, 16);
                }

                (val, size) => panic!(
                    "Type/size mismatch in write_raw: value = {:?} ({} bytes), info.size = {}",
                    val,
                    val.byte_size(),
                    size
                ),
            }
        }
    }
}


pub fn write_user_area(pid: Pid, offset: usize, data: u64) -> Result<()> {
    if write_user(pid, offset as _, data as i64).is_err() {
        bail!("Could not write to user area");
    }
    Ok(())
}

pub fn write_fprs(pid: Pid, fprs: &user_fpregs_struct) -> Result<()> {
    unsafe {
        let ret = ptrace(
            PTRACE_SETFPREGS,
            pid.as_raw(),
            ptr::null_mut::<c_void>(),
            fprs as *const _ as *mut c_void,
        );
        if ret != 0 {
            let err = Error::last_os_error();
            bail!("Could not write floating point registers: {}", err);
        }
    }
    Ok(())
}

pub fn write_gprs(pid: Pid, gprs: &user_regs_struct) -> Result<()> {
    if setregs(pid, *gprs).is_err() {
        bail!("Could not write general purpose registers");
    }
    Ok(())
}


pub fn write_register(pid: Pid, registers: &mut UserRegisters, info: &RegisterInfo, val: RegisterValue) {
    registers.write_raw(info, val);

    if info.register_type == RegisterType::Fpr {
        write_fprs(pid, &registers.data.i387)
            .unwrap_or_else(|e| panic!("Failed to write FPR registers: {}", e));
    } else {
        // align offset down to 8 bytes and write that word
        let aligned_offset = info.offset & !0b111;
        let aligned_value = unsafe {
            let aligned_ptr = (&registers.data.regs as *const _ as *const u8)
                .add(aligned_offset);
            aligned_ptr.cast::<u64>().read()
        };
        write_user_area(pid, aligned_offset, aligned_value)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to write GPR/debug at offset {}: {}",
                    aligned_offset, e
                )
            });
    }
}
