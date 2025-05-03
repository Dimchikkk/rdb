use nix::libc::{user_regs_struct, user_fpregs_struct};
use std::mem::{offset_of, zeroed};


use crate::Process;

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
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,

    // Debug Registers
    DR0, DR1, DR2, DR3, DR4, DR5, DR6, DR7,
}

#[repr(C)]
pub struct UserRegisters {
    pub regs: user_regs_struct,
    pub fp_regs: user_fpregs_struct,
    pub debug_regs: [u64; 8],
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
    (RAX) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rax) };
    (RBX) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rbx) };
    (RCX) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rcx) };
    (RDX) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rdx) };
    (RSI) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rsi) };
    (RDI) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rdi) };
    (RBP) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rbp) };
    (RSP) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rsp) };
    (R8)  => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r8) };
    (R9)  => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r9) };
    (R10) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r10) };
    (R11) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r11) };
    (R12) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r12) };
    (R13) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r13) };
    (R14) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r14) };
    (R15) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, r15) };
    (RIP) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, rip) };
    (EFLAGS) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, eflags) };
    (CS) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, cs) };
    (SS) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, ss) };
    (DS) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, ds) };
    (ES) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, es) };
    (FS) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, fs) };
    (GS) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, gs) };
    (ORIG_RAX) => { offset_of!(UserRegisters, regs) + offset_of!(user_regs_struct, orig_rax) };
}

macro_rules! fpr_offset {
    ($reg:ident) => {
        offset_of!(UserRegisters, fp_regs) + offset_of!(user_fpregs_struct, $reg)
    };
}

macro_rules! dr_offset {
    ($n:expr) => {
        offset_of!(UserRegisters, debug_regs) + ($n * 8)
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

macro_rules! define_fpr {
    ($name:ident, $dwarf:expr, $field:ident) => {
        RegisterInfo {
            id: RegisterId::$name,
            name: stringify!($name),
            dwarf_id: $dwarf,
            size: size_of::<nix::libc::c_ushort>(), // Adjust based on actual field type
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

pub fn register_by<F>(f: F) -> &'static RegisterInfo
where
    F: FnMut(&&RegisterInfo) -> bool
{
    REGISTERS.iter()
        .find(f)
        .unwrap_or_else(|| panic!("Can't find register info"))
}

pub fn register_by_id(id: RegisterId) -> &'static RegisterInfo {
    register_by(|reg| reg.id == id)
}

pub fn register_by_name(name: &str) -> &'static RegisterInfo {
    register_by(|reg| reg.name == name)
}

pub fn register_by_dwarf(dwarf_id: i32) -> &'static RegisterInfo {
    register_by(|reg| reg.dwarf_id == dwarf_id)
}

pub struct Registers<'a> {
    data: UserRegisters,
    process: &'a Process,  // Direct reference to process
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


impl<'a> Registers<'a> {
    pub(crate) fn new(process: &'a Process) -> Self {
        Registers {
            data: unsafe { zeroed() }, // Safe initialization through zeroed
            process,
        }
    }

    pub fn read(&self, info: &RegisterInfo) -> RegisterValue {
        unsafe {
            let ptr = (&self.data as *const UserRegisters as *const u8).add(info.offset);
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
                },
                (8, _) => RegisterValue::I64(ptr.cast::<i64>().read()),
                (16, RegisterFormat::Vector) => {
                    let mut bytes = [0u8; 16];
                    ptr.copy_to_nonoverlapping(bytes.as_mut_ptr(), 16);
                    RegisterValue::Bytes128(bytes)
                },
                _ => panic!("Unsupported register format/size"),
            }
        }
    }

    pub fn write(&mut self, info: &RegisterInfo, val: RegisterValue) {
        unsafe {
            let ptr = (&mut self.data as *mut UserRegisters as *mut u8).add(info.offset);
            match (val, info.size, info.format.clone()) {
                (RegisterValue::U8(v), 1, _) => ptr.write(v),
                (RegisterValue::U16(v), 2, _) => ptr.cast::<u16>().write(v),
                (RegisterValue::U32(v), 4, _) => ptr.cast::<u32>().write(v),
                (RegisterValue::U64(v), 8, _) => ptr.cast::<u64>().write(v),
                (RegisterValue::I8(v), 1, _) => ptr.cast::<i8>().write(v),
                (RegisterValue::I16(v), 2, _) => ptr.cast::<i16>().write(v),
                (RegisterValue::I32(v), 4, _) => ptr.cast::<i32>().write(v),
                (RegisterValue::I64(v), 8, _) => ptr.cast::<i64>().write(v),
                (RegisterValue::F32(v), 4, _) => ptr.cast::<f32>().write(v),
                (RegisterValue::F64(v), 8, _) => ptr.cast::<f64>().write(v),
                (RegisterValue::Bytes64(bytes), 8, _) => {
                    ptr.copy_from_nonoverlapping(bytes.as_ptr(), 8)
                },
                (RegisterValue::Bytes128(bytes), 16, _) => {
                    ptr.copy_from_nonoverlapping(bytes.as_ptr(), 16)
                },
                _ => panic!("Type/size mismatch"),
            }
        }

        if info.register_type == RegisterType::Fpr {
            self.process.write_fprs(&self.data.fp_regs);
        } else {
            let aligned_offset = info.offset & !0b111;
            let aligned_value = unsafe {
                let ptr = (&self.data as *const UserRegisters as *const u8).add(aligned_offset);
                ptr.cast::<u64>().read()
            };
            self.process.write_user_area(aligned_offset, aligned_value);
        }
    }

    pub fn read_by_id_as<T: FromRegisterValue>(&self, id: RegisterId) -> T {
        let info = register_by_id(id);
        let val = self.read(info);
        T::from_register_value(val)
            .unwrap_or_else(|| panic!("Invalid type conversion for register {}", info.name))
    }

    pub fn write_by_id(&mut self, id: RegisterId, val: impl IntoRegisterValue) {
        let info = register_by_id(id);
        self.write(info, val.into_register_value());
    }
}

pub trait FromRegisterValue {
    fn from_register_value(val: RegisterValue) -> Option<Self> where Self: Sized;
}

pub trait IntoRegisterValue {
    fn into_register_value(self) -> RegisterValue;
}

// Implement FromRegisterValue for all supported types
impl FromRegisterValue for u8 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::U8(v) => Some(v),
            RegisterValue::I8(v) => Some(v as u8),
            _ => None,
        }
    }
}

impl FromRegisterValue for u16 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::U16(v) => Some(v),
            RegisterValue::I16(v) => Some(v as u16),
            RegisterValue::U8(v) => Some(v as u16),
            RegisterValue::I8(v) => Some(v as u16),
            _ => None,
        }
    }
}

impl FromRegisterValue for u32 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::U32(v) => Some(v),
            RegisterValue::I32(v) => Some(v as u32),
            RegisterValue::U16(v) => Some(v as u32),
            RegisterValue::I16(v) => Some(v as u32),
            RegisterValue::U8(v) => Some(v as u32),
            RegisterValue::I8(v) => Some(v as u32),
            _ => None,
        }
    }
}

impl FromRegisterValue for i8 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::I8(v) => Some(v),
            RegisterValue::U8(v) => Some(v as i8),
            _ => None,
        }
    }
}

impl FromRegisterValue for i16 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::I16(v) => Some(v),
            RegisterValue::U16(v) => Some(v as i16),
            RegisterValue::I8(v) => Some(v as i16),
            RegisterValue::U8(v) => Some(v as i16),
            _ => None,
        }
    }
}

impl FromRegisterValue for i32 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::I32(v) => Some(v),
            RegisterValue::U32(v) => Some(v as i32),
            RegisterValue::I16(v) => Some(v as i32),
            RegisterValue::U16(v) => Some(v as i32),
            RegisterValue::I8(v) => Some(v as i32),
            RegisterValue::U8(v) => Some(v as i32),
            _ => None,
        }
    }
}

impl FromRegisterValue for i64 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::I64(v) => Some(v),
            RegisterValue::U64(v) => Some(v as i64),
            RegisterValue::I32(v) => Some(v as i64),
            RegisterValue::U32(v) => Some(v as i64),
            RegisterValue::I16(v) => Some(v as i64),
            RegisterValue::U16(v) => Some(v as i64),
            RegisterValue::I8(v) => Some(v as i64),
            RegisterValue::U8(v) => Some(v as i64),
            _ => None,
        }
    }
}

impl FromRegisterValue for f32 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::F32(v) => Some(v),
            RegisterValue::U32(v) => Some(f32::from_bits(v)),
            RegisterValue::I32(v) => Some(v as f32),
            _ => None,
        }
    }
}

impl FromRegisterValue for f64 {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::F64(v) => Some(v),
            RegisterValue::U64(v) => Some(f64::from_bits(v)),
            RegisterValue::I64(v) => Some(v as f64),
            _ => None,
        }
    }
}

impl FromRegisterValue for [u8; 8] {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::Bytes64(v) => Some(v),
            _ => None,
        }
    }
}

impl FromRegisterValue for [u8; 16] {
    fn from_register_value(val: RegisterValue) -> Option<Self> {
        match val {
            RegisterValue::Bytes128(v) => Some(v),
            _ => None,
        }
    }
}

// Implement IntoRegisterValue for all supported types
impl IntoRegisterValue for u8 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::U8(self)
    }
}

impl IntoRegisterValue for u16 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::U16(self)
    }
}

impl IntoRegisterValue for u32 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::U32(self)
    }
}

impl IntoRegisterValue for u64 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::U64(self)
    }
}

impl IntoRegisterValue for i8 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::I8(self)
    }
}

impl IntoRegisterValue for i16 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::I16(self)
    }
}

impl IntoRegisterValue for i32 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::I32(self)
    }
}

impl IntoRegisterValue for i64 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::I64(self)
    }
}

impl IntoRegisterValue for f32 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::F32(self)
    }
}

impl IntoRegisterValue for f64 {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::F64(self)
    }
}

impl IntoRegisterValue for [u8; 8] {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::Bytes64(self)
    }
}

impl IntoRegisterValue for [u8; 16] {
    fn into_register_value(self) -> RegisterValue {
        RegisterValue::Bytes128(self)
    }
}
