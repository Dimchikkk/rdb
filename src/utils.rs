use anyhow::{bail, Result};

use crate::process::Process;
use crate::types::VirtAddr;

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

impl<T: Copy> FromBytes for T {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != std::mem::size_of::<T>() {
            return Err(anyhow::anyhow!(
                "Expected {} bytes, got {}",
                std::mem::size_of::<T>(),
                bytes.len()
            ));
        }
        let mut value = std::mem::MaybeUninit::<T>::uninit();
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                value.as_mut_ptr() as *mut u8,
                std::mem::size_of::<T>(),
            );
            Ok(value.assume_init())
        }
    }
}

pub fn print_hex_dump(base: u64, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        print!("{:016x}: ", addr);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }
        print!("|");
        for byte in chunk {
            let c = *byte as char;
            if c.is_ascii_graphic() || c == ' ' {
                print!("{}", c);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

pub fn parse_vector(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();

    if !text.starts_with('[') || !text.ends_with(']') {
        bail!("Invalid format: memory vector must start with '[' and end with ']'");
    }

    let content = &text[1..text.len() - 1]; // strip brackets
    if content.trim().is_empty() {
        return Ok(vec![]);
    }

    let mut result = Vec::new();
    for part in content.split(',') {
        let trimmed = part.trim();
        if !trimmed.starts_with("0x") {
            bail!("Invalid byte format: '{}', must start with '0x'", trimmed);
        }
        let byte = u8::from_str_radix(&trimmed[2..], 16)
            .map_err(|_| anyhow::anyhow!("Invalid byte value: {}", trimmed))?;
        result.push(byte);
    }

    Ok(result)
}

pub fn print_disassembly(process: &Process, address: VirtAddr, n_instructions: usize) {
    let instructions = process.disassemble(n_instructions, Some(address));
    for instr in instructions {
        println!("{:#018x}: {}", instr.address.0, instr.text);
    }
}
