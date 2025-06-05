use std::fmt::Write;
use std::str::FromStr;

use crate::registers::{RegisterFormat, RegisterInfo, RegisterValue};

pub fn format_register_value(value: &RegisterValue) -> String {
    match value {
        RegisterValue::F32(f) => format!("{}", f),
        RegisterValue::F64(f) => format!("{}", f),

        // Special case: decode st0 as float
        RegisterValue::Bytes128(bytes) if bytes.len() >= 10 => {
            // For ST0...ST7 registers, decode 80-bit float:
            // You can do a heuristic or pass info that this is st0 here,
            // but assuming only for demonstration that this is st0:
            let f = decode_f80_to_f64(&bytes[0..10]);
            format!("{}", f)
        }

        RegisterValue::U8(v) => format!("0x{:02x}", v),
        RegisterValue::U16(v) => format!("0x{:04x}", v),
        RegisterValue::U32(v) => format!("0x{:08x}", v),
        RegisterValue::U64(v) => format!("0x{:016x}", v),
        RegisterValue::I8(v) => format!("0x{:02x}", v),
        RegisterValue::I16(v) => format!("0x{:04x}", v),
        RegisterValue::I32(v) => format!("0x{:08x}", v),
        RegisterValue::I64(v) => format!("0x{:016x}", v),

        RegisterValue::Bytes64(bytes) => {
            let mut s = String::from("[");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                write!(s, "0x{:02x}", b).unwrap();
            }
            s.push(']');
            s
        }
        RegisterValue::Bytes128(bytes) => {
            let mut s = String::from("[");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                write!(s, "0x{:02x}", b).unwrap();
            }
            s.push(']');
            s
        }
    }
}

fn decode_f80_to_f64(bytes: &[u8]) -> f64 {
    // bytes length must be >= 10
    assert!(bytes.len() >= 10);

    // Extract sign bit
    let sign = (bytes[9] & 0x80) != 0;

    // Extract exponent (15 bits)
    let exponent = (((bytes[9] & 0x7F) as u16) << 8) | bytes[8] as u16;

    // Extract mantissa (64 bits) - integer bit explicit
    let mantissa_bytes = &bytes[0..8];
    let mantissa = u64::from_le_bytes(mantissa_bytes.try_into().unwrap());

    if exponent == 0 && mantissa == 0 {
        // zero
        return 0.0;
    }

    if exponent == 0x7FFF {
        // Inf or NaN
        return if mantissa == 0 {
            if sign { f64::NEG_INFINITY } else { f64::INFINITY }
        } else {
            f64::NAN
        };
    }

    // Bias for extended precision is 16383
    let exp = exponent as i32 - 16383;

    // The mantissa includes the explicit integer bit at bit 63, so
    // fraction = mantissa / 2^63 (because bit 63 is integer bit)
    // so actual value = (-1)^sign * 2^exp * (mantissa / 2^63)

    let fraction = mantissa as f64 / (1u64 << 63) as f64;

    let value = fraction * 2f64.powi(exp);

    if sign { -value } else { value }
}

pub fn f64_to_x87_long_double_bytes(value: f64) -> [u8; 16] {
    let bits = value.to_bits();
    let sign = (bits >> 63) & 1;
    let exp = ((bits >> 52) & 0x7FF) as i32; // 11-bit exponent
    let frac = bits & 0xFFFFFFFFFFFFF; // 52-bit fraction

    let mut bytes = [0u8; 16];

    if exp == 0 && frac == 0 {
        // Zero
        // all bytes zero except sign bit in highest bit of exponent field
        // Exponent is 0
        // Integer bit = 0
        // Leave bytes zero (already zero)
        // but set sign bit in exponent high byte
        if sign != 0 {
            bytes[9] = 0x80; // sign bit at bit 15 of exponent (2nd last byte)
        }
        return bytes;
    }

    if exp == 0x7FF {
        // Inf or NaN - can be handled specially if needed
        return bytes;
    }

    // Calculate extended exponent = double exponent - 1023 + 16383
    let ext_exp = (exp - 1023 + 16383) as u16;

    // Construct 64-bit fraction with explicit integer bit (bit 63 = 1)
    let ext_frac = (1u64 << 63) | (frac << (63 - 52)); // shift mantissa to top bits

    // Pack into bytes (little endian):
    // Bytes 0..7 = ext_frac (64 bits)
    // Bytes 8..9 = ext_exp + sign in top bit of exponent (15 bits exponent + sign bit)
    // Bytes 10..15 = padding zero

    // Write fraction (64 bits)
    bytes[0..8].copy_from_slice(&ext_frac.to_le_bytes());

    // Write exponent (15 bits) and sign bit
    let exp_and_sign = (ext_exp & 0x7FFF) | ((sign as u16) << 15);
    bytes[8..10].copy_from_slice(&exp_and_sign.to_le_bytes());

    // bytes[10..16] = 0 (already zero)

    bytes
}

pub fn parse_register_value(
    info: &RegisterInfo,
    text: &str,
) -> Result<RegisterValue, String> {
    // Helper to strip optional “0x” / “0X”
    fn strip_0x(s: &str) -> &str {
        if s.starts_with("0x") || s.starts_with("0X") {
            &s[2..]
        } else {
            s
        }
    }

    match info.format {
        RegisterFormat::Uint => {
            let raw = if text.starts_with("0x") || text.starts_with("0X") {
                u64::from_str_radix(strip_0x(text), 16)
                    .map_err(|e| format!("Invalid hex for {}: {}", info.name, e))?
            } else {
                u64::from_str(text)
                    .map_err(|e| format!("Invalid decimal for {}: {}", info.name, e))?
            };

            let result = match info.size {
                1 => RegisterValue::U8(raw as u8),
                2 => RegisterValue::U16(raw as u16),
                4 => RegisterValue::U32(raw as u32),
                8 => RegisterValue::U64(raw),
                other => {
                    return Err(format!(
                        "{}: Unsupported Uint size {}",
                        info.name, other
                    ))
                }
            };
            Ok(result)
        }

        RegisterFormat::Float => {
            if info.size != 4 {
                return Err(format!(
                    "{}: Float register has unexpected size {}",
                    info.name, info.size
                ));
            }
            let f: f32 = text
                .parse()
                .map_err(|e| format!("Invalid f32 for {}: {}", info.name, e))?;
            Ok(RegisterValue::F32(f))
        }

        RegisterFormat::Double => {
            if info.size != 8 {
                return Err(format!(
                    "{}: Double register has unexpected size {}",
                    info.name, info.size
                ));
            }
            let f: f64 = text
                .parse()
                .map_err(|e| format!("Invalid f64 for {}: {}", info.name, e))?;
            Ok(RegisterValue::F64(f))
        }

        RegisterFormat::LongDouble => {
            if info.size != 16 {
                return Err(format!(
                    "{}: LongDouble register has unexpected size {}",
                    info.name, info.size
                ));
            }
            // Try parsing a single float first
            if let Ok(f) = text.parse::<f64>() {
                let bytes = f64_to_x87_long_double_bytes(f);
                return Ok(RegisterValue::Bytes128(bytes));
            }

            // Else parse as 16 comma-separated bytes (old behavior)
            let parts: Vec<&str> = text.split(',').map(str::trim).collect();
            if parts.len() != 16 {
                return Err(format!(
                    "{}: Expected 16 comma-separated bytes for LongDouble, found {}",
                    info.name,
                    parts.len()
                ));
            }
            let mut bytes = [0_u8; 16];
            for (i, piece) in parts.iter().enumerate() {
                let raw = u8::from_str_radix(strip_0x(piece), 16)
                    .map_err(|e| format!("Invalid byte {} for {}: {}", piece, info.name, e))?;
                bytes[i] = raw;
            }
            Ok(RegisterValue::Bytes128(bytes))
        }

        RegisterFormat::Vector => {
            let expected_len = info.size;
            if expected_len != 8 && expected_len != 16 {
                return Err(format!(
                    "{}: Vector register has unsupported size {}",
                    info.name, info.size
                ));
            }
            let parts: Vec<&str> = text.split(',').map(str::trim).collect();
            if parts.len() != expected_len {
                return Err(format!(
                    "{}: Expected {} comma‐separated bytes, found {}",
                    info.name,
                    expected_len,
                    parts.len()
                ));
            }
            if expected_len == 8 {
                let mut arr = [0_u8; 8];
                for (i, piece) in parts.iter().enumerate() {
                    let raw = u8::from_str_radix(strip_0x(piece), 16)
                        .map_err(|e| format!("Invalid byte {} for {}: {}", piece, info.name, e))?;
                    arr[i] = raw;
                }
                Ok(RegisterValue::Bytes64(arr))
            } else {
                let mut arr = [0_u8; 16];
                for (i, piece) in parts.iter().enumerate() {
                    let raw = u8::from_str_radix(strip_0x(piece), 16)
                        .map_err(|e| format!("Invalid byte {} for {}: {}", piece, info.name, e))?;
                    arr[i] = raw;
                }
                Ok(RegisterValue::Bytes128(arr))
            }
        }
    }
}
