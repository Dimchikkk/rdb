use std::fmt::Write;
use std::str::FromStr;

use crate::registers::{RegisterFormat, RegisterInfo, RegisterValue};

pub fn format_register_value(reg_name: &str, value: &RegisterValue) -> String {
    match (reg_name, value) {
        // Format st0..st7 as 80-bit float (only first 10 bytes)
        (name, RegisterValue::Bytes128(bytes)) if name.starts_with("st") && bytes.len() >= 10 => {
            let f = decode_f80_to_f64(&bytes[0..10]);
            format!("{}", f)
        }

        // Format mm0..mm7 as 8 bytes hex array (Bytes64)
        (name, RegisterValue::Bytes64(bytes)) if name.starts_with("mm") && bytes.len() == 8 => {
            let mut s = String::from("[");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                write!(s, "0x{:02x}", b).unwrap();
            }
            s.push(']');
            s
        }

        // Format xmm registers as 16 bytes hex array (Bytes128)
        (name, RegisterValue::Bytes128(bytes)) if name.starts_with("xmm") && bytes.len() == 16 => {
            let mut s = String::from("[");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                write!(s, "0x{:02x}", b).unwrap();
            }
            s.push(']');
            s
        }

        // Other float types
        (_, RegisterValue::F32(f)) => format!("{}", f),
        (_, RegisterValue::F64(f)) => format!("{}", f),

        // Other integers
        (_, RegisterValue::U8(v)) => format!("0x{:02x}", v),
        (_, RegisterValue::U16(v)) => format!("0x{:04x}", v),
        (_, RegisterValue::U32(v)) => format!("0x{:08x}", v),
        (_, RegisterValue::U64(v)) => format!("0x{:016x}", v),
        (_, RegisterValue::I8(v)) => format!("0x{:02x}", v),
        (_, RegisterValue::I16(v)) => format!("0x{:04x}", v),
        (_, RegisterValue::I32(v)) => format!("0x{:08x}", v),
        (_, RegisterValue::I64(v)) => format!("0x{:016x}", v),

        // Fallback for Bytes64 (non-mm)
        (_, RegisterValue::Bytes64(bytes)) => {
            let mut s = String::from("[");
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 { s.push_str(", "); }
                write!(s, "0x{:02x}", b).unwrap();
            }
            s.push(']');
            s
        }

        // Fallback for Bytes128 (non-st/xmm)
        (_, RegisterValue::Bytes128(bytes)) => {
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
        // Zero: exponent = 0, integer bit = 0, fraction = 0
        // Sign bit stored in bit 15 of exponent (byte 9, bit 7)
        if sign != 0 {
            bytes[9] = 0x80;
        }
        return bytes;
    }

    if exp == 0x7FF {
        // Inf or NaN - here we just return zeros for now (can improve later)
        return bytes;
    }

    // Convert double exponent to extended precision exponent with bias difference
    let ext_exp = (exp - 1023 + 16383) as u16;

    // Construct extended fraction with explicit integer bit (bit 63 = 1)
    let ext_frac = (1u64 << 63) | (frac << (63 - 52)); 

    // Write fraction (64 bits, little endian)
    bytes[0..8].copy_from_slice(&ext_frac.to_le_bytes());

    // Write exponent (15 bits) and sign bit (bit 15)
    let exp_and_sign = (ext_exp & 0x7FFF) | ((sign as u16) << 15);
    bytes[8..10].copy_from_slice(&exp_and_sign.to_le_bytes());

    // Remaining bytes [10..16] stay zero (padding)
    bytes
}

pub fn parse_register_value(
    info: &RegisterInfo,
    text: &str,
) -> Result<RegisterValue, String> {
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
            // Try parsing as f64 first
            if let Ok(f) = text.parse::<f64>() {
                let bytes = f64_to_x87_long_double_bytes(f);
                return Ok(RegisterValue::Bytes128(bytes));
            }

            // Otherwise parse as 16 comma-separated bytes
            let parts: Vec<&str> = text.split(',').map(str::trim).collect();
            if parts.len() != 16 {
                return Err(format!(
                    "{}: Expected 16 comma-separated bytes for LongDouble, found {}",
                    info.name,
                    parts.len()
                ));
            }
            let mut bytes = [0u8; 16];
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
                    "{}: Expected {} comma-separated bytes, found {}",
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
