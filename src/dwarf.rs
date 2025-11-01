use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use crate::elf::Elf;
use crate::types::FileAddr;

#[allow(non_camel_case_types)]
pub type DwarfTag = u64;
#[allow(non_camel_case_types)]
pub type DwarfAttr = u64;
#[allow(non_camel_case_types)]
pub type DwarfForm = u64;

pub const DW_TAG_SUBPROGRAM: DwarfTag = 0x2e;
pub const DW_TAG_INLINED_SUBROUTINE: DwarfTag = 0x1d;

// DW_AT_* constants (subset)
pub const DW_AT_NAME: DwarfAttr = 0x03;
pub const DW_AT_STMT_LIST: DwarfAttr = 0x10;
pub const DW_AT_LOW_PC: DwarfAttr = 0x11;
pub const DW_AT_HIGH_PC: DwarfAttr = 0x12;
pub const DW_AT_COMP_DIR: DwarfAttr = 0x1b;
pub const DW_AT_LINKAGE_NAME: DwarfAttr = 0x6e;
pub const DW_AT_SPECIFICATION: DwarfAttr = 0x47;
pub const DW_AT_ABSTRACT_ORIGIN: DwarfAttr = 0x31;
pub const DW_AT_RANGES: DwarfAttr = 0x55;

// DW_FORM_* constants (subset)
pub const DW_FORM_ADDR: DwarfForm = 0x01;
pub const DW_FORM_BLOCK2: DwarfForm = 0x03;
pub const DW_FORM_BLOCK4: DwarfForm = 0x04;
pub const DW_FORM_DATA2: DwarfForm = 0x05;
pub const DW_FORM_DATA4: DwarfForm = 0x06;
pub const DW_FORM_DATA8: DwarfForm = 0x07;
pub const DW_FORM_STRING: DwarfForm = 0x08;
pub const DW_FORM_BLOCK: DwarfForm = 0x09;
pub const DW_FORM_BLOCK1: DwarfForm = 0x0a;
pub const DW_FORM_DATA1: DwarfForm = 0x0b;
pub const DW_FORM_FLAG: DwarfForm = 0x0c;
pub const DW_FORM_SDATA: DwarfForm = 0x0d;
pub const DW_FORM_STRP: DwarfForm = 0x0e;
pub const DW_FORM_UDATA: DwarfForm = 0x0f;
pub const DW_FORM_REF_ADDR: DwarfForm = 0x10;
pub const DW_FORM_REF1: DwarfForm = 0x11;
pub const DW_FORM_REF2: DwarfForm = 0x12;
pub const DW_FORM_REF4: DwarfForm = 0x13;
pub const DW_FORM_REF8: DwarfForm = 0x14;
pub const DW_FORM_REF_UDATA: DwarfForm = 0x15;
pub const DW_FORM_SEC_OFFSET: DwarfForm = 0x17;
pub const DW_FORM_EXPRLOC: DwarfForm = 0x18;
pub const DW_FORM_FLAG_PRESENT: DwarfForm = 0x19;
pub const DW_FORM_INDIRECT: DwarfForm = 0x16;

// Line table opcodes (subset)
const DW_LNS_COPY: u8 = 0x01;
const DW_LNS_ADVANCE_PC: u8 = 0x02;
const DW_LNS_ADVANCE_LINE: u8 = 0x03;
const DW_LNS_SET_FILE: u8 = 0x04;
const DW_LNS_SET_COLUMN: u8 = 0x05;
const DW_LNS_NEGATE_STMT: u8 = 0x06;
const DW_LNS_SET_BASIC_BLOCK: u8 = 0x07;
const DW_LNS_CONST_ADD_PC: u8 = 0x08;
const DW_LNS_FIXED_ADVANCE_PC: u8 = 0x09;
const DW_LNS_SET_PROLOGUE_END: u8 = 0x0a;
const DW_LNS_SET_EPILOGUE_BEGIN: u8 = 0x0b;
const DW_LNS_SET_ISA: u8 = 0x0c;

const DW_LNE_END_SEQUENCE: u8 = 0x01;
const DW_LNE_SET_ADDRESS: u8 = 0x02;
const DW_LNE_DEFINE_FILE: u8 = 0x03;
const DW_LNE_SET_DISCRIMINATOR: u8 = 0x04;

#[derive(Clone, Copy)]
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn is_finished(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn advance(&mut self, amount: usize) -> Result<()> {
        if self.pos + amount > self.data.len() {
            bail!("Cursor advanced past end of data");
        }
        self.pos += amount;
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            bail!("Unexpected end of data");
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!("Unexpected end of data while reading bytes");
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.data[start..self.pos])
    }

    fn read_uleb128(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }

    fn read_sleb128(&mut self) -> Result<i64> {
        let mut result = 0i64;
        let mut shift = 0;
        let mut byte;

        loop {
            byte = self.read_u8()?;
            let value = (byte & 0x7f) as i64;
            result |= value << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }

        if shift < 64 && (byte & 0x40) != 0 {
            result |= (!0i64) << shift;
        }

        Ok(result)
    }

    fn read_cstr(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            bail!("Unterminated string in DWARF data");
        }
        let end = self.pos;
        self.pos += 1; // skip null terminator
        Ok(&self.data[start..end])
    }

    fn skip_form(&mut self, form: DwarfForm) -> Result<()> {
        match form {
            DW_FORM_FLAG_PRESENT => {}
            DW_FORM_DATA1 | DW_FORM_REF1 | DW_FORM_FLAG => {
                self.advance(1)?;
            }
            DW_FORM_DATA2 | DW_FORM_REF2 => {
                self.advance(2)?;
            }
            DW_FORM_DATA4 | DW_FORM_REF4 | DW_FORM_REF_ADDR | DW_FORM_SEC_OFFSET | DW_FORM_STRP => {
                self.advance(4)?;
            }
            DW_FORM_DATA8 | DW_FORM_REF8 | DW_FORM_ADDR => {
                self.advance(8)?;
            }
            DW_FORM_SDATA => {
                let _ = self.read_sleb128()?;
            }
            DW_FORM_UDATA | DW_FORM_REF_UDATA => {
                let _ = self.read_uleb128()?;
            }
            DW_FORM_BLOCK1 => {
                let size = self.read_u8()? as usize;
                self.advance(size)?;
            }
            DW_FORM_BLOCK2 => {
                let size = self.read_u16()? as usize;
                self.advance(size)?;
            }
            DW_FORM_BLOCK4 => {
                let size = self.read_u32()? as usize;
                self.advance(size)?;
            }
            DW_FORM_BLOCK | DW_FORM_EXPRLOC => {
                let size = self.read_uleb128()? as usize;
                self.advance(size)?;
            }
            DW_FORM_STRING => {
                let _ = self.read_cstr()?;
            }
            DW_FORM_INDIRECT => {
                let actual = self.read_uleb128()?;
                self.skip_form(actual)?;
            }
            _ => bail!("Unsupported DWARF form: {form:#x}"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AttrSpec {
    pub attr: DwarfAttr,
    pub form: DwarfForm,
}

#[derive(Clone, Debug)]
pub struct Abbrev {
    pub code: u64,
    pub tag: DwarfTag,
    pub has_children: bool,
    pub attr_specs: Vec<AttrSpec>,
}

#[derive(Clone)]
pub struct Attr {
    dwarf: *const Dwarf,
    cu_index: usize,
    name: DwarfAttr,
    form: DwarfForm,
    location: usize,
}

impl Attr {
    pub fn name(&self) -> DwarfAttr {
        self.name
    }

    pub fn form(&self) -> DwarfForm {
        self.form
    }

    fn dwarf(&self) -> &Dwarf {
        unsafe { &*self.dwarf }
    }

    fn compile_unit(&self) -> &CompileUnit {
        &self.dwarf().compile_units[self.cu_index]
    }

    fn data_slice(&self) -> Result<&[u8]> {
        let cu = self.compile_unit();
        let data = cu.data();
        if self.location >= data.len() {
            bail!("Attribute location outside compile unit bounds");
        }
        Ok(&data[self.location..])
    }

    pub fn as_address(&self) -> Result<FileAddr> {
        if self.form != DW_FORM_ADDR {
            bail!("Attribute is not an address form");
        }
        let mut cur = Cursor::new(self.data_slice()?);
        let raw = cur.read_u64()?;
        let elf = self.dwarf().elf();
        Ok(FileAddr::from(elf, raw))
    }

    pub fn as_section_offset(&self) -> Result<u32> {
        if self.form != DW_FORM_SEC_OFFSET {
            bail!("Attribute is not a section offset");
        }
        let mut cur = Cursor::new(self.data_slice()?);
        cur.read_u32()
    }

    pub fn as_u64(&self) -> Result<u64> {
        let mut cur = Cursor::new(self.data_slice()?);
        Ok(match self.form {
            DW_FORM_DATA1 | DW_FORM_REF1 | DW_FORM_FLAG => cur.read_u8()? as u64,
            DW_FORM_DATA2 | DW_FORM_REF2 => cur.read_u16()? as u64,
            DW_FORM_DATA4 | DW_FORM_REF4 | DW_FORM_REF_ADDR | DW_FORM_SEC_OFFSET | DW_FORM_STRP => {
                cur.read_u32()? as u64
            }
            DW_FORM_DATA8 | DW_FORM_REF8 => cur.read_u64()?,
            DW_FORM_UDATA | DW_FORM_REF_UDATA => cur.read_uleb128()?,
            _ => bail!("Unsupported integer DWARF form {:#x}", self.form),
        })
    }

    pub fn as_i64(&self) -> Result<i64> {
        let mut cur = Cursor::new(self.data_slice()?);
        Ok(match self.form {
            DW_FORM_SDATA => cur.read_sleb128()?,
            _ => self.as_u64()? as i64,
        })
    }

    pub fn as_block(&self) -> Result<&[u8]> {
        let mut cur = Cursor::new(self.data_slice()?);
        let size = match self.form {
            DW_FORM_BLOCK1 => cur.read_u8()? as usize,
            DW_FORM_BLOCK2 => cur.read_u16()? as usize,
            DW_FORM_BLOCK4 => cur.read_u32()? as usize,
            DW_FORM_BLOCK | DW_FORM_EXPRLOC => cur.read_uleb128()? as usize,
            _ => bail!("Attribute is not a block form"),
        };
        cur.read_bytes(size)
    }

    pub fn as_string(&self) -> Result<String> {
        let dwarf = self.dwarf();
        let mut cur = Cursor::new(self.data_slice()?);
        match self.form {
            DW_FORM_STRING => {
                let bytes = cur.read_cstr()?;
                Ok(String::from_utf8(bytes.to_vec()).context("Invalid UTF-8 in DWARF string")?)
            }
            DW_FORM_STRP => {
                let offset = cur.read_u32()? as usize;
                let strings = &dwarf.debug_str;
                if offset >= strings.len() {
                    bail!(
                        "DWARF string offset out of bounds: offset={}, debug_str.len()={}",
                        offset,
                        strings.len()
                    );
                }
                let mut str_cur = Cursor::new(&strings[offset..]);
                let bytes = str_cur.read_cstr()?;
                Ok(String::from_utf8(bytes.to_vec()).context("Invalid UTF-8 in DWARF strp")?)
            }
            _ => bail!("Attribute is not a string form"),
        }
    }
}

#[derive(Clone)]
pub struct Die {
    dwarf: *const Dwarf,
    cu_index: usize,
    position: usize,
    next_offset: usize,
    abbrev_code: u64,
    attr_locs: Vec<usize>,
}

impl fmt::Debug for Die {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Die")
            .field("position", &self.position)
            .field("abbrev_code", &self.abbrev_code)
            .finish()
    }
}

impl Die {
    fn dwarf(&self) -> &Dwarf {
        unsafe { &*self.dwarf }
    }

    fn compile_unit(&self) -> &CompileUnit {
        &self.dwarf().compile_units[self.cu_index]
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn next_offset(&self) -> usize {
        self.next_offset
    }

    pub fn abbrev_code(&self) -> u64 {
        self.abbrev_code
    }

    pub fn is_null(&self) -> bool {
        self.abbrev_code == 0
    }

    pub fn abbrev_entry(&self) -> Option<&Abbrev> {
        if self.is_null() {
            return None;
        }
        let cu = self.compile_unit();
        cu.abbrev_table().get(&self.abbrev_code)
    }

    pub fn contains(&self, attr: DwarfAttr) -> bool {
        self.attr_index(attr).is_some()
    }

    pub fn get_attr(&self, attr: DwarfAttr) -> Result<Attr> {
        let idx = self
            .attr_index(attr)
            .ok_or_else(|| anyhow!("Attribute {attr:#x} not present in DIE"))?;
        let abbrev = self
            .abbrev_entry()
            .expect("abbrev entry present when attribute index exists");
        Ok(Attr {
            dwarf: self.dwarf,
            cu_index: self.cu_index,
            name: abbrev.attr_specs[idx].attr,
            form: abbrev.attr_specs[idx].form,
            location: self.attr_locs[idx],
        })
    }

    fn attr_index(&self, attr: DwarfAttr) -> Option<usize> {
        self.abbrev_entry()
            .and_then(|abbrev| abbrev.attr_specs.iter().position(|spec| spec.attr == attr))
    }

    pub fn tag(&self) -> Option<DwarfTag> {
        self.abbrev_entry().map(|a| a.tag)
    }

    pub fn cu(&self) -> &CompileUnit {
        self.compile_unit()
    }

    pub fn children(&self) -> DieChildren {
        if self.abbrev_entry().map_or(false, |a| a.has_children) {
            DieChildren {
                dwarf: self.dwarf,
                cu_index: self.cu_index,
                next_offset: self.next_offset,
                finished: false,
            }
        } else {
            DieChildren {
                dwarf: self.dwarf,
                cu_index: self.cu_index,
                next_offset: self.next_offset,
                finished: true,
            }
        }
    }

    pub fn low_pc(&self) -> Result<FileAddr> {
        let dwarf = self.dwarf();
        if self.contains(DW_AT_RANGES) {
            let ranges = dwarf.range_list_from_attr(&self.get_attr(DW_AT_RANGES)?)?;
            ranges
                .entries()
                .first()
                .map(|entry| entry.low)
                .ok_or_else(|| anyhow!("Empty range list for DIE"))
        } else if self.contains(DW_AT_LOW_PC) {
            self.get_attr(DW_AT_LOW_PC)?.as_address()
        } else {
            bail!("DIE does not provide low_pc");
        }
    }

    pub fn high_pc(&self) -> Result<FileAddr> {
        let dwarf = self.dwarf();
        if self.contains(DW_AT_RANGES) {
            let ranges = dwarf.range_list_from_attr(&self.get_attr(DW_AT_RANGES)?)?;
            ranges
                .entries()
                .last()
                .map(|entry| entry.high)
                .ok_or_else(|| anyhow!("Empty range list for DIE"))
        } else if self.contains(DW_AT_HIGH_PC) {
            let low = self.low_pc()?;
            let high_attr = self.get_attr(DW_AT_HIGH_PC)?;
            if high_attr.form() == DW_FORM_ADDR {
                high_attr.as_address()
            } else {
                Ok(FileAddr::from(
                    dwarf.elf(),
                    low.addr() + high_attr.as_u64()?,
                ))
            }
        } else {
            bail!("DIE does not provide high_pc");
        }
    }

    pub fn contains_address(&self, address: FileAddr) -> Result<bool> {
        let dwarf = self.dwarf();
        if self.contains(DW_AT_RANGES) {
            let ranges = dwarf.range_list_from_attr(&self.get_attr(DW_AT_RANGES)?)?;
            Ok(ranges.contains(address))
        } else if self.contains(DW_AT_LOW_PC) {
            let low = self.low_pc()?;
            if self.contains(DW_AT_HIGH_PC) {
                let high = self.high_pc()?;
                Ok(low <= address && address < high)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    pub fn name(&self) -> Result<Option<String>> {
        die_name(self.dwarf(), self)
    }

    /// Returns the offset of the next sibling DIE, skipping all descendants.
    /// If this DIE has no children, returns next_offset().
    /// If this DIE has children, skips over all of them to find the next sibling.
    fn next_sibling(&self) -> Result<usize> {
        // If this DIE doesn't have children, the next DIE is the sibling
        if !self.abbrev_entry().map_or(false, |a| a.has_children) {
            return Ok(self.next_offset);
        }

        // This DIE has children. We need to skip over all descendants.
        // Start at the first child and track nesting depth.
        let cu = self.compile_unit();
        let mut offset = self.next_offset;
        let mut depth = 1; // We're inside this DIE's children

        loop {
            let die = parse_die_at(cu, offset)?;
            offset = die.next_offset();

            if die.is_null() {
                // Null DIE marks end of children at current depth
                depth -= 1;
                if depth == 0 {
                    // We've found the null DIE that ends our children
                    return Ok(offset);
                }
            } else if die.abbrev_entry().map_or(false, |a| a.has_children) {
                // This child has children, so we need to go deeper
                depth += 1;
            }
        }
    }
}

pub struct DieChildren {
    dwarf: *const Dwarf,
    cu_index: usize,
    next_offset: usize,
    finished: bool,
}

impl Iterator for DieChildren {
    type Item = Die;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let dwarf = unsafe { &*self.dwarf };
        let cu = &dwarf.compile_units[self.cu_index];
        let die = parse_die_at(cu, self.next_offset).ok()?;
        // Use next_sibling() to skip descendants, not just next_offset()
        self.next_offset = die.next_sibling().ok()?;
        if die.is_null() {
            self.finished = true;
            None
        } else {
            Some(die)
        }
    }
}

fn parse_die_at(cu: &CompileUnit, offset: usize) -> Result<Die> {
    let data = cu.data();
    if offset >= data.len() {
        bail!("DIE offset outside compile unit data");
    }

    let mut cur = Cursor::new(&data[offset..]);
    let abbrev_code = cur.read_uleb128()?;

    if abbrev_code == 0 {
        let next_offset = offset + cur.position();
        return Ok(Die {
            dwarf: cu.dwarf,
            cu_index: cu.index,
            position: offset,
            next_offset,
            abbrev_code,
            attr_locs: Vec::new(),
        });
    }

    let abbrev = cu
        .abbrev_table()
        .get(&abbrev_code)
        .ok_or_else(|| anyhow!("Missing abbrev code {abbrev_code}"))?;

    let mut attr_locs = Vec::with_capacity(abbrev.attr_specs.len());
    for spec in abbrev.attr_specs.iter() {
        let attr_offset = offset + cur.position();
        attr_locs.push(attr_offset);
        cur.skip_form(spec.form)?;
    }

    let next_offset = offset + cur.position();

    Ok(Die {
        dwarf: cu.dwarf,
        cu_index: cu.index,
        position: offset,
        next_offset,
        abbrev_code,
        attr_locs,
    })
}

#[derive(Clone, Debug)]
pub struct RangeListEntry {
    pub low: FileAddr,
    pub high: FileAddr,
}

pub struct RangeList {
    entries: Vec<RangeListEntry>,
}

impl RangeList {
    pub fn contains(&self, address: FileAddr) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.low <= address && address < entry.high)
    }

    pub fn entries(&self) -> &[RangeListEntry] {
        &self.entries
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineTableFile {
    pub path: PathBuf,
    pub modification_time: u64,
    pub file_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineTableEntry {
    pub address: FileAddr,
    pub file_index: u64,
    pub line: u64,
    pub column: u64,
    pub is_stmt: bool,
    pub basic_block_start: bool,
    pub end_sequence: bool,
    pub prologue_end: bool,
    pub epilogue_begin: bool,
    pub discriminator: u64,
    pub file: Option<LineTableFile>,
}

impl LineTableEntry {
    fn new(address: FileAddr) -> Self {
        Self {
            address,
            file_index: 1,
            line: 1,
            column: 0,
            is_stmt: false,
            basic_block_start: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            discriminator: 0,
            file: None,
        }
    }
}

#[derive(Clone)]
struct LineTableState {
    address: FileAddr,
    file_index: u64,
    line: u64,
    column: u64,
    is_stmt: bool,
    basic_block_start: bool,
    end_sequence: bool,
    prologue_end: bool,
    epilogue_begin: bool,
    discriminator: u64,
}

impl LineTableState {
    fn new(default_is_stmt: bool, base_address: FileAddr) -> Self {
        Self {
            address: base_address,
            file_index: 1,
            line: 1,
            column: 0,
            is_stmt: default_is_stmt,
            basic_block_start: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            discriminator: 0,
        }
    }

    fn reset(&mut self, default_is_stmt: bool, base_address: FileAddr) {
        *self = Self::new(default_is_stmt, base_address);
    }
}

#[derive(Clone)]
pub struct LineTable {
    dwarf: *const Dwarf,
    cu_index: usize,
    default_is_stmt: bool,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    include_directories: Vec<PathBuf>,
    file_names: RefCell<Vec<LineTableFile>>,
    program_offset: usize,
    program_len: usize,
}

impl LineTable {
    fn dwarf(&self) -> &Dwarf {
        unsafe { &*self.dwarf }
    }

    fn cu(&self) -> &CompileUnit {
        &self.dwarf().compile_units[self.cu_index]
    }

    fn program(&self) -> &[u8] {
        &self.dwarf().debug_line[self.program_offset..self.program_offset + self.program_len]
    }

    fn files(&self) -> std::cell::Ref<'_, Vec<LineTableFile>> {
        self.file_names.borrow()
    }

    fn files_mut(&self) -> std::cell::RefMut<'_, Vec<LineTableFile>> {
        self.file_names.borrow_mut()
    }

    pub fn iter(&self) -> LineTableIter {
        LineTableIter::new(self)
    }

    pub fn get_entry_by_address(&self, address: FileAddr) -> Option<LineTableEntry> {

        let mut iter = self.iter();
        let mut prev = match iter.next() {
            Some(entry) => entry,
            None => return None,
        };

        // Check for exact match on first entry
        if prev.address == address && prev.address.addr() > 0 && !prev.end_sequence {
            return Some(prev);
        }

        for entry in iter {
            // Check for exact match
            if entry.address == address && entry.address.addr() > 0 && !entry.end_sequence {
                return Some(entry);
            }

            // Check if this could be a match: prev.address <= target < entry.address
            // Also ensure prev has a non-zero address to skip placeholder entries
            // Skip entries with addr=0 as they're likely sequence markers
            if prev.address <= address
                && entry.address > address
                && !prev.end_sequence
                && prev.address.addr() > 0
                && entry.address.addr() > 0
            {
                return Some(prev);
            }
            prev = entry;
        }
        None
    }

    pub fn get_entries_by_line<P: AsRef<Path>>(&self, path: P, line: u64) -> Vec<LineTableEntry> {
        let mut entries = Vec::new();
        let path = path.as_ref();
        for entry in self.iter() {
            if entry.line == line {
                if let Some(file) = &entry.file {
                    if paths_match(&file.path, path) {
                        entries.push(entry);
                    }
                }
            }
        }
        entries
    }

    pub fn entry_after(&self, address: FileAddr) -> Option<LineTableEntry> {
        let entries: Vec<_> = self.iter().collect();

        let mut candidate_index: Option<usize> = None;

        for (idx, entry) in entries.iter().enumerate() {
            if entry.end_sequence {
                candidate_index = None;
                continue;
            }

            if entry.address > address {
                break;
            }

            candidate_index = Some(idx);

            if entry.address == address {
                break;
            }
        }

        if let Some(idx) = candidate_index {
            for entry in entries.iter().skip(idx + 1) {
                if entry.end_sequence {
                    break;
                }

                return Some(entry.clone());
            }
            return None;
        }

        for entry in entries.iter() {
            if entry.end_sequence {
                break;
            }

            return Some(entry.clone());
        }

        None
    }
}

pub struct LineTableIter<'a> {
    table: &'a LineTable,
    cursor: Cursor<'a>,
    registers: LineTableState,
    finished: bool,
}

impl<'a> LineTableIter<'a> {
    fn new(table: &'a LineTable) -> Self {
        let program = table.program();
        let base_addr = FileAddr::from(table.dwarf().elf(), 0);
        LineTableIter {
            table,
            cursor: Cursor::new(program),
            registers: LineTableState::new(table.default_is_stmt, base_addr),
            finished: false,
        }
    }

    fn make_entry(&self) -> LineTableEntry {
        let mut entry = LineTableEntry::new(self.registers.address);
        entry.file_index = self.registers.file_index;
        entry.line = self.registers.line;
        entry.column = self.registers.column;
        entry.is_stmt = self.registers.is_stmt;
        entry.basic_block_start = self.registers.basic_block_start;
        entry.end_sequence = self.registers.end_sequence;
        entry.prologue_end = self.registers.prologue_end;
        entry.epilogue_begin = self.registers.epilogue_begin;
        entry.discriminator = self.registers.discriminator;

        if let Some(file) = self
            .table
            .files()
            .get((entry.file_index.saturating_sub(1)) as usize)
            .cloned()
        {
            entry.file = Some(file);
        }

        entry
    }

    fn execute_standard_opcode(&mut self, opcode: u8) -> Result<bool> {
        match opcode {
            DW_LNS_COPY => {
                let emitted = true;
                self.registers.basic_block_start = false;
                self.registers.prologue_end = false;
                self.registers.epilogue_begin = false;
                self.registers.discriminator = 0;
                Ok(emitted)
            }
            DW_LNS_ADVANCE_PC => {
                let advance = self.cursor.read_uleb128()?;
                self.registers.address += advance as i64;
                Ok(false)
            }
            DW_LNS_ADVANCE_LINE => {
                let advance = self.cursor.read_sleb128()?;
                self.registers.line = ((self.registers.line as i64) + advance) as u64;
                Ok(false)
            }
            DW_LNS_SET_FILE => {
                self.registers.file_index = self.cursor.read_uleb128()?;
                Ok(false)
            }
            DW_LNS_SET_COLUMN => {
                self.registers.column = self.cursor.read_uleb128()?;
                Ok(false)
            }
            DW_LNS_NEGATE_STMT => {
                self.registers.is_stmt = !self.registers.is_stmt;
                Ok(false)
            }
            DW_LNS_SET_BASIC_BLOCK => {
                self.registers.basic_block_start = true;
                Ok(false)
            }
            DW_LNS_CONST_ADD_PC => {
                let adjust = ((255 - self.table.opcode_base) / self.table.line_range) as u64;
                self.registers.address += adjust as i64;
                Ok(false)
            }
            DW_LNS_FIXED_ADVANCE_PC => {
                let advance = self.cursor.read_u16()? as u64;
                self.registers.address += advance as i64;
                Ok(false)
            }
            DW_LNS_SET_PROLOGUE_END => {
                self.registers.prologue_end = true;
                Ok(false)
            }
            DW_LNS_SET_EPILOGUE_BEGIN => {
                self.registers.epilogue_begin = true;
                Ok(false)
            }
            DW_LNS_SET_ISA => {
                let _ = self.cursor.read_uleb128()?;
                Ok(false)
            }
            _ => bail!("Unexpected DWARF standard opcode {opcode:#x}"),
        }
    }

    fn execute_extended_opcode(&mut self) -> Result<bool> {
        let len = self.cursor.read_uleb128()? as usize;
        let before = self.cursor.position();
        let opcode = self.cursor.read_u8()?;
        let emitted;
        match opcode {
            DW_LNE_END_SEQUENCE => {
                self.registers.end_sequence = true;
                emitted = true;
                self.registers.reset(
                    self.table.default_is_stmt,
                    FileAddr::from(self.table.dwarf().elf(), 0),
                );
            }
            DW_LNE_SET_ADDRESS => {
                let addr = self.cursor.read_u64()?;
                self.registers.address = FileAddr::from(self.table.dwarf().elf(), addr);
                emitted = false;
            }
            DW_LNE_DEFINE_FILE => {
                let file = parse_line_table_file(
                    self.table,
                    &mut self.cursor,
                    self.table.include_directories.clone(),
                )?;
                self.table.files_mut().push(file);
                emitted = false;
            }
            DW_LNE_SET_DISCRIMINATOR => {
                self.registers.discriminator = self.cursor.read_uleb128()?;
                emitted = false;
            }
            _ => {
                // Skip the remaining bytes for unknown extended opcodes
                // len includes the opcode byte itself, which we already read
                if len > 0 {
                    self.cursor.advance(len.saturating_sub(1))?;
                }
                emitted = false;
            }
        }

        let consumed = self.cursor.position() - before;
        if consumed < len {
            self.cursor.advance(len - consumed)?;
        }
        Ok(emitted)
    }
}

impl<'a> Iterator for LineTableIter<'a> {
    type Item = LineTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        loop {
            if self.cursor.is_finished() {
                self.finished = true;
                return None;
            }

            let opcode = self.cursor.read_u8().ok()?;

            let emitted = if opcode == 0 {
                self.execute_extended_opcode().ok()?
            } else if opcode < self.table.opcode_base {
                self.execute_standard_opcode(opcode).ok()?
            } else {
                let adjusted = opcode - self.table.opcode_base;
                let address_increment = adjusted / self.table.line_range;
                let line_increment = adjusted % self.table.line_range;
                self.registers.address += address_increment as i64;
                self.registers.line = (self.registers.line as i64
                    + self.table.line_base as i64
                    + line_increment as i64) as u64;
                let emitted = true;
                self.registers.basic_block_start = false;
                self.registers.prologue_end = false;
                self.registers.epilogue_begin = false;
                self.registers.discriminator = 0;
                emitted
            };

            if emitted {
                let entry = self.make_entry();
                return Some(entry);
            }
        }
    }
}

fn paths_match(lhs: &Path, rhs: &Path) -> bool {
    if rhs.is_absolute() {
        return lhs == rhs;
    }

    let lhs_components: Vec<_> = lhs.components().collect();
    let rhs_components: Vec<_> = rhs.components().collect();

    if rhs_components.len() > lhs_components.len() {
        return false;
    }

    let start = lhs_components.len() - rhs_components.len();
    lhs_components[start..] == rhs_components
}

fn parse_line_table_file(
    table: &LineTable,
    cur: &mut Cursor<'_>,
    include_directories: Vec<PathBuf>,
) -> Result<LineTableFile> {
    let name_bytes = cur.read_cstr()?;
    let name =
        String::from_utf8(name_bytes.to_vec()).context("Invalid UTF-8 in line table file")?;
    let dir_index = cur.read_uleb128()? as usize;
    let modification_time = cur.read_uleb128()?;
    let file_length = cur.read_uleb128()?;

    let path = if name.starts_with('/') {
        PathBuf::from(&name)
    } else if dir_index == 0 {
        if let Ok(root) = table.cu().root() {
            if let Ok(comp_dir_attr) = root.get_attr(DW_AT_COMP_DIR) {
                let dir = comp_dir_attr.as_string()?;
                PathBuf::from(dir).join(&name)
            } else {
                PathBuf::from(&name)
            }
        } else {
            PathBuf::from(&name)
        }
    } else {
        include_directories
            .get(dir_index.saturating_sub(1))
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(&name)
    };

    Ok(LineTableFile {
        path,
        modification_time,
        file_length,
    })
}

#[derive(Clone)]
pub struct CompileUnit {
    dwarf: *const Dwarf,
    index: usize,
    offset: usize,
    size: usize,
    abbrev_offset: u32,
    line_table: RefCell<Option<LineTable>>,
}

impl CompileUnit {
    pub fn data(&self) -> &[u8] {
        let dwarf = unsafe { &*self.dwarf };
        &dwarf.debug_info[self.offset..self.offset + self.size]
    }

    pub fn root(&self) -> Result<Die> {
        parse_die_at(self, 11)
    }

    pub fn lines(&self) -> Result<Option<LineTable>> {
        if let Some(existing) = self.line_table.borrow().clone() {
            return Ok(Some(existing));
        }

        if !self.root()?.contains(DW_AT_STMT_LIST) {
            return Ok(None);
        }

        let dwarf = unsafe { &*self.dwarf };
        let stmt_list_attr = self.root()?.get_attr(DW_AT_STMT_LIST)?;
        let offset = stmt_list_attr.as_u64()? as usize;
        if offset >= dwarf.debug_line.len() {
            bail!("Line table offset outside .debug_line");
        }

        let mut cursor = Cursor::new(&dwarf.debug_line[offset..]);
        let unit_length = cursor.read_u32()? as usize;
        let header_start_pos = cursor.position(); // Position after reading unit_length

        let version = cursor.read_u16()?;
        if version != 4 {
            bail!("Only DWARF v4 line tables supported");
        }

        let header_length = cursor.read_u32()? as usize;
        let header_end = cursor.position() + header_length;

        let minimum_instruction_length = cursor.read_u8()?;
        if minimum_instruction_length != 1 {
            bail!("Unsupported minimum instruction length {minimum_instruction_length}");
        }
        let maximum_operations_per_instruction = cursor.read_u8()?;
        if maximum_operations_per_instruction != 1 {
            bail!("Unsupported operations per instruction");
        }

        let default_is_stmt = cursor.read_u8()? != 0;
        let line_base = cursor.read_i8()?;
        let line_range = cursor.read_u8()?;
        let opcode_base = cursor.read_u8()?;

        // Skip standard opcode lengths array (opcode_base - 1 bytes)
        for _ in 0..(opcode_base.saturating_sub(1)) {
            cursor.read_u8()?;
        }

        let mut include_directories = Vec::new();
        while cursor.position() < header_end {
            let dir_bytes = cursor.read_cstr()?;
            if dir_bytes.is_empty() {
                break;
            }
            let dir =
                String::from_utf8(dir_bytes.to_vec()).context("Invalid UTF-8 in directory")?;
            include_directories.push(PathBuf::from(dir));
        }

        let mut files = Vec::new();
        while cursor.position() < header_end {
            if cursor.remaining().first() == Some(&0) {
                cursor.advance(1)?;
                break;
            }
            let file = parse_line_table_file_placeholder(&mut cursor, &include_directories, self)?;
            files.push(file);
        }

        if cursor.position() < header_end {
            cursor.advance(header_end - cursor.position())?;
        }

        // Calculate program offset and length correctly
        // program_offset is where the line number program starts (after the header)
        // program_len is how much is left in the unit after the header
        let program_offset = offset + header_start_pos + header_length;
        let program_len = unit_length - (header_start_pos - 4 + header_length); // Subtract header size from unit_length

        let table = LineTable {
            dwarf: self.dwarf,
            cu_index: self.index,
            default_is_stmt,
            line_base,
            line_range,
            opcode_base,
            include_directories,
            file_names: RefCell::new(files),
            program_offset,
            program_len,
        };

        *self.line_table.borrow_mut() = Some(table.clone());
        Ok(Some(table))
    }

    pub fn abbrev_table(&self) -> &HashMap<u64, Abbrev> {
        let dwarf = unsafe { &*self.dwarf };
        dwarf
            .abbrev_tables
            .get(&self.abbrev_offset)
            .expect("Abbrev table present")
    }
}

fn parse_line_table_file_placeholder(
    cur: &mut Cursor<'_>,
    include_dirs: &[PathBuf],
    cu: &CompileUnit,
) -> Result<LineTableFile> {
    let name_bytes = cur.read_cstr()?;
    let name =
        String::from_utf8(name_bytes.to_vec()).context("Invalid UTF-8 in line table file")?;
    let dir_index = cur.read_uleb128()? as usize;
    let modification_time = cur.read_uleb128()?;
    let file_length = cur.read_uleb128()?;

    let path = if name.starts_with('/') {
        PathBuf::from(name)
    } else if dir_index == 0 {
        if let Ok(attr) = cu.root()?.get_attr(DW_AT_COMP_DIR) {
            PathBuf::from(attr.as_string()?).join(name)
        } else {
            PathBuf::from(name)
        }
    } else if let Some(dir) = include_dirs.get(dir_index - 1) {
        dir.join(name)
    } else {
        PathBuf::from(name)
    };

    Ok(LineTableFile {
        path,
        modification_time,
        file_length,
    })
}

pub struct Dwarf {
    elf: *const Elf,
    pub debug_info: Vec<u8>,
    pub debug_line: Vec<u8>,
    pub debug_abbrev: Vec<u8>,
    pub debug_str: Vec<u8>,
    pub debug_ranges: Vec<u8>,
    pub compile_units: Vec<CompileUnit>,
    abbrev_tables: HashMap<u32, HashMap<u64, Abbrev>>,
}

impl Dwarf {
    pub fn new(elf: &Elf) -> Result<Box<Self>> {
        let debug_info = elf.get_section_bytes(".debug_info").unwrap_or_default();
        let debug_line = elf.get_section_bytes(".debug_line").unwrap_or_default();
        let debug_abbrev = elf.get_section_bytes(".debug_abbrev").unwrap_or_default();
        let debug_str = elf.get_section_bytes(".debug_str").unwrap_or_default();
        let debug_ranges = elf.get_section_bytes(".debug_ranges").unwrap_or_default();

        let mut dwarf = Box::new(Self {
            elf: elf as *const _ as *const Elf,
            debug_info,
            debug_line,
            debug_abbrev,
            debug_str,
            debug_ranges,
            compile_units: Vec::new(),
            abbrev_tables: HashMap::new(),
        });

        dwarf.parse_compile_units()?;
        Ok(dwarf)
    }

    fn elf(&self) -> &Elf {
        unsafe { &*self.elf }
    }

    fn parse_compile_units(&mut self) -> Result<()> {
        let mut offset = 0usize;
        let mut index = 0usize;
        while offset < self.debug_info.len() {
            if offset + 11 > self.debug_info.len() {
                break;
            }

            let mut cur = Cursor::new(&self.debug_info[offset..]);
            let unit_len = cur.read_u32()? as usize;
            let version = cur.read_u16()?;
            if version != 4 {
                bail!("Only DWARF v4 supported (saw version {version})");
            }
            let abbrev_offset = cur.read_u32()?;
            let address_size = cur.read_u8()?;
            if address_size != 8 {
                bail!("Unsupported address size {address_size}");
            }

            let total_size = unit_len + 4;
            if offset + total_size > self.debug_info.len() {
                bail!("Compile unit extends past end of .debug_info");
            }

            if !self.abbrev_tables.contains_key(&abbrev_offset) {
                let table = parse_abbrev_table(&self.debug_abbrev, abbrev_offset as usize)?;
                self.abbrev_tables.insert(abbrev_offset, table);
            }

            let cu = CompileUnit {
                dwarf: self as *const _ as *const Dwarf,
                index,
                offset,
                size: total_size,
                abbrev_offset,
                line_table: RefCell::new(None),
            };

            self.compile_units.push(cu);
            offset += total_size;
            index += 1;
        }
        Ok(())
    }

    pub fn compile_unit_containing_address(
        &self,
        address: FileAddr,
    ) -> Result<Option<&CompileUnit>> {
        for cu in &self.compile_units {
            if let Ok(root) = cu.root() {
                if root.contains(DW_AT_LOW_PC) {
                    let low = root.get_attr(DW_AT_LOW_PC)?.as_address()?;
                    if root.contains(DW_AT_HIGH_PC) {
                        let high_attr = root.get_attr(DW_AT_HIGH_PC)?;
                        let high = match high_attr.form() {
                            DW_FORM_ADDR => high_attr.as_address()?,
                            _ => {
                                FileAddr::from(self.elf(), low.addr() + high_attr.as_u64()? as u64)
                            }
                        };
                        if low <= address && address < high {
                            return Ok(Some(cu));
                        }
                    }
                    if root.contains(DW_AT_RANGES) {
                        if let Ok(ranges) = self.range_list_from_attr(&root.get_attr(DW_AT_RANGES)?)
                        {
                            if ranges.contains(address) {
                                return Ok(Some(cu));
                            }
                        }
                    }
                } else if root.contains(DW_AT_RANGES) {
                    if let Ok(ranges) = self.range_list_from_attr(&root.get_attr(DW_AT_RANGES)?) {
                        if ranges.contains(address) {
                            return Ok(Some(cu));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn function_containing_address(&self, address: FileAddr) -> Result<Option<Die>> {
        for (idx, cu) in self.compile_units.iter().enumerate() {
            let root = cu.root()?;
            if std::env::var_os("RDB_DEBUG").is_some() {
                let has_children = root.abbrev_entry().map_or(false, |a| a.has_children);
                eprintln!("  Searching CU #{} at offset 0x{:x}, root has_children={}",
                    idx, cu.offset, has_children);
            }
            if let Some(die) = find_function_in_die(&root, address)? {
                return Ok(Some(die));
            }
        }
        Ok(None)
    }

    pub fn find_functions(&self, name: &str) -> Result<Vec<Die>> {
        let mut result = Vec::new();
        for cu in &self.compile_units {
            collect_functions_with_name(&cu.root()?, name, &mut result)?;
        }
        Ok(result)
    }

    pub fn inline_stack_at_address(&self, address: FileAddr) -> Result<Vec<Die>> {
        let mut stack = Vec::new();
        if let Some(func) = self.function_containing_address(address)? {
            stack.push(func.clone());
            loop {
                let mut found = None;
                if let Some(last) = stack.last() {
                    // Search through ALL descendants, not just immediate children
                    found = find_inlined_subroutine_at_address(last, address)?;
                }
                if let Some(die) = found {
                    stack.push(die);
                } else {
                    break;
                }
            }
        }
        Ok(stack)
    }

    pub(crate) fn range_list_from_attr(&self, attr: &Attr) -> Result<RangeList> {
        let offset = attr.as_section_offset()? as usize;
        if offset >= self.debug_ranges.len() {
            bail!("Range list offset outside .debug_ranges");
        }
        let mut cur = Cursor::new(&self.debug_ranges[offset..]);
        let mut entries = Vec::new();
        loop {
            let low = cur.read_u64()?;
            let high = cur.read_u64()?;
            if low == 0 && high == 0 {
                break;
            }
            entries.push(RangeListEntry {
                low: FileAddr::from(self.elf(), low),
                high: FileAddr::from(self.elf(), high),
            });
        }
        Ok(RangeList { entries })
    }
}

fn parse_abbrev_table(data: &[u8], offset: usize) -> Result<HashMap<u64, Abbrev>> {
    if offset >= data.len() {
        bail!("Abbrev table offset outside .debug_abbrev");
    }
    let mut table = HashMap::new();
    let mut cur = Cursor::new(&data[offset..]);

    loop {
        let code = cur.read_uleb128()?;
        if code == 0 {
            break;
        }
        let tag = cur.read_uleb128()?;
        let has_children = cur.read_u8()? != 0;
        let mut attr_specs = Vec::new();
        loop {
            let attr = cur.read_uleb128()?;
            let form = cur.read_uleb128()?;
            if attr == 0 && form == 0 {
                break;
            }
            attr_specs.push(AttrSpec { attr, form });
        }
        table.insert(
            code,
            Abbrev {
                code,
                tag,
                has_children,
                attr_specs,
            },
        );
    }
    Ok(table)
}

fn find_inlined_subroutine_at_address(die: &Die, address: FileAddr) -> Result<Option<Die>> {
    // Look at immediate children only (siblings at the same level)
    if !die.abbrev_entry().map_or(false, |a| a.has_children) {
        return Ok(None);
    }

    let cu = die.compile_unit();
    let mut offset = die.next_offset();
    let debug = std::env::var_os("RDB_DEBUG").is_some();

    if debug {
        let parent_name = die.name().ok().flatten().unwrap_or_else(|| "<unnamed>".to_string());
        eprintln!("  find_inlined_subroutine_at_address: searching children of '{}' for address 0x{:x}",
            parent_name, address.addr());
    }

    loop {
        let child = parse_die_at(cu, offset)?;

        if child.is_null() {
            // End of children at this level
            break;
        }

        if debug {
            let child_name = child.name().ok().flatten().unwrap_or_else(|| "<unnamed>".to_string());
            eprintln!("    child: tag=0x{:x?}, name='{}', has_children={}",
                child.tag(), child_name, child.abbrev_entry().map_or(false, |a| a.has_children));
        }

        // Check if this is an inlined subroutine containing the address
        if child.tag() == Some(DW_TAG_INLINED_SUBROUTINE) {
            if debug {
                eprintln!("      found DW_TAG_INLINED_SUBROUTINE, checking if it contains address...");
            }
            if child.contains_address(address)? {
                if debug {
                    eprintln!("      YES! returning this inlined subroutine");
                }
                return Ok(Some(child));
            } else if debug {
                eprintln!("      no, doesn't contain address");
            }
        }

        // Move to next sibling (skip this child's descendants)
        offset = child.next_sibling()?;
    }

    if debug {
        eprintln!("  find_inlined_subroutine_at_address: no inlined subroutine found");
    }

    Ok(None)
}

fn find_function_in_die(die: &Die, address: FileAddr) -> Result<Option<Die>> {
    // Debug: log all DIEs we visit if debugging
    if std::env::var_os("RDB_DEBUG").is_some() {
        if die.tag() == Some(0x39) { // Always log namespaces
            let name = die.name().ok().flatten().unwrap_or_else(|| "<unnamed>".to_string());
            let has_children = die.abbrev_entry().map_or(false, |a| a.has_children);
            eprintln!("  Visiting namespace: '{}', has_children={}", name, has_children);
        }
    }

    // First check if this DIE is a function and contains the address
    if matches!(
        die.tag(),
        Some(DW_TAG_SUBPROGRAM | DW_TAG_INLINED_SUBROUTINE)
    ) {
        // Only check if DIE has address information
        if die.contains(DW_AT_LOW_PC) || die.contains(DW_AT_RANGES) {
            let contains = die.contains_address(address)?;
            if std::env::var_os("RDB_DEBUG").is_some() {
                let name = die.name().unwrap_or(None).unwrap_or_else(|| "<unnamed>".to_string());
                if let (Ok(low), Ok(high)) = (die.low_pc(), die.high_pc()) {
                    eprintln!("  find_function_in_die: checking {}, low=0x{:x}, high=0x{:x}, addr=0x{:x}, contains={}",
                        name, low.addr(), high.addr(), address.addr(), contains);
                }
            }
            if contains {
                return Ok(Some(die.clone()));
            }
        } else if std::env::var_os("RDB_DEBUG").is_some() {
            let name = die.name().unwrap_or(None).unwrap_or_else(|| "<unnamed>".to_string());
            eprintln!("  find_function_in_die: subprogram {} has no address info", name);
        }
    }

    // Always recurse into children to find nested functions
    // (e.g., functions inside namespaces, lexical blocks, etc.)
    let children_iter = die.children();
    if std::env::var_os("RDB_DEBUG").is_some() {
        let has_children = die.abbrev_entry().map_or(false, |a| a.has_children);
        if has_children && (die.tag() == Some(0x11) || die.tag() == Some(0x39)) { // Log for CUs and namespaces
            let name = die.name().ok().flatten().unwrap_or_else(|| "<anon>".to_string());
            let tag_name = if die.tag() == Some(0x11) { "CU" } else { "namespace" };
            eprintln!("  {} '{}' has_children=true, iterating...", tag_name, name);
        }
    }
    let mut child_count = 0;
    for child in children_iter {
        child_count += 1;
        if std::env::var_os("RDB_DEBUG").is_some() && die.tag() == Some(0x11) && die.cu().index == 0 {
            // Log first CU's children
            let child_name = child.name().ok().flatten().unwrap_or_else(|| "<no-name>".to_string());
            eprintln!("  CU[{}] child #{}: tag=0x{:x?}, name='{}'", die.cu().index, child_count, child.tag(), child_name);
        }
        if let Some(found) = find_function_in_die(&child, address)? {
            if std::env::var_os("RDB_DEBUG").is_some() && die.tag() == Some(0x11) {
                eprintln!("  Found function after {} children", child_count);
            }
            return Ok(Some(found));
        }
    }
    if std::env::var_os("RDB_DEBUG").is_some() {
        let is_interesting = die.tag() == Some(0x11) || die.tag() == Some(0x39);
        if is_interesting {
            let name = die.name().ok().flatten().unwrap_or_else(|| "<anon>".to_string());
            let tag_name = if die.tag() == Some(0x11) { "CU" } else { "namespace" };
            eprintln!("  {} '{}' had {} children, not found", tag_name, name, child_count);
        }
    }

    Ok(None)
}

fn collect_functions_with_name(die: &Die, name: &str, out: &mut Vec<Die>) -> Result<()> {
    if matches!(
        die.tag(),
        Some(DW_TAG_SUBPROGRAM | DW_TAG_INLINED_SUBROUTINE)
    ) {
        if let Some(die_name) = die.name()? {
            if die_name == name {
                out.push(die.clone());
            }
        }
    }

    for child in die.children() {
        collect_functions_with_name(&child, name, out)?;
    }
    Ok(())
}

fn die_name(dwarf: &Dwarf, die: &Die) -> Result<Option<String>> {
    if die.contains(DW_AT_NAME) {
        return Ok(Some(die.get_attr(DW_AT_NAME)?.as_string()?));
    }
    if die.contains(DW_AT_LINKAGE_NAME) {
        return Ok(Some(die.get_attr(DW_AT_LINKAGE_NAME)?.as_string()?));
    }
    if die.contains(DW_AT_SPECIFICATION) {
        let spec_die = resolve_reference(dwarf, die, die.get_attr(DW_AT_SPECIFICATION)?)?;
        return die_name(dwarf, &spec_die);
    }
    if die.contains(DW_AT_ABSTRACT_ORIGIN) {
        let origin = resolve_reference(dwarf, die, die.get_attr(DW_AT_ABSTRACT_ORIGIN)?)?;
        return die_name(dwarf, &origin);
    }
    Ok(None)
}

fn resolve_reference(dwarf: &Dwarf, die: &Die, attr: Attr) -> Result<Die> {
    // DW_FORM_REF1/2/4/8/UDATA are CU-relative offsets
    // DW_FORM_REF_ADDR is a .debug_info section offset
    let cu = die.compile_unit();

    let (cu_for_ref, offset_in_cu) = match attr.form() {
        DW_FORM_REF1 | DW_FORM_REF2 | DW_FORM_REF4 | DW_FORM_REF8 | DW_FORM_REF_UDATA => {
            // These are CU-relative offsets
            let offset_in_cu = attr.as_u64()? as usize;
            (cu, offset_in_cu)
        }
        DW_FORM_REF_ADDR => {
            // This is a .debug_info section offset
            let section_offset = attr.as_u64()? as usize;
            if section_offset >= dwarf.debug_info.len() {
                bail!("Reference offset outside .debug_info");
            }

            // Find the CU that contains this offset
            let cu_for_offset = dwarf
                .compile_units
                .iter()
                .find(|cu| section_offset >= cu.offset && section_offset < cu.offset + cu.size)
                .ok_or_else(|| anyhow!("Reference offset does not belong to any compile unit"))?;

            (cu_for_offset, section_offset - cu_for_offset.offset)
        }
        _ => bail!("Unsupported reference form {:#x}", attr.form()),
    };

    parse_die_at(cu_for_ref, offset_in_cu)
}
