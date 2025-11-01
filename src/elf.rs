use anyhow::{bail, Result};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::mem;
use std::ops::Bound::{Included, Unbounded};
use std::path::Path;
use std::path::PathBuf;

use memmap2::Mmap;
use nix::libc::{Elf64_Ehdr, Elf64_Shdr, Elf64_Sym};
use rustc_demangle::demangle;

use crate::dwarf::Dwarf;
use crate::types::{FileAddr, VirtAddr};

pub struct Elf {
    pub path: PathBuf,
    pub file_size: usize,
    pub mmap: Mmap,
    pub data_ptr: *const u8, // raw pointer to mapped data

    // ELF header
    pub header: Elf64_Ehdr,

    // Section headers
    pub section_headers: Vec<Elf64_Shdr>,
    // Map section name -> pointer to section header
    pub section_map: HashMap<String, *const Elf64_Shdr>,

    // Load bias (virtual address offset)
    pub load_bias: VirtAddr,

    // Symbol tables
    pub symbol_table: Vec<Elf64_Sym>,
    pub symbol_name_map: HashMap<String, Vec<*const Elf64_Sym>>,
    // Map from [start,end) range -> symbol pointer
    pub symbol_addr_map: BTreeMap<(FileAddr, FileAddr), *const Elf64_Sym>,

    // DWARF debugging information
    pub dwarf_data: Option<Box<Dwarf>>,
}

/// Extract the symbol type from st_info (lower 4 bits)
#[inline]
pub fn elf64_st_type(st_info: u8) -> u8 {
    st_info & 0xf
}

pub const STT_TLS: u8 = 6;
pub const STT_FUNC: u8 = 2;

impl PartialEq for Elf {
    fn eq(&self, other: &Self) -> bool {
        (self as *const _) == (other as *const _)
    }
}

impl Eq for Elf {}

impl Elf {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let file = File::open(&path_buf)?;
        let file_size = file.metadata()?.len() as usize;

        // Memory map the whole file as read-only
        let mmap = unsafe { Mmap::map(&file)? };
        let data_ptr = mmap.as_ptr();

        // Check file size is enough to contain ELF header
        if file_size < std::mem::size_of::<Elf64_Ehdr>() {
            bail!("File too small for ELF header");
        }

        // SAFETY: We trust the ELF file layout and alignment here.
        let header = unsafe {
            let mut hdr = std::mem::zeroed();
            std::ptr::copy_nonoverlapping(
                data_ptr,
                &mut hdr as *mut _ as *mut u8,
                std::mem::size_of::<Elf64_Ehdr>(),
            );
            hdr
        };

        Ok(Self {
            path: path_buf,
            file_size,
            data_ptr,
            mmap,
            header,

            section_headers: Vec::new(),
            section_map: HashMap::new(),

            load_bias: VirtAddr(0),

            symbol_table: Vec::new(),
            symbol_name_map: HashMap::new(),
            symbol_addr_map: BTreeMap::new(),
            dwarf_data: None,
        })
    }

    pub fn init(&mut self) -> Result<()> {
        self.parse_section_headers()?;
        self.build_section_map()?;
        self.parse_symbol_table()?;
        self.build_symbol_maps()?;
        self.dwarf_data = Some(Dwarf::new(self)?);
        Ok(())
    }

    pub fn notify_loaded(&mut self, address: VirtAddr) {
        self.load_bias = address;
    }

    /// Returns the section header that contains the given file address, or None.
    pub fn get_section_containing_addr(&self, addr: FileAddr) -> Option<&Elf64_Shdr> {
        // Return None if the address belongs to a different ELF file
        if let Some(elf) = addr.elf_file() {
            if elf as *const Elf != self as *const Elf {
                return None;
            }
        } else {
            return None;
        }

        // Find the section whose address range contains addr.addr()
        self.section_headers.iter().find(|section| {
            let start = section.sh_addr;
            let end = section.sh_addr + section.sh_size;
            start <= addr.addr() && addr.addr() < end
        })
    }

    /// Returns the section header that contains the given virtual address, or None.
    pub fn get_section_containing_addr_virt(&self, addr: VirtAddr) -> Option<&Elf64_Shdr> {
        let target_addr = addr.0;

        self.section_headers.iter().find(|section| {
            let start = self.load_bias.0 + section.sh_addr;
            let end = start + section.sh_size;
            start <= target_addr && target_addr < end
        })
    }

    pub fn parse_section_headers(&mut self) -> Result<()> {
        let header = &self.header;

        // SAFETY: the mmap is assumed to be valid and large enough
        let shoff = header.e_shoff as usize;
        let entsize = header.e_shentsize as usize;
        let mut count = header.e_shnum as usize;

        if count == 0 && entsize != 0 {
            // ELF Extension: section header count stored in sh_size of first header
            let first_header_ptr = unsafe { self.data_ptr.add(shoff) as *const Elf64_Shdr };

            if first_header_ptr.is_null() {
                bail!("Invalid section header offset");
            }

            unsafe {
                count = (*first_header_ptr).sh_size as usize;
            }
        }

        if count == 0 || entsize != mem::size_of::<Elf64_Shdr>() {
            bail!("Invalid section header count or size");
        }

        let section_data_start = unsafe { self.data_ptr.add(shoff) };
        let section_slice =
            unsafe { std::slice::from_raw_parts(section_data_start as *const Elf64_Shdr, count) };

        self.section_headers = section_slice.to_vec();
        Ok(())
    }

    pub fn get_section_name(&self, section_index: usize) -> Option<&str> {
        let shstrndx = self.header.e_shstrndx as usize;
        if shstrndx >= self.section_headers.len() || section_index >= self.section_headers.len() {
            return None;
        }

        // Section header string table section
        let shstr_section = &self.section_headers[shstrndx];

        let sh_name_offset = self.section_headers[section_index].sh_name as usize;
        let str_offset = shstr_section.sh_offset as usize + sh_name_offset;

        if str_offset >= self.file_size {
            return None;
        }

        unsafe {
            let ptr = self.data_ptr.add(str_offset);
            let c_str = std::ffi::CStr::from_ptr(ptr as *const i8);
            c_str.to_str().ok()
        }
    }

    pub fn build_section_map(&mut self) -> Result<()> {
        for (i, section) in self.section_headers.iter().enumerate() {
            if let Some(name) = self.get_section_name(i) {
                self.section_map
                    .insert(name.to_string(), section as *const _);
            }
        }
        Ok(())
    }

    fn get_section(&self, name: &str) -> Option<&Elf64_Shdr> {
        self.section_map.get(name).map(|&ptr| unsafe { &*ptr })
    }

    fn parse_symbol_table(&mut self) -> Result<()> {
        // Try to get .symtab first
        let symtab_section = self
            .get_section(".symtab")
            .or_else(|| self.get_section(".dynsym"));

        let symtab = match symtab_section {
            Some(sec) => sec,
            None => {
                // No symbol table found, do nothing
                return Ok(());
            }
        };

        let entsize = symtab.sh_entsize as usize;
        let size = symtab.sh_size as usize;
        let offset = symtab.sh_offset as usize;

        if entsize == 0 {
            bail!("Symbol entry size is zero");
        }
        if size % entsize != 0 {
            bail!("Symbol section size is not multiple of entry size");
        }

        let count = size / entsize;

        // Resize symbol_table Vec
        self.symbol_table.resize(count, unsafe { mem::zeroed() });

        // Copy raw bytes from mmap to symbol_table memory
        // Safety:
        // - mmap contains the full file, offset+size checked by ELF validity
        // - symbol_table has enough space after resize
        unsafe {
            let src_ptr = self.data_ptr.add(offset);
            let dst_ptr = self.symbol_table.as_mut_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size);
        }

        Ok(())
    }

    pub fn build_symbol_maps(&mut self) -> Result<()> {
        for symbol in &self.symbol_table {
            // Clone mangled_name early as a String, breaking borrow link to self
            let mangled_name = self.get_string(symbol.st_name as usize).to_owned();
            if mangled_name.is_empty() {
                continue;
            }

            let demangled_name = {
                let demangled = demangle(&mangled_name).to_string();
                if demangled == mangled_name {
                    mangled_name.clone()
                } else {
                    demangled
                }
            };

            // Now no immutable borrows remain, safe to mutably borrow self
            self.symbol_name_map
                .entry(demangled_name.clone())
                .or_default()
                .push(symbol as *const _);

            if demangled_name != mangled_name {
                self.symbol_name_map
                    .entry(mangled_name)
                    .or_default()
                    .push(symbol as *const _);
            }

            let st_value = symbol.st_value;
            let st_name = symbol.st_name;
            let st_size = symbol.st_size;
            let st_type = elf64_st_type(symbol.st_info);

            if st_value != 0 && st_name != 0 && st_type != STT_TLS {
                let start = FileAddr::from(self, st_value);
                let end = FileAddr::from(self, st_value + st_size);
                self.symbol_addr_map
                    .insert((start, end), symbol as *const _);
            }
        }
        Ok(())
    }

    /// Returns a string slice from the string table at the given index.
    /// Falls back to ".dynstr" if ".strtab" not found. Returns empty string if neither exists.
    pub fn get_string(&self, index: usize) -> &str {
        let opt_strtab = self
            .get_section(".strtab")
            .or_else(|| self.get_section(".dynstr"));

        if let Some(strtab) = opt_strtab {
            let start = unsafe { self.data_ptr.add(strtab.sh_offset as usize + index) };

            // SAFETY: We assume that the ELF file and its string table are valid,
            // and that the string at `index` is null-terminated.
            // We'll create a CStr from the pointer and convert to &str.
            unsafe {
                // Find the length of the null-terminated string
                let c_str = std::ffi::CStr::from_ptr(start as *const i8);
                c_str.to_str().unwrap_or("")
            }
        } else {
            ""
        }
    }

    pub fn get_section_start_address(&self, name: &str) -> Option<FileAddr> {
        self.get_section(name)
            .map(|sect| FileAddr::from(self, sect.sh_addr))
    }

    pub fn get_symbols_by_name(&self, name: &str) -> Vec<&Elf64_Sym> {
        if let Some(symbols) = self.symbol_name_map.get(name) {
            symbols
                .iter()
                .map(|&ptr| unsafe { &*ptr }) // Convert *const Elf64_Sym to &Elf64_Sym
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_symbol_at_address(&self, address: FileAddr) -> Option<&Elf64_Sym> {
        if address.elf_file()? != self {
            return None;
        }

        let null_addr = FileAddr::from(self, 0);

        self.symbol_addr_map
            .get(&(address, null_addr))
            .map(|&ptr| unsafe { &*ptr })
    }

    pub fn get_symbol_at_address_virt(&self, address: VirtAddr) -> Option<&Elf64_Sym> {
        self.get_symbol_at_address(address.to_file_addr(self))
    }

    pub fn get_symbol_containing_address(&self, address: FileAddr) -> Option<&Elf64_Sym> {
        if address.elf_file()? != self || self.symbol_addr_map.is_empty() {
            return None;
        }

        let null_addr = FileAddr::from(self, 0);

        // lower_bound equivalent: range starting from key
        let mut range = self
            .symbol_addr_map
            .range((Included((address, null_addr)), Unbounded));

        if let Some((&(start, _), &ptr)) = range.next() {
            if start == address {
                return Some(unsafe { &*ptr });
            }
        } else {
            return None;
        }

        // check the previous entry if any
        let mut prev_range = self
            .symbol_addr_map
            .range((Unbounded, Included((address, null_addr))));
        if let Some((&(start, end), &ptr)) = prev_range.next_back() {
            if start < address && address < end {
                return Some(unsafe { &*ptr });
            }
        }

        None
    }

    pub fn get_symbol_containing_address_virt(&self, address: VirtAddr) -> Option<&Elf64_Sym> {
        self.get_symbol_containing_address(address.to_file_addr(self))
    }

    pub fn get_section_bytes(&self, name: &str) -> Option<Vec<u8>> {
        let section = self.get_section(name)?;
        let offset = section.sh_offset as usize;
        let size = section.sh_size as usize;

        if offset + size > self.file_size {
            return None;
        }

        unsafe {
            let ptr = self.data_ptr.add(offset);
            Some(std::slice::from_raw_parts(ptr, size).to_vec())
        }
    }

    pub fn dwarf(&self) -> &Dwarf {
        self.dwarf_data
            .as_ref()
            .expect("DWARF data not initialized")
    }
}
