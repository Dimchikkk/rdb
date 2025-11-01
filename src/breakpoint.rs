use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{bail, Result};

use crate::dwarf::{
    Die, LineTable, LineTableEntry, DW_AT_LOW_PC, DW_AT_RANGES, DW_TAG_INLINED_SUBROUTINE,
};
use crate::elf::Elf;
use crate::process::Process;
use crate::stoppoint::Stoppoint;
use crate::types::{FileAddr, VirtAddr};

static NEXT_BREAKPOINT_ID: AtomicI32 = AtomicI32::new(1);

#[derive(Clone, Debug)]
pub enum BreakpointKind {
    Address { address: VirtAddr },
    Function { name: String },
    Line { file: PathBuf, line: u64 },
}

#[derive(Clone, Debug)]
pub struct Breakpoint {
    id: i32,
    kind: BreakpointKind,
    site_ids: Vec<i32>,
    is_enabled: bool,
    is_hardware: bool,
    is_internal: bool,
}

impl Breakpoint {
    pub fn new(kind: BreakpointKind, is_hardware: bool, is_internal: bool) -> Self {
        let id = if is_internal {
            -1
        } else {
            NEXT_BREAKPOINT_ID.fetch_add(1, Ordering::SeqCst)
        };

        Self {
            id,
            kind,
            site_ids: Vec::new(),
            is_enabled: false,
            is_hardware,
            is_internal,
        }
    }

    pub fn id(&self) -> i32 {
        self.id
    }

    pub fn kind(&self) -> &BreakpointKind {
        &self.kind
    }

    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    pub fn sites(&self) -> &[i32] {
        &self.site_ids
    }

    pub fn resolve(&mut self, process: &mut Process, elf: &Elf) -> Result<()> {
        let kind = self.kind.clone();
        match kind {
            BreakpointKind::Address { address } => {
                self.add_site(process, address)?;
            }
            BreakpointKind::Function { name } => {
                self.resolve_function(process, elf, &name)?;
            }
            BreakpointKind::Line { file, line } => {
                self.resolve_line(process, elf, &file, line)?;
            }
        }
        Ok(())
    }

    pub fn enable(&mut self, process: &mut Process, elf: &Elf) -> Result<()> {
        self.resolve(process, elf)?;
        self.apply_enabled_state(process, true)?;
        self.is_enabled = true;
        Ok(())
    }

    pub fn disable(&mut self, process: &mut Process) -> Result<()> {
        self.apply_enabled_state(process, false)?;
        self.is_enabled = false;
        Ok(())
    }

    pub fn remove_sites(&mut self, process: &mut Process) -> Result<()> {
        while let Some(site_id) = self.site_ids.pop() {
            process
                .breakpoint_sites
                .remove_by_id(&mut process.registers, site_id)?;
        }
        Ok(())
    }

    fn apply_enabled_state(&self, process: &mut Process, enable: bool) -> Result<()> {
        for site_id in &self.site_ids {
            if let Some(site) = process.breakpoint_sites.get_by_id_mut(*site_id) {
                if enable {
                    site.enable(&mut process.registers)?;
                } else {
                    site.disable(&mut process.registers)?;
                }
            }
        }
        Ok(())
    }

    fn add_site(&mut self, process: &mut Process, addr: VirtAddr) -> Result<()> {
        if self.site_ids.iter().any(|&id| {
            process
                .breakpoint_sites
                .get_by_id_mut(id)
                .map_or(false, |site| site.address == addr)
        }) {
            return Ok(());
        }

        let site_id = process.create_breakpoint_site(
            addr,
            self.is_hardware,
            self.is_internal,
            if self.is_internal {
                None
            } else {
                Some(self.id)
            },
        )?;

        if !self.site_ids.contains(&site_id) {
            self.site_ids.push(site_id);
        }

        if self.is_enabled {
            if let Some(site) = process.breakpoint_sites.get_by_id_mut(site_id) {
                site.enable(&mut process.registers)?;
            }
        }

        Ok(())
    }

    fn resolve_function(&mut self, process: &mut Process, elf: &Elf, name: &str) -> Result<()> {
        let dwarf = elf.dwarf();
        let mut resolved = false;

        let dies = dwarf.find_functions(name)?;
        for die in dies {
            self.resolve_function_die(process, &die)?;
            resolved = true;
        }

        if !resolved {
            let symbols = elf.get_symbols_by_name(name);
            for sym in symbols {
                let file_addr = FileAddr::from(elf, sym.st_value);
                let adjusted_addr = adjust_function_entry(elf, file_addr)?;
                let virt = adjusted_addr.to_virt_addr();
                if virt.0 != 0 {
                    if std::env::var_os("RDB_DEBUG").is_some() {
                        eprintln!(
                            "resolve_function symbol: {} -> 0x{:x} (file=0x{:x})",
                            name,
                            virt.0,
                            adjusted_addr.addr()
                        );
                    }
                    self.add_site(process, virt)?;
                    resolved = true;
                }
            }
        }

        if !resolved {
            bail!("Function '{name}' not found");
        }
        Ok(())
    }

    fn resolve_function_die(&mut self, process: &mut Process, die: &Die) -> Result<()> {
        let file_addr = die.low_pc()?;
        let virt = if die.tag() == Some(DW_TAG_INLINED_SUBROUTINE) {
            file_addr.to_virt_addr()
        } else {
            let mut resolved_addr = file_addr;
            if let Some(line_table) = die.cu().lines()? {
                resolved_addr = skip_prologue_address(&line_table, file_addr)?;
            }
            resolved_addr.to_virt_addr()
        };

        if virt.0 == 0 {
            bail!("Could not translate function address to virtual address");
        }

        if std::env::var_os("RDB_DEBUG").is_some() {
            let name = die.name().ok().flatten().unwrap_or_default();
            eprintln!("resolve_function_die: {} -> 0x{:x}", name, virt.0);
        }

        self.add_site(process, virt)
    }

    fn resolve_line(
        &mut self,
        process: &mut Process,
        elf: &Elf,
        file: &PathBuf,
        line: u64,
    ) -> Result<()> {
        let dwarf = elf.dwarf();
        let mut resolved = false;

        for cu in &dwarf.compile_units {
            if let Some(line_table) = cu.lines()? {
                let entries = line_table.get_entries_by_line(file, line);
                for entry in entries {
                    let adjusted = adjust_line_entry(elf, &line_table, entry)?;
                    let virt = adjusted.address.to_virt_addr();
                    if virt.0 != 0 {
                        self.add_site(process, virt)?;
                        resolved = true;
                    }
                }
            }
        }

        if !resolved {
            bail!("No line information for {}:{}", file.display(), line);
        }
        Ok(())
    }
}

fn adjust_line_entry(
    elf: &Elf,
    line_table: &LineTable,
    entry: LineTableEntry,
) -> Result<LineTableEntry> {
    let file_addr = entry.address;
    let dwarf = elf.dwarf();
    let stack = dwarf.inline_stack_at_address(file_addr)?;
    if let Some(first) = stack.first() {
        let no_inline = stack.len() == 1;
        let contains_range = first.contains(DW_AT_RANGES);
        let contains_low = first.contains(DW_AT_LOW_PC);
        if no_inline && (contains_range || contains_low) && first.low_pc()? == file_addr {
            if let Some(next) = line_table.entry_after(file_addr) {
                return Ok(next);
            }
        }
    }

    Ok(entry)
}

fn adjust_function_entry(elf: &Elf, address: FileAddr) -> Result<FileAddr> {
    let dwarf = elf.dwarf();
    if let Some(cu) = dwarf.compile_unit_containing_address(address)? {
        if let Some(line_table) = cu.lines()? {
            return skip_prologue_address(&line_table, address);
        }
    }
    Ok(address)
}

fn skip_prologue_address(line_table: &LineTable, address: FileAddr) -> Result<FileAddr> {
    let mut current = address;
    if let Some(entry) = line_table.get_entry_by_address(address) {
        if entry.prologue_end {
            return Ok(entry.address);
        }
        current = entry.address;
    }

    if let Some(next) = line_table.entry_after(current) {
        return Ok(next.address);
    }

    Ok(current)
}

pub struct BreakpointCollection {
    breakpoints: Vec<Breakpoint>,
}

impl BreakpointCollection {
    pub fn new() -> Self {
        Self {
            breakpoints: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Breakpoint> {
        self.breakpoints.iter()
    }

    pub fn push(&mut self, breakpoint: Breakpoint) -> &mut Breakpoint {
        self.breakpoints.push(breakpoint);
        self.breakpoints.last_mut().unwrap()
    }

    pub fn get_by_id_mut(&mut self, id: i32) -> Option<&mut Breakpoint> {
        self.breakpoints.iter_mut().find(|bp| bp.id == id)
    }

    pub fn remove_by_id(&mut self, id: i32) -> Option<Breakpoint> {
        if let Some(pos) = self.breakpoints.iter().position(|bp| bp.id == id) {
            Some(self.breakpoints.remove(pos))
        } else {
            None
        }
    }
}
