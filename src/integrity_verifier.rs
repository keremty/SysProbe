#![allow(non_snake_case)]

use core::mem;
use core::ptr;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;
use winapi::um::processthreadsapi::GetProcessId;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER,
    IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_NT_SIGNATURE,
};
use xxhash_rust::xxh3::xxh3_64;

use crate::memory_region_analysis::{MemoryRegion, ModuleInfo, RegionBacking};
use crate::nt::nt_success;
use crate::syscalls::nt_read_virtual_memory;

const MAX_USER_ADDRESS: usize = 0x0000_7FFF_FFFF_FFFF;
const RELOC_TYPE_ABSOLUTE: u16 = 0;
const RELOC_TYPE_HIGHLOW: u16 = 3;
const RELOC_TYPE_DIR64: u16 = 10;

#[derive(Debug)]
pub enum AnalysisError {
    MissingPath,
    IoError,
    ParseError(&'static str),
    ReadFailed { addr: usize, size: usize, status: i32 },
    DataUnavailable(&'static str),
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct IntegrityOptions {
    pub inline_check_count: usize,
    pub inline_check_bytes: usize,
    pub chunk_check_count: usize,
    pub chunk_size: usize,
    pub max_diffs: usize,
    pub full_hash: bool,
    pub reloc_mask: bool,
}

impl Default for IntegrityOptions {
    fn default() -> Self {
        Self {
            inline_check_count: 64,
            inline_check_bytes: 16,
            chunk_check_count: 64,
            chunk_size: 4096,
            max_diffs: 128,
            full_hash: false,
            reloc_mask: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrityDiff {
    pub rva: u32,
    pub disk_bytes: Vec<u8>,
    pub mem_bytes: Vec<u8>,
    pub reason: &'static str,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrityReport {
    pub pid: u32,
    pub module_base: usize,
    pub module_path: String,
    pub text_rva: u32,
    pub text_size: u32,
    pub inline_diffs: Vec<IntegrityDiff>,
    pub chunk_diffs: Vec<IntegrityDiff>,
    pub full_hash_match: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
struct SectionInfo {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

#[derive(Debug, Clone)]
struct DiskPe {
    bytes: Vec<u8>,
    sections: Vec<SectionInfo>,
    export_rva: u32,
    export_size: u32,
    reloc_rva: u32,
    reloc_size: u32,
    text: SectionInfo,
    relocs: RelocTable,
}

#[derive(Debug, Clone, Copy)]
struct ExportSymbol {
    rva: u32,
}

#[derive(Debug, Clone)]
struct RelocEntry {
    rva: u32,
    size: u8,
}

#[derive(Debug, Clone, Default)]
struct RelocTable {
    entries: Vec<RelocEntry>,
}

impl RelocTable {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn mask_chunk(&self, base_rva: u32, buf: &mut [u8]) {
        if self.entries.is_empty() {
            return;
        }
        let end_rva = base_rva.saturating_add(buf.len() as u32);
        let mut left = 0usize;
        let mut right = self.entries.len();
        while left < right {
            let mid = left + (right - left) / 2;
            if self.entries[mid].rva < base_rva {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        for entry in self.entries[left..].iter() {
            if entry.rva >= end_rva {
                break;
            }
            let offset = entry.rva.saturating_sub(base_rva) as usize;
            let size = entry.size as usize;
            for i in 0..size {
                if offset + i < buf.len() {
                    buf[offset + i] = 0;
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct IntegrityScratch {
    disk_cache: HashMap<String, DiskPe>,
}

pub fn verify_module(
    process: HANDLE,
    module: &ModuleInfo,
    options: IntegrityOptions,
) -> Result<IntegrityReport, AnalysisError> {
    let mut scratch = IntegrityScratch::default();
    verify_module_with_cache(process, module, options, &mut scratch, None)
}

pub fn verify_module_with_cache(
    process: HANDLE,
    module: &ModuleInfo,
    options: IntegrityOptions,
    scratch: &mut IntegrityScratch,
    memory_map: Option<&[MemoryRegion]>,
) -> Result<IntegrityReport, AnalysisError> {
    let pid = unsafe { GetProcessId(process) };
    let module_path = module
        .full_name
        .clone()
        .or_else(|| module.base_name.clone())
        .ok_or(AnalysisError::MissingPath)?;

    let disk = load_disk_pe_cached(&module_path, scratch)?;
    let text_rva = disk.text.virtual_address;
    let text_size = disk.text.virtual_size;

    let exports = parse_exports(disk)?;
    let inline_diffs = compare_inline_exports(
        process,
        module.base_address,
        disk,
        &exports,
        options,
        memory_map,
    )?;

    let chunk_diffs = compare_text_chunks(
        process,
        module.base_address,
        disk,
        options,
        &module_path,
    )?;

    let full_hash_match = if options.full_hash {
        Some(compare_full_text_hash(process, module.base_address, disk, options)?)
    } else {
        None
    };

    Ok(IntegrityReport {
        pid,
        module_base: module.base_address,
        module_path,
        text_rva,
        text_size,
        inline_diffs,
        chunk_diffs,
        full_hash_match,
    })
}

fn load_disk_pe_cached<'a>(
    path: &str,
    scratch: &'a mut IntegrityScratch,
) -> Result<&'a DiskPe, AnalysisError> {
    if scratch.disk_cache.contains_key(path) {
        return Ok(scratch.disk_cache.get(path).unwrap());
    }

    let disk = load_disk_pe(path)?;
    scratch.disk_cache.insert(path.to_string(), disk);
    Ok(scratch.disk_cache.get(path).unwrap())
}

fn load_disk_pe(path: &str) -> Result<DiskPe, AnalysisError> {
    let bytes = fs::read(Path::new(path)).map_err(|_| AnalysisError::IoError)?;
    if bytes.len() < mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err(AnalysisError::ParseError("DOS header too small"));
    }

    let dos: IMAGE_DOS_HEADER = unsafe { ptr::read_unaligned(bytes.as_ptr() as *const _) };
    if dos.e_magic != 0x5A4D {
        return Err(AnalysisError::ParseError("Invalid DOS magic"));
    }

    let nt_offset = dos.e_lfanew as usize;
    if nt_offset + mem::size_of::<IMAGE_NT_HEADERS64>() > bytes.len() {
        return Err(AnalysisError::ParseError("NT header too small"));
    }
    let nt: IMAGE_NT_HEADERS64 =
        unsafe { ptr::read_unaligned(bytes.as_ptr().add(nt_offset) as *const _) };
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return Err(AnalysisError::ParseError("Invalid NT signature"));
    }

    let section_count = nt.FileHeader.NumberOfSections as usize;
    let section_table = nt_offset + mem::size_of::<IMAGE_NT_HEADERS64>();
    let table_size = section_count * mem::size_of::<IMAGE_SECTION_HEADER>();
    if section_table + table_size > bytes.len() {
        return Err(AnalysisError::ParseError("Section table too small"));
    }

    let mut sections = Vec::new();
    let mut text_section = None;
    let mut offset = section_table;
    for _ in 0..section_count {
        let header: IMAGE_SECTION_HEADER =
            unsafe { ptr::read_unaligned(bytes.as_ptr().add(offset) as *const _) };
        let info = SectionInfo {
            name: header.Name,
            virtual_address: header.VirtualAddress,
            virtual_size: unsafe { *header.Misc.VirtualSize() },
            raw_ptr: header.PointerToRawData,
            raw_size: header.SizeOfRawData,
        };
        if &info.name[..5] == b".text" {
            text_section = Some(info);
        }
        sections.push(info);
        offset += mem::size_of::<IMAGE_SECTION_HEADER>();
    }

    let text = text_section.ok_or(AnalysisError::ParseError("Text section missing"))?;
    let export_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let reloc_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

    let mut disk = DiskPe {
        bytes,
        sections,
        export_rva: export_dir.VirtualAddress,
        export_size: export_dir.Size,
        reloc_rva: reloc_dir.VirtualAddress,
        reloc_size: reloc_dir.Size,
        text,
        relocs: RelocTable::default(),
    };

    disk.relocs = parse_relocations(&disk);
    Ok(disk)
}

fn parse_exports(disk: &DiskPe) -> Result<Vec<ExportSymbol>, AnalysisError> {
    if disk.export_rva == 0 || disk.export_size == 0 {
        return Ok(Vec::new());
    }

    let export_offset = rva_to_file_offset(disk, disk.export_rva)
        .ok_or(AnalysisError::ParseError("Invalid export RVA"))?;
    if export_offset + mem::size_of::<IMAGE_EXPORT_DIRECTORY>() > disk.bytes.len() {
        return Err(AnalysisError::ParseError("Export directory too small"));
    }

    let export_dir: IMAGE_EXPORT_DIRECTORY = unsafe {
        ptr::read_unaligned(disk.bytes.as_ptr().add(export_offset) as *const _)
    };

    let func_count = export_dir.NumberOfFunctions as usize;
    if func_count == 0 {
        return Ok(Vec::new());
    }

    let func_rva_list = rva_to_file_offset(disk, export_dir.AddressOfFunctions)
        .ok_or(AnalysisError::ParseError("Invalid functions RVA"))?;
    if func_rva_list + func_count * 4 > disk.bytes.len() {
        return Err(AnalysisError::ParseError("Functions list too small"));
    }

    let mut exports = Vec::new();
    for i in 0..func_count {
        let rva = u32::from_le_bytes([
            disk.bytes[func_rva_list + i * 4],
            disk.bytes[func_rva_list + i * 4 + 1],
            disk.bytes[func_rva_list + i * 4 + 2],
            disk.bytes[func_rva_list + i * 4 + 3],
        ]);
        if rva == 0 {
            continue;
        }
        exports.push(ExportSymbol { rva });
    }

    Ok(exports)
}

fn parse_relocations(disk: &DiskPe) -> RelocTable {
    if disk.reloc_rva == 0 || disk.reloc_size == 0 {
        return RelocTable::default();
    }

    let offset = match rva_to_file_offset(disk, disk.reloc_rva) {
        Some(o) => o,
        None => return RelocTable::default(),
    };

    let size = disk.reloc_size as usize;
    if offset + size > disk.bytes.len() {
        return RelocTable::default();
    }

    let text_start = disk.text.virtual_address;
    let text_end = text_start.saturating_add(disk.text.virtual_size);

    let data = &disk.bytes[offset..offset + size];
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    while cursor + 8 <= data.len() {
        let page_rva = u32::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        let block_size = u32::from_le_bytes([
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]) as usize;
        if block_size < 8 || cursor + block_size > data.len() {
            break;
        }

        let entry_count = (block_size - 8) / 2;
        let mut entry_off = cursor + 8;
        for _ in 0..entry_count {
            if entry_off + 2 > data.len() {
                break;
            }
            let raw = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
            let rtype = raw >> 12;
            let roffs = raw & 0x0FFF;
            entry_off += 2;

            if rtype == RELOC_TYPE_ABSOLUTE {
                continue;
            }

            let size = match rtype {
                RELOC_TYPE_DIR64 => 8,
                RELOC_TYPE_HIGHLOW => 4,
                _ => continue,
            };

            let rva = page_rva.saturating_add(roffs as u32);
            if rva < text_start || rva >= text_end {
                continue;
            }

            entries.push(RelocEntry { rva, size });
        }

        cursor = cursor.saturating_add(block_size);
    }

    entries.sort_by_key(|e| e.rva);
    RelocTable { entries }
}

fn compare_inline_exports(
    process: HANDLE,
    module_base: usize,
    disk: &DiskPe,
    exports: &[ExportSymbol],
    options: IntegrityOptions,
    memory_map: Option<&[MemoryRegion]>,
) -> Result<Vec<IntegrityDiff>, AnalysisError> {
    let mut diffs = Vec::new();
    let mut seen = HashSet::new();

    for export in exports.iter().take(options.inline_check_count) {
        if diffs.len() >= options.max_diffs {
            break;
        }

        if !seen.insert(export.rva) {
            continue;
        }

        let disk_offset = match rva_to_file_offset(disk, export.rva) {
            Some(o) => o,
            None => continue,
        };

        let length = options.inline_check_bytes;
        if disk_offset + length > disk.bytes.len() {
            continue;
        }

        let mut disk_bytes = disk.bytes[disk_offset..disk_offset + length].to_vec();
        let mut mem_bytes = read_process_bytes_exact(process, module_base + export.rva as usize, length)?;
        let hotpatch_allowed =
            is_hotpatch_jump(module_base, export.rva, disk, &mem_bytes, memory_map);

        if options.reloc_mask && !disk.relocs.is_empty() {
            disk.relocs.mask_chunk(export.rva, &mut disk_bytes);
            disk.relocs.mask_chunk(export.rva, &mut mem_bytes);
        }

        if disk_bytes != mem_bytes {
            diffs.push(IntegrityDiff {
                rva: export.rva,
                disk_bytes,
                mem_bytes,
                reason: if hotpatch_allowed {
                    "Hotpatch JMP within .text"
                } else {
                    "Inline prologue mismatch"
                },
                allowed: hotpatch_allowed,
            });
        }
    }

    Ok(diffs)
}

fn compare_text_chunks(
    process: HANDLE,
    module_base: usize,
    disk: &DiskPe,
    options: IntegrityOptions,
    module_path: &str,
) -> Result<Vec<IntegrityDiff>, AnalysisError> {
    let mut diffs = Vec::new();
    let text = disk.text;
    let text_size = text.virtual_size as usize;
    if text_size == 0 {
        return Ok(diffs);
    }

    let chunk_size = options.chunk_size.max(256);
    let max_chunks = text_size / chunk_size;
    if max_chunks == 0 {
        return Ok(diffs);
    }

    let mut seed = xxh3_64(module_path.as_bytes());
    for _ in 0..options.chunk_check_count {
        if diffs.len() >= options.max_diffs {
            break;
        }
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let idx = (seed as usize) % max_chunks;
        let rva = text.virtual_address as usize + idx * chunk_size;

        let disk_offset = match rva_to_file_offset(disk, rva as u32) {
            Some(o) => o,
            None => continue,
        };

        if disk_offset + chunk_size > disk.bytes.len() {
            continue;
        }

        let mut disk_chunk = disk.bytes[disk_offset..disk_offset + chunk_size].to_vec();
        let mut mem_chunk = read_process_bytes_exact(process, module_base + rva, chunk_size)?;

        if options.reloc_mask && !disk.relocs.is_empty() {
            disk.relocs.mask_chunk(rva as u32, &mut disk_chunk);
            disk.relocs.mask_chunk(rva as u32, &mut mem_chunk);
        }

        let disk_hash = xxh3_64(&disk_chunk);
        let mem_hash = xxh3_64(&mem_chunk);
        if disk_hash != mem_hash {
            let sample_len = 16usize.min(chunk_size);
            diffs.push(IntegrityDiff {
                rva: rva as u32,
                disk_bytes: disk_chunk[..sample_len].to_vec(),
                mem_bytes: mem_chunk[..sample_len].to_vec(),
                reason: "Chunk hash mismatch",
                allowed: false,
            });
        }
    }

    Ok(diffs)
}

fn compare_full_text_hash(
    process: HANDLE,
    module_base: usize,
    disk: &DiskPe,
    options: IntegrityOptions,
) -> Result<bool, AnalysisError> {
    let text = disk.text;
    let text_size = text.virtual_size as usize;
    if text_size == 0 {
        return Err(AnalysisError::DataUnavailable("Text size 0"));
    }

    let disk_offset = rva_to_file_offset(disk, text.virtual_address)
        .ok_or(AnalysisError::ParseError("Text offset missing"))?;
    if disk_offset + text_size > disk.bytes.len() {
        return Err(AnalysisError::ParseError("Text section too small on disk"));
    }

    let chunk = options.chunk_size.max(4096);
    let mut disk_hasher = Sha256::new();
    let mut remaining = text_size;
    let mut cursor = 0usize;
    while remaining > 0 {
        let size = remaining.min(chunk);
        let mut disk_chunk = disk.bytes[disk_offset + cursor..disk_offset + cursor + size].to_vec();
        if options.reloc_mask && !disk.relocs.is_empty() {
            disk.relocs.mask_chunk(text.virtual_address + cursor as u32, &mut disk_chunk);
        }
        disk_hasher.update(&disk_chunk);
        remaining = remaining.saturating_sub(size);
        cursor = cursor.saturating_add(size);
    }
    let disk_hash = disk_hasher.finalize();

    let mut mem_hasher = Sha256::new();
    let mut remaining = text_size;
    let mut cursor = 0usize;
    while remaining > 0 {
        let size = remaining.min(chunk);
        let mut mem_chunk = read_process_bytes_exact(process, module_base + text.virtual_address as usize + cursor, size)?;
        if options.reloc_mask && !disk.relocs.is_empty() {
            disk.relocs.mask_chunk(text.virtual_address + cursor as u32, &mut mem_chunk);
        }
        mem_hasher.update(&mem_chunk);
        remaining = remaining.saturating_sub(size);
        cursor = cursor.saturating_add(size);
    }
    let mem_hash = mem_hasher.finalize();

    Ok(disk_hash.as_slice() == mem_hash.as_slice())
}

fn read_process_bytes_exact(
    process: HANDLE,
    addr: usize,
    size: usize,
) -> Result<Vec<u8>, AnalysisError> {
    if addr == 0 || addr > MAX_USER_ADDRESS {
        return Err(AnalysisError::ReadFailed {
            addr,
            size,
            status: -1,
        });
    }

    let mut buf = vec![0u8; size];
    let mut read_len: usize = 0;
    let status = unsafe {
        nt_read_virtual_memory(
            process,
            addr as *mut c_void,
            buf.as_mut_ptr() as *mut c_void,
            size,
            &mut read_len as *mut usize,
        )
    };

    if !nt_success(status) || read_len < size {
        return Err(AnalysisError::ReadFailed { addr, size, status });
    }

    Ok(buf)
}

fn is_hotpatch_jump(
    module_base: usize,
    export_rva: u32,
    disk: &DiskPe,
    mem_bytes: &[u8],
    memory_map: Option<&[MemoryRegion]>,
) -> bool {
    if mem_bytes.is_empty() {
        return false;
    }

    let text_start = module_base.saturating_add(disk.text.virtual_address as usize);
    let text_end = text_start.saturating_add(disk.text.virtual_size as usize);
    if text_start == 0 || text_end <= text_start {
        return false;
    }

    let entry = module_base.saturating_add(export_rva as usize);
    let opcode = mem_bytes[0];

    let target = if opcode == 0xE9 && mem_bytes.len() >= 5 {
        let disp = i32::from_le_bytes([mem_bytes[1], mem_bytes[2], mem_bytes[3], mem_bytes[4]]);
        (entry as isize).wrapping_add(5).wrapping_add(disp as isize) as usize
    } else if opcode == 0xEB && mem_bytes.len() >= 2 {
        let disp = mem_bytes[1] as i8 as isize;
        (entry as isize).wrapping_add(2).wrapping_add(disp) as usize
    } else {
        return false;
    };

    if target < text_start || target >= text_end {
        return false;
    }

    if let Some(map) = memory_map {
        let backing = region_backing(map, target);
        return backing == Some(RegionBacking::Image);
    }

    true
}

fn region_backing(map: &[MemoryRegion], addr: usize) -> Option<RegionBacking> {
    let region = find_region_for_address(map, addr)?;
    match region.region_type {
        t if (t & 0x0100_0000) != 0 => Some(RegionBacking::Image),
        t if (t & 0x0004_0000) != 0 => Some(RegionBacking::Mapped),
        t if (t & 0x0002_0000) != 0 => Some(RegionBacking::Private),
        _ => Some(RegionBacking::Unknown),
    }
}

fn find_region_for_address(map: &[MemoryRegion], addr: usize) -> Option<&MemoryRegion> {
    let mut left = 0usize;
    let mut right = map.len();
    while left < right {
        let mid = left + (right - left) / 2;
        let region = &map[mid];
        let start = region.base_address;
        let end = start.saturating_add(region.region_size);
        if addr < start {
            right = mid;
        } else if addr >= end {
            left = mid + 1;
        } else {
            return Some(region);
        }
    }
    None
}

fn rva_to_file_offset(disk: &DiskPe, rva: u32) -> Option<usize> {
    for section in &disk.sections {
        let start = section.virtual_address;
        let size = section.virtual_size.max(section.raw_size);
        let end = start.saturating_add(size);
        if rva >= start && rva < end {
            let delta = rva.saturating_sub(start) as usize;
            return Some(section.raw_ptr as usize + delta);
        }
    }
    None
}
