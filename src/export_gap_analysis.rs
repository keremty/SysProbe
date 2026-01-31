//! Export Gap Analysis
//! Analyzes PE export tables to identify memory regions between exports.

use winapi::ctypes::c_void;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64,
};

use crate::hash::fnv1a_hash;

const PRELOADED_DLL_HASHES: &[u64] = &[
    fnv1a_hash(b"uxtheme.dll"),
    fnv1a_hash(b"dwmapi.dll"),
    fnv1a_hash(b"oleaut32.dll"),
    fnv1a_hash(b"propsys.dll"),
    fnv1a_hash(b"shcore.dll"),
    fnv1a_hash(b"shlwapi.dll"),
    fnv1a_hash(b"clbcatq.dll"),
    fnv1a_hash(b"wintypes.dll"),
    fnv1a_hash(b"msctf.dll"),
];

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_init_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
}

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct PebLdrData {
    length: u32,
    initialized: u32,
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry,
    in_memory_order_module_list: ListEntry,
    in_init_order_module_list: ListEntry,
}

#[repr(C)]
struct Peb {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: [u8; 1],
    reserved3: [*mut c_void; 2],
    ldr: *mut PebLdrData,
}

#[derive(Debug, Clone, Copy)]
pub struct ExportGapInfo {
    pub module_base: usize,
    pub export_address: usize,
    pub export_rva: u32,
    pub gap_size: usize,
    pub export_name_rva: u32,
    pub is_redirected: bool,
}

#[derive(Debug, Clone)]
pub struct ModuleAnalysisResult {
    pub module_base: usize,
    pub module_hash: u64,
    pub export_gaps: Vec<ExportGapInfo>,
    pub total_exports: usize,
    pub redirected_count: usize,
}

#[inline(always)]
unsafe fn get_peb() -> *mut Peb {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags)
    );
    peb
}

#[inline(always)]
fn hash_wide_string_ci(s: *const u16, len: usize) -> u64 {
    use crate::hash::{FNV_OFFSET, FNV_PRIME, HASH_SALT, HASH_TAG};

    let mut hash = FNV_OFFSET;

    for i in 0..len {
        let mut c = unsafe { *s.add(i) } as u8;

        if c.is_ascii_uppercase() {
            c = c.to_ascii_lowercase();
        }
        hash ^= c as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    let tag_mix = HASH_TAG.rotate_left((len as u32) & 31);
    hash ^ HASH_SALT ^ tag_mix
}

unsafe fn find_loaded_module_by_hash(target_hash: u64) -> Option<*mut c_void> {
    let peb = get_peb();
    if peb.is_null() {
        return None;
    }

    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return None;
    }

    let list_head = &(*ldr).in_load_order_module_list as *const ListEntry;
    let mut current = (*list_head).flink;

    while !std::ptr::eq(current, list_head as *mut ListEntry) {
        let entry = current as *const LdrDataTableEntry;

        let name = &(*entry).base_dll_name;
        if !name.buffer.is_null() && name.length > 0 {
            let char_count = (name.length / 2) as usize;
            let hash = hash_wide_string_ci(name.buffer, char_count);

            if hash == target_hash {
                let base = (*entry).dll_base;
                if !base.is_null() {
                    return Some(base);
                }
            }
        }

        current = (*current).flink;
    }

    None
}

unsafe fn detect_redirection_at_export(addr: *mut u8) -> bool {
    if addr.is_null() {
        return false;
    }
    let b = core::ptr::read_volatile(addr);
    b == 0xE9 || b == 0xCC
}

unsafe fn analyze_module_exports(
    module: *mut c_void,
    min_gap_size: usize,
) -> Option<Vec<ExportGapInfo>> {
    let dos = module as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D {
        return None;
    }

    let nt = (module as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != 0x4550 {
        return None;
    }

    let exp_rva =
        (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
    let exp_size = (*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
    if exp_rva == 0 {
        return None;
    }

    let exp = (module as usize + exp_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let num_funcs = (*exp).NumberOfFunctions as usize;
    let num_names = (*exp).NumberOfNames as usize;

    if num_funcs == 0 {
        return None;
    }

    let funcs = (module as usize + (*exp).AddressOfFunctions as usize) as *const u32;
    let names = (module as usize + (*exp).AddressOfNames as usize) as *const u32;
    let ordinals = (module as usize + (*exp).AddressOfNameOrdinals as usize) as *const u16;

    let exp_start = exp_rva as usize;
    let exp_end = exp_start + exp_size as usize;

    const MAX_EXPORTS: usize = 512;
    let mut rvas: [(u32, u32); MAX_EXPORTS] = [(0, 0); MAX_EXPORTS];
    let mut rva_count = 0;

    for i in 0..num_funcs.min(MAX_EXPORTS) {
        let rva = *funcs.add(i);
        if rva == 0 {
            continue;
        }

        if (rva as usize) >= exp_start && (rva as usize) < exp_end {
            continue;
        }

        let mut name_rva = 0u32;
        for j in 0..num_names.min(MAX_EXPORTS) {
            if *ordinals.add(j) as usize == i {
                name_rva = *names.add(j);
                break;
            }
        }

        rvas[rva_count] = (rva, name_rva);
        rva_count += 1;
    }

    if rva_count < 2 {
        return None;
    }

    for i in 0..rva_count {
        for j in 0..rva_count - 1 - i {
            if rvas[j].0 > rvas[j + 1].0 {
                rvas.swap(j, j + 1);
            }
        }
    }

    let mut results = Vec::new();

    for i in 0..rva_count - 1 {
        let (rva, name_rva) = rvas[i];
        let next_rva = rvas[i + 1].0;
        let gap = (next_rva - rva) as usize;

        let export_addr = (module as usize + rva as usize) as *mut u8;
        let is_redirected = detect_redirection_at_export(export_addr);

        if gap >= min_gap_size {
            results.push(ExportGapInfo {
                module_base: module as usize,
                export_address: export_addr as usize,
                export_rva: rva,
                gap_size: gap,
                export_name_rva: name_rva,
                is_redirected,
            });
        }
    }

    Some(results)
}

pub unsafe fn get_export_name(module_base: usize, name_rva: u32) -> Option<String> {
    if name_rva == 0 {
        return None;
    }
    let name_ptr = (module_base + name_rva as usize) as *const u8;

    let mut len = 0;
    while *name_ptr.add(len) != 0 && len < 64 {
        len += 1;
    }

    if len == 0 {
        return None;
    }

    let slice = core::slice::from_raw_parts(name_ptr, len);
    core::str::from_utf8(slice).ok().map(|s| s.to_string())
}

pub unsafe fn analyze_preloaded_modules(min_gap_size: usize) -> Vec<ModuleAnalysisResult> {
    let mut results = Vec::new();

    for &hash in PRELOADED_DLL_HASHES.iter() {
        if let Some(base) = find_loaded_module_by_hash(hash) {
            if let Some(exports) = analyze_module_exports(base, min_gap_size) {
                let redirected_count = exports.iter().filter(|e| e.is_redirected).count();
                results.push(ModuleAnalysisResult {
                    module_base: base as usize,
                    module_hash: hash,
                    export_gaps: exports.clone(),
                    total_exports: exports.len(),
                    redirected_count,
                });
            }
        }
    }

    results
}

pub unsafe fn analyze_loaded_module_by_hash(
    target_hash: u64,
    min_gap_size: usize,
) -> Option<ModuleAnalysisResult> {
    let base = find_loaded_module_by_hash(target_hash)?;
    let exports = analyze_module_exports(base, min_gap_size)?;
    let total_exports = exports.len();
    let redirected_count = exports.iter().filter(|e| e.is_redirected).count();
    Some(ModuleAnalysisResult {
        module_base: base as usize,
        module_hash: target_hash,
        export_gaps: exports,
        total_exports,
        redirected_count,
    })
}

pub unsafe fn scan_for_export_gaps(
    target_size: usize,
) -> Vec<(usize, String, ExportGapInfo)> {
    let mut findings = Vec::new();

    let module_results = analyze_preloaded_modules(target_size);

    for result in module_results {
        for export in &result.export_gaps {
            let name = get_export_name(export.module_base, export.export_name_rva)
                .unwrap_or_else(|| format!("ordinal@{:X}", export.export_rva));

            findings.push((result.module_base, name, *export));
        }
    }

    findings
}

pub fn generate_analysis_report(min_size: usize) -> String {
    let mut report = String::new();
    report.push_str("=== Export Gap Analysis ===\n\n");

    unsafe {
        let results = analyze_preloaded_modules(min_size);

        if results.is_empty() {
            report.push_str("No preloaded modules found.\n");
            return report;
        }

        for result in &results {
            report.push_str(&format!(
                "Module: 0x{:X}\n",
                result.module_base
            ));
            report.push_str(&format!(
                "  Exports with padding (>= {} bytes): {}\n",
                min_size,
                result.export_gaps.len()
            ));
            report.push_str(&format!(
                "  Redirected exports: {}\n",
                result.redirected_count
            ));

            for export in &result.export_gaps {
                let name = get_export_name(export.module_base, export.export_name_rva)
                    .unwrap_or_else(|| "unnamed".to_string());
                report.push_str(&format!(
                    "    - {} @ 0x{:X} (gap: {} bytes) {}\n",
                    name,
                    export.export_address,
                    export.gap_size,
                    if export.is_redirected { "[REDIRECTED]" } else { "" }
                ));
            }
            report.push_str("\n");
        }
    }

    report
}
