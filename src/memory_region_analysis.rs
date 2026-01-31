#![allow(non_snake_case)]

use core::mem;
use core::ptr;
use std::collections::{HashMap, HashSet};

use ntapi::ntexapi::{SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION};
use ntapi::ntpsapi::{PROCESS_BASIC_INFORMATION, THREAD_BASIC_INFORMATION};
use serde::Serialize;
use winapi::ctypes::c_void;
use winapi::shared::ntdef::{HANDLE, NTSTATUS, UNICODE_STRING};
use winapi::um::psapi::{QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION};
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

use crate::entropy::{region_entropy, HIGH_ENTROPY_THRESHOLD, DEFAULT_MAX_READ};
use crate::signature::{verify_signature, SignatureInfo};
use crate::nt::{
    nt_success, CLIENT_ID, LDR_DATA_TABLE_ENTRY, LIST_ENTRY, OBJECT_ATTRIBUTES, PEB, PEB_LDR_DATA,
    MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use crate::syscalls::{
    nt_close, nt_open_process, nt_open_thread, nt_query_information_process,
    nt_query_information_thread, nt_query_system_information, nt_query_virtual_memory,
    nt_read_virtual_memory,
};

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const THREAD_BASIC_INFORMATION_CLASS: u32 = 0;
const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
const MEMORY_BASIC_INFORMATION_CLASS: u32 = 0;
const MEMORY_MAPPED_FILENAME_INFORMATION_CLASS: u32 = 2;

const MEM_PRIVATE: u32 = 0x00020000;
const MEM_MAPPED: u32 = 0x00040000;
const MEM_IMAGE: u32 = 0x01000000;

const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as i32;
const MAX_USER_ADDRESS: usize = 0x0000_7FFF_FFFF_FFFF;
const MAX_UNICODE_BYTES: usize = 0x4000;

const PEB_LDR_INMEMORY_OFFSET: usize = 8 + (3 * mem::size_of::<*mut c_void>());
const LDR_INMEMORY_OFFSET: usize = mem::size_of::<LIST_ENTRY>();

#[repr(C)]
struct NtTib {
    ExceptionList: *mut c_void,
    StackBase: *mut c_void,
    StackLimit: *mut c_void,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RegionBacking {
    Image,
    Mapped,
    Private,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ThreadStartVerdict {
    CleanImage,
    PrivateExecutable,
    MappedExecutable,
    MappedNoFile,
    ImageNotInModuleList,
    UnknownExecutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RegionVerdict {
    PrivateExecutable,
    MappedExecutable,
    MappedNoFile,
    ImageNotInModuleList,
    UnknownExecutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WorkingSetShare {
    Shared,
    PrivateCopy,
    NotResident,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackScanSummary {
    pub scanned_bytes: usize,
    pub addresses_scanned: usize,
    pub module_hits: usize,
    pub exec_private_hits: usize,
    pub exec_mapped_hits: usize,
    pub mapped_no_file_hits: usize,
    pub image_not_in_list_hits: usize,
    pub suspicious_hits: usize,
    pub validated_hits: usize,
    pub unvalidated_hits: usize,
    pub validation_failures: usize,
    pub samples: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
    pub full_name: Option<String>,
    pub base_name: Option<String>,
    pub signature: Option<SignatureInfo>,
    pub memory_map_present: bool,
    pub memory_map_checked: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub allocation_base: usize,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadStartFinding {
    pub pid: u32,
    pub tid: u32,
    pub start_address: usize,
    pub win32_start_address: Option<u64>,
    pub start_mismatch: bool,
    pub region: MemoryRegion,
    pub backing: RegionBacking,
    pub mapped_path: Option<String>,
    pub verdict: ThreadStartVerdict,
    pub working_set: WorkingSetShare,
    pub severity: FindingSeverity,
    pub stack_summary: Option<StackScanSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionFinding {
    pub region: MemoryRegion,
    pub backing: RegionBacking,
    pub mapped_path: Option<String>,
    pub verdict: RegionVerdict,
    pub working_set: WorkingSetShare,
    pub severity: FindingSeverity,
    pub entropy: Option<f64>,
    pub entropy_high: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessScanReport {
    pub pid: u32,
    pub image_name: Option<String>,
    pub modules: Vec<ModuleInfo>,
    pub modules_complete: bool,
    pub thread_findings: Vec<ThreadStartFinding>,
    pub region_findings: Vec<RegionFinding>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ScanOptions {
    pub max_processes: usize,
    pub max_threads_per_process: usize,
    pub max_regions_per_process: usize,
    pub max_modules_per_process: usize,
    pub min_region_size: usize,
    pub collect_mapped_paths: bool,
    pub collect_modules: bool,
    pub check_working_set: bool,
    pub scan_thread_stacks: bool,
    pub stack_scan_bytes: usize,
    pub stack_chunk_bytes: usize,
    pub stack_max_samples: usize,
    pub stack_max_lookups: usize,
    pub stack_max_validations: usize,
    pub verify_thread_start: bool,
    pub scan_threads: bool,
    pub scan_regions: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_processes: 512,
            max_threads_per_process: 4096,
            max_regions_per_process: 65536,
            max_modules_per_process: 1024,
            min_region_size: 0x1000,
            collect_mapped_paths: false,
            collect_modules: true,
            check_working_set: true,
            scan_thread_stacks: true,
            stack_scan_bytes: 0,
            stack_chunk_bytes: 0x20000,
            stack_max_samples: 8,
            stack_max_lookups: 256,
            stack_max_validations: 64,
            verify_thread_start: true,
            scan_threads: true,
            scan_regions: true,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct ScanStats {
    pub processes_seen: usize,
    pub processes_scanned: usize,
    pub processes_skipped: usize,
    pub threads_seen: usize,
    pub threads_analyzed: usize,
    pub thread_stacks_scanned: usize,
    pub stack_suspicious_threads: usize,
    pub regions_scanned: usize,
    pub modules_seen: usize,
    pub module_lists_ok: usize,
    pub module_lists_failed: usize,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemScanReport {
    pub processes: Vec<ProcessScanReport>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone)]
struct ProcessSnapshot {
    pid: u32,
    image_name: Option<String>,
    threads: Vec<ThreadSnapshot>,
}

#[derive(Debug, Clone, Copy)]
struct ThreadSnapshot {
    tid: u32,
    start_address: usize,
}

fn build_memory_map(handle: HANDLE, max_regions: usize) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let mut addr: usize = 0;
    let mut scanned: usize = 0;

    loop {
        if scanned >= max_regions {
            break;
        }

        let mbi = match query_memory_basic_information(handle, addr) {
            Some(m) => m,
            None => break,
        };

        scanned = scanned.saturating_add(1);

        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;
        if region_size == 0 {
            break;
        }

        let next = region_base.saturating_add(region_size);
        if next <= addr {
            break;
        }
        addr = next;

        regions.push(MemoryRegion {
            base_address: region_base,
            allocation_base: mbi.AllocationBase as usize,
            region_size,
            state: mbi.State,
            protect: mbi.Protect,
            region_type: mbi.Type,
        });
    }

    regions
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

fn mark_module_map_presence(modules: &mut [ModuleInfo], map: &[MemoryRegion]) {
    for module in modules {
        let present = find_region_for_address(map, module.base_address)
            .map(|region| {
                backing_from_type(region.region_type) == RegionBacking::Image
                    && region.allocation_base == module.base_address
            })
            .unwrap_or(false);
        module.memory_map_present = present;
        module.memory_map_checked = true;
    }
}

pub fn scan_system(options: ScanOptions) -> SystemScanReport {
    let snapshots = query_system_processes();
    let mut stats = ScanStats::default();
    stats.processes_seen = snapshots.len();

    let mut processes = Vec::new();

    for snapshot in snapshots.into_iter().take(options.max_processes) {
        if let Some(report) = scan_process_snapshot(snapshot, options, &mut stats) {
            processes.push(report);
        }
    }

    SystemScanReport { processes, stats }
}

pub fn scan_process(pid: u32, options: ScanOptions) -> Option<ProcessScanReport> {
    let mut stats = ScanStats::default();
    let snapshot = query_process_snapshot(pid)?;
    scan_process_snapshot(snapshot, options, &mut stats)
}

pub fn list_process_threads(pid: u32) -> Vec<u32> {
    let snapshot = match query_process_snapshot(pid) {
        Some(s) => s,
        None => return Vec::new(),
    };
    snapshot.threads.into_iter().map(|t| t.tid).collect()
}

pub fn build_memory_map_for_pid(pid: u32) -> Option<Vec<MemoryRegion>> {
    let handle = open_process(pid)?;
    let map = build_memory_map(handle, 65536);
    unsafe {
        nt_close(handle);
    }
    Some(map)
}

fn scan_process_snapshot(
    snapshot: ProcessSnapshot,
    options: ScanOptions,
    stats: &mut ScanStats,
) -> Option<ProcessScanReport> {
    if snapshot.pid == 0 {
        stats.processes_skipped += 1;
        return None;
    }

    let handle = match open_process(snapshot.pid) {
        Some(h) => h,
        None => {
            stats.processes_skipped += 1;
            return None;
        }
    };

    stats.processes_scanned += 1;

    let (mut modules, modules_complete) = if options.collect_modules {
        let (mods, complete) = query_module_list(handle, options.max_modules_per_process);
        if complete {
            stats.module_lists_ok += 1;
            stats.modules_seen += mods.len();
        } else {
            stats.module_lists_failed += 1;
        }
        (mods, complete)
    } else {
        (Vec::new(), false)
    };

    let memory_map = if options.scan_regions || options.scan_thread_stacks || options.scan_threads {
        build_memory_map(handle, options.max_regions_per_process)
    } else {
        Vec::new()
    };

    if !modules.is_empty() && !memory_map.is_empty() {
        mark_module_map_presence(&mut modules, &memory_map);
    }
    let memory_map_ref = if memory_map.is_empty() {
        None
    } else {
        Some(memory_map.as_slice())
    };

    let module_refs = if modules_complete {
        Some(modules.as_slice())
    } else {
        None
    };

    let mut thread_findings = Vec::new();
    let mut region_findings = Vec::new();

    if options.scan_threads {
        let limit = options.max_threads_per_process.min(snapshot.threads.len());
        stats.threads_seen += limit;

        for thread in snapshot.threads.iter().take(limit) {
            stats.threads_analyzed += 1;
            if let Some(finding) = analyze_thread_start(
                handle,
                snapshot.pid,
                thread,
                options,
                module_refs,
                memory_map_ref,
                stats,
            )
            {
                stats.findings += 1;
                thread_findings.push(finding);
            }
        }
    }

    if options.scan_regions {
        let (regions, scanned) =
            scan_executable_unbacked_regions(handle, options, module_refs, memory_map_ref);
        stats.regions_scanned += scanned;
        stats.findings += regions.len();
        region_findings = regions;
    }

    unsafe {
        nt_close(handle);
    }

    let report = ProcessScanReport {
        pid: snapshot.pid,
        image_name: snapshot.image_name,
        modules,
        modules_complete,
        thread_findings,
        region_findings,
    };

    Some(report)
}

fn query_system_processes() -> Vec<ProcessSnapshot> {
    let mut size: usize = 0x10000;

    for _ in 0..6 {
        let mut buffer = vec![0u8; size];
        let mut return_len: u32 = 0;
        let status = unsafe {
            nt_query_system_information(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut return_len as *mut u32,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            let reported = return_len as usize;
            size = if reported > size {
                reported + 0x1000
            } else {
                size.saturating_mul(2)
            };
            size = size.min(16 * 1024 * 1024);
            continue;
        }

        if !nt_success(status) {
            return Vec::new();
        }

        unsafe {
            return parse_system_processes(&buffer);
        }
    }

    Vec::new()
}

fn query_process_snapshot(pid: u32) -> Option<ProcessSnapshot> {
    let snapshots = query_system_processes();
    snapshots.into_iter().find(|p| p.pid == pid)
}

unsafe fn parse_system_processes(buffer: &[u8]) -> Vec<ProcessSnapshot> {
    let mut results = Vec::new();
    let buf_start = buffer.as_ptr() as usize;
    let buf_end = buf_start + buffer.len();
    let mut offset: usize = 0;

    while offset < buffer.len() {
        let entry_ptr = buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION;
        let entry_addr = entry_ptr as usize;
        if entry_addr + mem::size_of::<SYSTEM_PROCESS_INFORMATION>() > buf_end {
            break;
        }

        let entry = ptr::read_unaligned(entry_ptr);
        let pid = entry.UniqueProcessId as usize as u32;
        let image_name = {
            let u = ptr::read_unaligned(ptr::addr_of!((*entry_ptr).ImageName));
            unicode_string_from_buffer(u.Length, u.Buffer, buf_start, buf_end)
        };

        if entry.NextEntryOffset != 0 {
            let off = entry.NextEntryOffset as usize;
            if off < mem::size_of::<SYSTEM_PROCESS_INFORMATION>() || (off & 7) != 0 {
                break;
            }
        }

        let entry_size = if entry.NextEntryOffset == 0 {
            buf_end.saturating_sub(entry_addr)
        } else {
            entry.NextEntryOffset as usize
        };

        let thread_count = entry.NumberOfThreads as usize;
        if thread_count > 0x20000 {
            break;
        }
        let thread_info_size = mem::size_of::<SYSTEM_THREAD_INFORMATION>();
        let threads_bytes = thread_count.saturating_mul(thread_info_size);

        let threads_ptr = ptr::addr_of!((*entry_ptr).Threads) as *const SYSTEM_THREAD_INFORMATION;
        let threads_offset = (threads_ptr as usize).saturating_sub(entry_addr);

        if entry_size < threads_offset.saturating_add(threads_bytes) {
            break;
        }

        let mut threads = Vec::with_capacity(thread_count);
        let mut t_ptr = threads_ptr;
        for _ in 0..thread_count {
            let t_addr = t_ptr as usize;
            if t_addr + thread_info_size > buf_end
                || t_addr + thread_info_size > entry_addr + entry_size
            {
                break;
            }
            let t = ptr::read_unaligned(t_ptr);
            let tid = t.ClientId.UniqueThread as usize as u32;
            let start_address = t.StartAddress as usize;
            threads.push(ThreadSnapshot { tid, start_address });
            t_ptr = t_ptr.add(1);
        }

        results.push(ProcessSnapshot {
            pid,
            image_name,
            threads,
        });

        if entry.NextEntryOffset == 0 {
            break;
        }

        offset = offset.saturating_add(entry.NextEntryOffset as usize);
    }

    results
}

fn query_module_list(handle: HANDLE, max_modules: usize) -> (Vec<ModuleInfo>, bool) {
    if max_modules == 0 {
        return (Vec::new(), false);
    }
    if mem::size_of::<usize>() != 8 {
        return (Vec::new(), false);
    }

    let info = match query_process_basic_information(handle) {
        Some(i) => i,
        None => return (Vec::new(), false),
    };

    let peb_addr = info.PebBaseAddress as usize;
    if !is_user_address(peb_addr) {
        return (Vec::new(), false);
    }

    let peb: PEB = match read_struct(handle, peb_addr) {
        Some(p) => p,
        None => return (Vec::new(), false),
    };

    let ldr_addr = peb.Ldr as usize;
    if !is_user_address(ldr_addr) {
        return (Vec::new(), false);
    }

    let ldr: PEB_LDR_DATA = match read_struct(handle, ldr_addr) {
        Some(l) => l,
        None => return (Vec::new(), false),
    };

    let list_head = ldr_addr.saturating_add(PEB_LDR_INMEMORY_OFFSET);
    let mut current = ldr.InMemoryOrderModuleList.Flink as usize;

    if current == 0 || list_head == 0 {
        return (Vec::new(), false);
    }

    let mut modules = Vec::new();
    let mut seen = HashSet::new();
    let mut complete = true;

    while current != list_head {
        if !is_user_address(current) || !seen.insert(current) {
            complete = false;
            break;
        }

        let entry_addr = current.saturating_sub(LDR_INMEMORY_OFFSET);
        if !is_user_address(entry_addr) {
            complete = false;
            break;
        }

        let entry: LDR_DATA_TABLE_ENTRY = match read_struct(handle, entry_addr) {
            Some(e) => e,
            None => {
                complete = false;
                break;
            }
        };

        let base = entry.DllBase as usize;
        let size = entry.SizeOfImage as usize;
        if base != 0 && size != 0 {
            let full_name =
                read_remote_unicode_string(handle, entry.FullDllName.Length, entry.FullDllName.Buffer);
            let base_name =
                read_remote_unicode_string(handle, entry.BaseDllName.Length, entry.BaseDllName.Buffer);
            let signature = full_name.as_ref().map(|p| verify_signature(p));
            modules.push(ModuleInfo {
                base_address: base,
                size,
                full_name,
                base_name,
                signature,
                memory_map_present: false,
                memory_map_checked: false,
            });
        }

        current = entry.InMemoryOrderLinks.Flink as usize;
        if current == 0 || modules.len() >= max_modules {
            complete = false;
            break;
        }
    }

    (modules, complete)
}

fn query_process_basic_information(handle: HANDLE) -> Option<PROCESS_BASIC_INFORMATION> {
    let mut info: PROCESS_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut return_len: u32 = 0;
    let status = unsafe {
        nt_query_information_process(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut info as *mut _ as *mut c_void,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len as *mut u32,
        )
    };

    if !nt_success(status) {
        return None;
    }

    Some(info)
}

fn read_struct<T>(handle: HANDLE, addr: usize) -> Option<T> {
    if !is_user_address(addr) {
        return None;
    }

    let mut out = mem::MaybeUninit::<T>::uninit();
    let mut read_len: usize = 0;
    let status = unsafe {
        nt_read_virtual_memory(
            handle,
            addr as *mut c_void,
            out.as_mut_ptr() as *mut c_void,
            mem::size_of::<T>(),
            &mut read_len as *mut usize,
        )
    };

    if !nt_success(status) || read_len != mem::size_of::<T>() {
        return None;
    }

    Some(unsafe { out.assume_init() })
}

fn read_remote_unicode_string(handle: HANDLE, length: u16, buffer: *const u16) -> Option<String> {
    if length == 0 || buffer.is_null() {
        return None;
    }

    let byte_len = length as usize;
    if byte_len > MAX_UNICODE_BYTES || (byte_len & 1) != 0 {
        return None;
    }

    let mut buf = vec![0u16; byte_len / 2];
    let mut read_len: usize = 0;
    let status = unsafe {
        nt_read_virtual_memory(
            handle,
            buffer as *mut c_void,
            buf.as_mut_ptr() as *mut c_void,
            byte_len,
            &mut read_len as *mut usize,
        )
    };

    if !nt_success(status) || read_len < byte_len {
        return None;
    }

    Some(String::from_utf16_lossy(&buf))
}

fn is_user_address(addr: usize) -> bool {
    addr >= 0x10000 && addr <= MAX_USER_ADDRESS
}

fn find_module_for_address(modules: &[ModuleInfo], addr: usize) -> Option<&ModuleInfo> {
    for module in modules {
        let start = module.base_address;
        let end = start.saturating_add(module.size);
        if addr >= start && addr < end {
            return Some(module);
        }
    }

    None
}

fn query_working_set_share(handle: HANDLE, address: usize) -> WorkingSetShare {
    if !is_user_address(address) {
        return WorkingSetShare::Unknown;
    }

    let mut info = PSAPI_WORKING_SET_EX_INFORMATION {
        VirtualAddress: address as *mut c_void,
        VirtualAttributes: unsafe { mem::zeroed() },
    };

    let ok = unsafe {
        QueryWorkingSetEx(
            handle,
            &mut info as *mut _ as *mut c_void,
            mem::size_of::<PSAPI_WORKING_SET_EX_INFORMATION>() as u32,
        )
    };

    if ok == 0 {
        return WorkingSetShare::Unknown;
    }

    if info.VirtualAttributes.Valid() == 0 {
        return WorkingSetShare::NotResident;
    }

    if info.VirtualAttributes.Shared() != 0 {
        WorkingSetShare::Shared
    } else {
        WorkingSetShare::PrivateCopy
    }
}

fn apply_working_set_override(
    severity: FindingSeverity,
    backing: RegionBacking,
    working_set: WorkingSetShare,
) -> FindingSeverity {
    if matches!(backing, RegionBacking::Image | RegionBacking::Mapped)
        && working_set == WorkingSetShare::PrivateCopy
    {
        return FindingSeverity::High;
    }

    severity
}

fn is_plausible_return_address(
    process: HANDLE,
    addr: usize,
    memory_map: Option<&[MemoryRegion]>,
) -> bool {
    if addr < 6 {
        return false;
    }

    if let Some(map) = memory_map {
        let read_addr = addr.saturating_sub(6);
        let region = match find_region_for_address(map, read_addr) {
            Some(r) => r,
            None => return false,
        };
        if region.state != MEM_COMMIT || !is_readable(region.protect) {
            return false;
        }
        let region_end = region
            .base_address
            .saturating_add(region.region_size);
        if read_addr.saturating_add(6) > region_end {
            return false;
        }
    }

    let mut bytes = [0u8; 6];
    let mut read_len: usize = 0;
    let status = unsafe {
        nt_read_virtual_memory(
            process,
            (addr - 6) as *mut c_void,
            bytes.as_mut_ptr() as *mut c_void,
            bytes.len(),
            &mut read_len as *mut usize,
        )
    };

    if !nt_success(status) || read_len < 2 {
        return false;
    }

    // CALL rel32: E8 xx xx xx xx  (return address at next instruction)
    if read_len >= 5 && bytes[1] == 0xE8 {
        return true;
    }

    // CALL [RIP+disp32]: FF 15 xx xx xx xx
    if read_len >= 6 && bytes[0] == 0xFF && bytes[1] == 0x15 {
        return true;
    }

    // CALL r/m64 (register): FF D0..D7 (2 bytes)
    if read_len >= 2 && bytes[4] == 0xFF && (bytes[5] & 0xF8) == 0xD0 {
        return true;
    }

    false
}

fn severity_rank(sev: FindingSeverity) -> u8 {
    match sev {
        FindingSeverity::Low => 0,
        FindingSeverity::Medium => 1,
        FindingSeverity::High => 2,
    }
}

fn classify_stack_severity(summary: &StackScanSummary) -> FindingSeverity {
    if summary.validated_hits > 0 || summary.suspicious_hits > 0 {
        return FindingSeverity::High;
    }

    if summary.exec_mapped_hits > 0 {
        return FindingSeverity::Medium;
    }

    FindingSeverity::Low
}

fn open_thread(tid: u32) -> Option<HANDLE> {
    let mut handle: HANDLE = ptr::null_mut();
    let mut obj = OBJECT_ATTRIBUTES::null();
    let mut client_id = CLIENT_ID {
        UniqueProcess: ptr::null_mut(),
        UniqueThread: tid as usize as HANDLE,
    };

    let status = unsafe {
        nt_open_thread(
            &mut handle as *mut HANDLE,
            crate::nt::THREAD_QUERY_INFORMATION,
            &mut obj as *mut OBJECT_ATTRIBUTES,
            &mut client_id as *mut CLIENT_ID,
        )
    };

    if !nt_success(status) || handle.is_null() {
        return None;
    }

    Some(handle)
}

fn query_thread_basic_information(handle: HANDLE) -> Option<THREAD_BASIC_INFORMATION> {
    let mut info: THREAD_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut return_len: u32 = 0;
    let status = unsafe {
        nt_query_information_thread(
            handle,
            THREAD_BASIC_INFORMATION_CLASS,
            &mut info as *mut _ as *mut c_void,
            mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
            &mut return_len as *mut u32,
        )
    };

    if !nt_success(status) {
        return None;
    }

    Some(info)
}

fn query_thread_win32_start_address(handle: HANDLE) -> Option<u64> {
    let mut start: usize = 0;
    let mut return_len: u32 = 0;
    let status = unsafe {
        nt_query_information_thread(
            handle,
            THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &mut start as *mut _ as *mut c_void,
            mem::size_of::<usize>() as u32,
            &mut return_len as *mut u32,
        )
    };

    if !nt_success(status) || start == 0 {
        return None;
    }

    Some(start as u64)
}

fn analyze_thread_stack(
    process: HANDLE,
    thread: HANDLE,
    modules: Option<&[ModuleInfo]>,
    memory_map: Option<&[MemoryRegion]>,
    options: ScanOptions,
) -> Option<StackScanSummary> {
    let map = match memory_map {
        Some(m) if !m.is_empty() => m,
        _ => return None,
    };

    if options.stack_scan_bytes < 8 || options.stack_max_lookups == 0 {
        return None;
    }

    let info = query_thread_basic_information(thread)?;

    let teb_addr = info.TebBaseAddress as usize;
    if !is_user_address(teb_addr) {
        return None;
    }

    let tib: NtTib = read_struct(process, teb_addr)?;
    let stack_base = tib.StackBase as usize;
    let stack_limit = tib.StackLimit as usize;

    if !is_user_address(stack_base) || !is_user_address(stack_limit) || stack_base <= stack_limit {
        return None;
    }

    let stack_size = stack_base.saturating_sub(stack_limit);
    if stack_size < 8 {
        return None;
    }

    let scan_bytes = if options.stack_scan_bytes == 0 {
        stack_size
    } else {
        stack_size.min(options.stack_scan_bytes)
    };
    if scan_bytes < 8 {
        return None;
    }

    let mut chunk_size = if options.stack_chunk_bytes == 0 {
        scan_bytes
    } else {
        options.stack_chunk_bytes
    };
    if scan_bytes < 0x1000 {
        chunk_size = scan_bytes;
    } else {
        if chunk_size < 0x1000 {
            chunk_size = 0x1000;
        }
        if chunk_size > scan_bytes {
            chunk_size = scan_bytes;
        }
    }

    if chunk_size == 0 {
        return None;
    }

    let scan_start = stack_base.saturating_sub(scan_bytes);

    let mut buffer = vec![0u8; chunk_size];
    let mut addr = scan_start;
    let mut lookups = 0usize;
    let mut validations = 0usize;
    let mut mapped_cache: HashMap<usize, Option<String>> = HashMap::new();

    let mut summary = StackScanSummary {
        scanned_bytes: 0,
        addresses_scanned: 0,
        module_hits: 0,
        exec_private_hits: 0,
        exec_mapped_hits: 0,
        mapped_no_file_hits: 0,
        image_not_in_list_hits: 0,
        suspicious_hits: 0,
        validated_hits: 0,
        unvalidated_hits: 0,
        validation_failures: 0,
        samples: Vec::new(),
    };

    while addr < stack_base {
        let remaining = stack_base.saturating_sub(addr);
        let read_size = remaining.min(chunk_size);
        if read_size < 8 {
            break;
        }

        let mut read_len: usize = 0;
        let status = unsafe {
            nt_read_virtual_memory(
                process,
                addr as *mut c_void,
                buffer.as_mut_ptr() as *mut c_void,
                read_size,
                &mut read_len as *mut usize,
            )
        };

        if nt_success(status) && read_len >= 8 {
            let bytes = read_len.min(read_size);
            summary.scanned_bytes = summary.scanned_bytes.saturating_add(bytes);
            let slice = &buffer[..bytes];

            for chunk in slice.chunks_exact(8) {
                let value = u64::from_ne_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
                let candidate = value as usize;

                if !is_user_address(candidate) {
                    continue;
                }

                summary.addresses_scanned += 1;

                if let Some(module_list) = modules {
                    if find_module_for_address(module_list, candidate).is_some() {
                        summary.module_hits += 1;
                        continue;
                    }
                }

                let region = match find_region_for_address(map, candidate) {
                    Some(r) => r,
                    None => continue,
                };

                if region.state != MEM_COMMIT || !is_executable(region.protect) {
                    continue;
                }

                let backing = backing_from_type(region.region_type);
                match backing {
                    RegionBacking::Private => {
                        summary.exec_private_hits += 1;
                        if validations < options.stack_max_validations
                            && lookups < options.stack_max_lookups
                        {
                            lookups += 1;
                            validations += 1;
                            if is_plausible_return_address(process, candidate, Some(map)) {
                                summary.validated_hits += 1;
                                summary.suspicious_hits += 1;
                                if summary.samples.len() < options.stack_max_samples {
                                    summary.samples.push(candidate as u64);
                                }
                            } else {
                                summary.validation_failures += 1;
                            }
                        } else {
                            summary.unvalidated_hits += 1;
                        }
                    }
                    RegionBacking::Mapped => {
                        summary.exec_mapped_hits += 1;
                        if options.collect_mapped_paths {
                            let base = region.allocation_base;
                            let path = match mapped_cache.get(&base) {
                                Some(p) => p.clone(),
                                None => {
                                    let p = query_mapped_filename(process, region.base_address);
                                    mapped_cache.insert(base, p.clone());
                                    p
                                }
                            };
                            if path.is_none() {
                                summary.mapped_no_file_hits += 1;
                                if validations < options.stack_max_validations
                                    && lookups < options.stack_max_lookups
                                {
                                    lookups += 1;
                                    validations += 1;
                                    if is_plausible_return_address(process, candidate, Some(map)) {
                                        summary.validated_hits += 1;
                                        summary.suspicious_hits += 1;
                                        if summary.samples.len() < options.stack_max_samples {
                                            summary.samples.push(candidate as u64);
                                        }
                                    } else {
                                        summary.validation_failures += 1;
                                    }
                                } else {
                                    summary.unvalidated_hits += 1;
                                }
                            }
                        }
                    }
                    RegionBacking::Image => {
                        if modules.is_some() {
                            summary.image_not_in_list_hits += 1;
                            if validations < options.stack_max_validations
                                && lookups < options.stack_max_lookups
                            {
                                lookups += 1;
                                validations += 1;
                                if is_plausible_return_address(process, candidate, Some(map)) {
                                    summary.validated_hits += 1;
                                    summary.suspicious_hits += 1;
                                    if summary.samples.len() < options.stack_max_samples {
                                        summary.samples.push(candidate as u64);
                                    }
                                } else {
                                    summary.validation_failures += 1;
                                }
                            } else {
                                summary.unvalidated_hits += 1;
                            }
                        }
                    }
                    RegionBacking::Unknown => {}
                }
            }
        }

        addr = addr.saturating_add(read_size);
    }

    Some(summary)
}

fn analyze_thread_start(
    handle: HANDLE,
    pid: u32,
    thread: &ThreadSnapshot,
    options: ScanOptions,
    modules: Option<&[ModuleInfo]>,
    memory_map: Option<&[MemoryRegion]>,
    stats: &mut ScanStats,
) -> Option<ThreadStartFinding> {
    let thread_handle = if options.scan_thread_stacks || options.verify_thread_start {
        open_thread(thread.tid)
    } else {
        None
    };

    let win32_start_address = if options.verify_thread_start {
        thread_handle.and_then(query_thread_win32_start_address)
    } else {
        None
    };

    let mut stack_summary = if options.scan_thread_stacks
        && (options.stack_scan_bytes == 0 || options.stack_scan_bytes >= 0x1000)
    {
        let summary = thread_handle.and_then(|h| analyze_thread_stack(handle, h, modules, memory_map, options));
        if let Some(ref s) = summary {
            stats.thread_stacks_scanned += 1;
            if s.suspicious_hits > 0 {
                stats.stack_suspicious_threads += 1;
            }
        }
        summary
    } else {
        None
    };

    if let Some(h) = thread_handle {
        unsafe { nt_close(h); }
    }

    let region = if let Some(map) = memory_map {
        find_region_for_address(map, thread.start_address).cloned().or_else(|| {
            query_memory_basic_information(handle, thread.start_address).map(|mbi| MemoryRegion {
                base_address: mbi.BaseAddress as usize,
                allocation_base: mbi.AllocationBase as usize,
                region_size: mbi.RegionSize,
                state: mbi.State,
                protect: mbi.Protect,
                region_type: mbi.Type,
            })
        })?
    } else {
        let mbi = query_memory_basic_information(handle, thread.start_address)?;
        MemoryRegion {
            base_address: mbi.BaseAddress as usize,
            allocation_base: mbi.AllocationBase as usize,
            region_size: mbi.RegionSize,
            state: mbi.State,
            protect: mbi.Protect,
            region_type: mbi.Type,
        }
    };

    if region.state != MEM_COMMIT {
        return None;
    }

    let exec = is_executable(region.protect);
    if !exec {
        return None;
    }

    let backing = backing_from_type(region.region_type);
    let working_set = if options.check_working_set && backing != RegionBacking::Private {
        query_working_set_share(handle, thread.start_address)
    } else {
        WorkingSetShare::Unknown
    };

    let mut mapped_path = None;
    if options.collect_mapped_paths && backing == RegionBacking::Mapped {
        mapped_path = query_mapped_filename(handle, region.base_address);
    }

    let mut verdict = match backing {
        RegionBacking::Image => ThreadStartVerdict::CleanImage,
        RegionBacking::Private => ThreadStartVerdict::PrivateExecutable,
        RegionBacking::Mapped => {
            if mapped_path.is_some() {
                ThreadStartVerdict::MappedExecutable
            } else {
                ThreadStartVerdict::MappedNoFile
            }
        }
        RegionBacking::Unknown => ThreadStartVerdict::UnknownExecutable,
    };

    let severity =
        apply_working_set_override(classify_thread_severity(backing, region.protect, mapped_path.as_ref()), backing, working_set);

    let mut severity = severity;
    if backing == RegionBacking::Image {
        if let Some(module_list) = modules {
            if find_module_for_address(module_list, thread.start_address).is_none() {
                verdict = ThreadStartVerdict::ImageNotInModuleList;
                severity = FindingSeverity::High;
            }
        }
    }

    let start_mismatch = win32_start_address
        .map(|addr| addr as usize != thread.start_address)
        .unwrap_or(false);
    if start_mismatch {
        if let Some(map) = memory_map {
            if let Some(region) = find_region_for_address(map, win32_start_address.unwrap() as usize)
            {
                if region.state == MEM_COMMIT && is_executable(region.protect) {
                    let wb = backing_from_type(region.region_type);
                    let boosted = match wb {
                        RegionBacking::Private => FindingSeverity::High,
                        RegionBacking::Mapped => FindingSeverity::Medium,
                        RegionBacking::Image => {
                            if let Some(module_list) = modules {
                                if find_module_for_address(module_list, region.base_address).is_none() {
                                    FindingSeverity::High
                                } else {
                                    FindingSeverity::Medium
                                }
                            } else {
                                FindingSeverity::Medium
                            }
                        }
                        RegionBacking::Unknown => FindingSeverity::Medium,
                    };
                    if severity_rank(boosted) > severity_rank(severity) {
                        severity = boosted;
                    }
                }
            }
        }
    }

    if let Some(ref s) = stack_summary {
        let stack_sev = classify_stack_severity(s);
        if severity_rank(stack_sev) > severity_rank(severity) {
            severity = stack_sev;
        }
    }

    let stack_suspicious = stack_summary.as_ref().map_or(false, |s| s.suspicious_hits > 0);
    let should_report = verdict != ThreadStartVerdict::CleanImage || stack_suspicious;
    if !should_report {
        return None;
    }

    Some(ThreadStartFinding {
        pid,
        tid: thread.tid,
        start_address: thread.start_address,
        win32_start_address,
        start_mismatch,
        region,
        backing,
        mapped_path,
        verdict,
        working_set,
        severity,
        stack_summary: stack_summary.take(),
    })
}

fn scan_executable_unbacked_regions(
    handle: HANDLE,
    options: ScanOptions,
    modules: Option<&[ModuleInfo]>,
    memory_map: Option<&[MemoryRegion]>,
) -> (Vec<RegionFinding>, usize) {
    let mut findings = Vec::new();
    let owned_map;
    let map = if let Some(m) = memory_map {
        m
    } else {
        owned_map = build_memory_map(handle, options.max_regions_per_process);
        &owned_map
    };

    let scanned = map.len();

    for region in map.iter().copied() {
        if region.state != MEM_COMMIT || region.region_size < options.min_region_size {
            continue;
        }

        let exec = is_executable(region.protect);
        if !exec {
            continue;
        }

        let backing = backing_from_type(region.region_type);
        let working_set = if options.check_working_set && backing != RegionBacking::Private {
            query_working_set_share(handle, region.base_address)
        } else {
            WorkingSetShare::Unknown
        };

        if backing == RegionBacking::Image {
            if let Some(module_list) = modules {
                if find_module_for_address(module_list, region.base_address).is_none() {
                    let mut mapped_path = None;
                    if options.collect_mapped_paths {
                        mapped_path = query_mapped_filename(handle, region.base_address);
                    }

                    findings.push(RegionFinding {
                        region,
                        backing,
                        mapped_path,
                        verdict: RegionVerdict::ImageNotInModuleList,
                        working_set,
                        severity: FindingSeverity::High,
                        entropy: None,
                        entropy_high: false,
                    });
                }
            }
            continue;
        }

        let mut mapped_path = None;
        if options.collect_mapped_paths && backing == RegionBacking::Mapped {
            mapped_path = query_mapped_filename(handle, region.base_address);
        }

        let verdict = region_verdict_from_backing(backing, mapped_path.as_ref());
        let mut severity = apply_working_set_override(
            classify_region_severity(backing, region.protect, mapped_path.as_ref()),
            backing,
            working_set,
        );
        let mut entropy = None;
        let mut entropy_high = false;

        if backing == RegionBacking::Private && is_rwx(region.protect) && is_readable(region.protect)
        {
            if let Some(h) = region_entropy(handle, region.base_address, region.region_size, DEFAULT_MAX_READ) {
                entropy = Some(h);
                if h >= HIGH_ENTROPY_THRESHOLD {
                    entropy_high = true;
                    if severity_rank(FindingSeverity::High) > severity_rank(severity) {
                        severity = FindingSeverity::High;
                    }
                }
            }
        }

        findings.push(RegionFinding {
            region,
            backing,
            mapped_path,
            verdict,
            working_set,
            severity,
            entropy,
            entropy_high,
        });
    }

    (findings, scanned)
}

fn query_memory_basic_information(handle: HANDLE, address: usize) -> Option<MEMORY_BASIC_INFORMATION> {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut return_length: usize = 0;
    let status = unsafe {
        nt_query_virtual_memory(
            handle,
            address as *mut c_void,
            MEMORY_BASIC_INFORMATION_CLASS,
            &mut mbi as *mut _ as *mut c_void,
            mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            &mut return_length,
        )
    };

    if !nt_success(status) {
        return None;
    }

    Some(mbi)
}

fn query_mapped_filename(handle: HANDLE, base_address: usize) -> Option<String> {
    let mut size: usize = 0x400;

    for _ in 0..3 {
        let mut buffer = vec![0u8; size];
        let mut return_length: usize = 0;
        let status = unsafe {
            nt_query_virtual_memory(
                handle,
                base_address as *mut c_void,
                MEMORY_MAPPED_FILENAME_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                &mut return_length,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            let reported = return_length.max(size * 2);
            size = reported.min(0x10000);
            continue;
        }

        if !nt_success(status) {
            return None;
        }

        let buf_start = buffer.as_ptr() as usize;
        let buf_end = buf_start + buffer.len();
        let u = unsafe { &*(buffer.as_ptr() as *const UNICODE_STRING) };

        if u.Length == 0 || u.Buffer.is_null() {
            return None;
        }

        let byte_len = u.Length as usize;
        let ptr = u.Buffer as usize;
        if ptr < buf_start || ptr.saturating_add(byte_len) > buf_end {
            return None;
        }

        let slice = unsafe { core::slice::from_raw_parts(u.Buffer, byte_len / 2) };
        let s = String::from_utf16_lossy(slice);
        if s.is_empty() {
            return None;
        }
        return Some(s);
    }

    None
}

fn open_process(pid: u32) -> Option<HANDLE> {
    let mut handle: HANDLE = ptr::null_mut();
    let mut obj = OBJECT_ATTRIBUTES::null();
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as usize as HANDLE,
        UniqueThread: ptr::null_mut(),
    };

    let status = unsafe {
        nt_open_process(
            &mut handle as *mut HANDLE,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            &mut obj as *mut OBJECT_ATTRIBUTES,
            &mut client_id as *mut CLIENT_ID,
        )
    };

    if !nt_success(status) || handle.is_null() {
        return None;
    }

    Some(handle)
}

fn is_executable(protect: u32) -> bool {
    let exec_mask =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    (protect & exec_mask) != 0
}

fn is_readable(protect: u32) -> bool {
    if (protect & PAGE_NOACCESS) != 0 {
        return false;
    }
    if (protect & PAGE_GUARD) != 0 {
        return false;
    }
    true
}

fn is_rwx(protect: u32) -> bool {
    (protect & PAGE_EXECUTE_READWRITE) != 0
}

fn backing_from_type(ty: u32) -> RegionBacking {
    if (ty & MEM_IMAGE) != 0 {
        return RegionBacking::Image;
    }
    if (ty & MEM_MAPPED) != 0 {
        return RegionBacking::Mapped;
    }
    if (ty & MEM_PRIVATE) != 0 {
        return RegionBacking::Private;
    }
    RegionBacking::Unknown
}

fn classify_thread_severity(
    backing: RegionBacking,
    protect: u32,
    mapped_path: Option<&String>,
) -> FindingSeverity {
    match backing {
        RegionBacking::Private => {
            if is_rwx(protect) {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            }
        }
        RegionBacking::Mapped => {
            if mapped_path.is_none() {
                FindingSeverity::High
            } else if is_rwx(protect) {
                FindingSeverity::Medium
            } else {
                FindingSeverity::Low
            }
        }
        _ => FindingSeverity::Medium,
    }
}

fn classify_region_severity(
    backing: RegionBacking,
    protect: u32,
    mapped_path: Option<&String>,
) -> FindingSeverity {
    classify_thread_severity(backing, protect, mapped_path)
}

fn region_verdict_from_backing(backing: RegionBacking, mapped_path: Option<&String>) -> RegionVerdict {
    match backing {
        RegionBacking::Private => RegionVerdict::PrivateExecutable,
        RegionBacking::Mapped => {
            if mapped_path.is_some() {
                RegionVerdict::MappedExecutable
            } else {
                RegionVerdict::MappedNoFile
            }
        }
        RegionBacking::Image => RegionVerdict::ImageNotInModuleList,
        RegionBacking::Unknown => RegionVerdict::UnknownExecutable,
    }
}

fn unicode_string_from_buffer(length: u16, buffer: *const u16, buf_start: usize, buf_end: usize) -> Option<String> {
    if length == 0 || buffer.is_null() {
        return None;
    }

    let byte_len = length as usize;
    if (byte_len & 1) != 0 {
        return None;
    }
    let ptr = buffer as usize;
    if ptr < buf_start || ptr.saturating_add(byte_len) > buf_end {
        return None;
    }

    let slice = unsafe { core::slice::from_raw_parts(buffer, byte_len / 2) };
    Some(String::from_utf16_lossy(slice))
}
