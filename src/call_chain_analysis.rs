//! Call stack analysis utilities for defensive inspection.

#![allow(non_snake_case)]

use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::nt::{PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SavedStackState {
    pub real_rsp: u64,
    pub real_rbp: u64,
    pub real_return_addr: u64,
}

const MAX_SITES: usize = 32;

static KERNEL32_SITES: [AtomicU64; MAX_SITES] = [const { AtomicU64::new(0) }; MAX_SITES];
static NTDLL_SITES: [AtomicU64; MAX_SITES] = [const { AtomicU64::new(0) }; MAX_SITES];

pub static NTDLL_RETURN_SITES: [AtomicU64; MAX_SITES] =
    [const { AtomicU64::new(0) }; MAX_SITES];

static KERNELBASE_SITES: [AtomicU64; MAX_SITES] = [const { AtomicU64::new(0) }; MAX_SITES];

static KERNEL32_SITE_COUNT: AtomicUsize = AtomicUsize::new(0);
static NTDLL_SITE_COUNT: AtomicUsize = AtomicUsize::new(0);

pub static NTDLL_RETURN_COUNT: AtomicUsize = AtomicUsize::new(0);

static KERNELBASE_SITE_COUNT: AtomicUsize = AtomicUsize::new(0);
static SITES_INITIALIZED: AtomicU64 = AtomicU64::new(0);
static SITE_ROTATOR: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
pub unsafe fn get_teb() -> *mut u8 {
    let teb: *mut u8;
    core::arch::asm!(
        "mov {}, gs:[0x30]",
        out(reg) teb,
        options(nostack, nomem, preserves_flags)
    );
    teb
}

#[inline(always)]
pub unsafe fn get_peb() -> *mut u8 {
    let teb = get_teb();
    if teb.is_null() {
        return ptr::null_mut();
    }
    // PEB is at TEB + 0x60
    *(teb.add(0x60) as *const *mut u8)
}

#[inline(always)]
pub unsafe fn get_stack_base() -> u64 {
    let teb = get_teb();
    if teb.is_null() {
        return 0;
    }
    *(teb.add(0x08) as *const u64)
}

#[inline(always)]
pub unsafe fn get_stack_limit() -> u64 {
    let teb = get_teb();
    if teb.is_null() {
        return 0;
    }
    *(teb.add(0x10) as *const u64)
}

#[inline(always)]
pub unsafe fn get_current_rsp() -> u64 {
    let rsp: u64;
    core::arch::asm!(
        "mov {}, rsp",
        out(reg) rsp,
        options(nostack, nomem, preserves_flags)
    );
    rsp
}

#[inline(always)]
pub unsafe fn get_current_rbp() -> u64 {
    let rbp: u64;
    core::arch::asm!(
        "mov {}, rbp",
        out(reg) rbp,
        options(nostack, nomem, preserves_flags)
    );
    rbp
}

#[inline(always)]
pub unsafe fn save_stack_state() -> SavedStackState {
    let rsp = get_current_rsp();
    let rbp = get_current_rbp();
    let return_addr = if rsp != 0 { *(rsp as *const u64) } else { 0 };

    SavedStackState {
        real_rsp: rsp,
        real_rbp: rbp,
        real_return_addr: return_addr,
    }
}

#[inline]
pub fn random_index(max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    let next = SITE_ROTATOR.fetch_add(1, Ordering::Relaxed);
    next % max
}

pub unsafe fn is_memory_executable(addr: usize) -> bool {
    if addr == 0 || addr < 0x10000 {
        return false;
    }

    #[repr(C)]
    struct MemoryBasicInfo {
        base_address: usize,
        allocation_base: usize,
        allocation_protect: u32,
        _pad1: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
        _pad2: u32,
    }

    let mut mbi: MemoryBasicInfo = core::mem::zeroed();
    let mut return_length: usize = 0;

    use winapi::ctypes::c_void;
    let status = crate::syscalls::nt_query_virtual_memory(
        -1isize as *mut c_void,
        addr as *mut c_void,
        0,
        &mut mbi as *mut _ as *mut c_void,
        core::mem::size_of::<MemoryBasicInfo>(),
        &mut return_length,
    );

    if status != 0 {
        return false;
    }

    // Check MEM_COMMIT (0x1000)
    const MEM_COMMIT: u32 = 0x1000;
    if mbi.state != MEM_COMMIT {
        return false;
    }

    let exec_mask =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    (mbi.protect & exec_mask) != 0
}

pub unsafe fn scan_module_for_sites(
    module_base: *const u8,
    site_pool: &[AtomicU64; MAX_SITES],
) -> usize {
    if module_base.is_null() {
        return 0;
    }

    let (text_start, text_size) = match crate::pe::find_text_section(module_base) {
        Some(t) => t,
        None => return 0,
    };

    let text_end = (text_start as usize + text_size).saturating_sub(3);
    let mut site_count = 0;

    let mut addr = text_start as usize;
    while addr < text_end && site_count < MAX_SITES {
        let b0 = *(addr as *const u8);
        let b1 = *((addr + 1) as *const u8);
        let b2 = *((addr + 2) as *const u8);

        let is_site = matches!((b0, b1, b2), (0x0F, 0x05, 0xC3));

        if is_site {
            let site_addr = addr as u64;

            site_pool[site_count].store(site_addr, Ordering::Release);
            site_count += 1;
        }

        addr += 1;
    }

    site_count
}

pub unsafe fn find_call_site_return_addresses(
    module_base: *const u8,
    output_pool: &[AtomicU64; MAX_SITES],
) -> usize {
    if module_base.is_null() {
        return 0;
    }

    let (text_start, text_size) = match crate::pe::find_text_section(module_base) {
        Some(t) => t,
        None => return 0,
    };

    let text_end = (text_start as usize + text_size).saturating_sub(10);
    let module_end =
        module_base as usize + crate::pe::get_module_size(module_base as _).unwrap_or(0) as usize;
    let mut count = 0;

    let mut addr = text_start as usize + 0x1000;

    while addr < text_end && count < MAX_SITES {
        let b0 = *(addr as *const u8);

        if b0 == 0xE8 {
            let prefix_valid = if addr > text_start as usize + 1 {
                let b_minus1 = *((addr - 1) as *const u8);
                let b_minus2 = *((addr - 2) as *const u8);

                let is_valid_prefix = matches!(
                    b_minus1,
                    0xC3 |
                    // NOP
                    0x90 |
                    // REX prefixes
                    0x48 | 0x4C | 0x49 | 0x41 | 0x44 | 0x45 |
                    // MOV/LEA
                    0x8B | 0x89 | 0x8D |
                    // XOR/SUB
                    0x31 | 0x33 | 0x2B | 0x83 |
                    // PUSH (50-57)
                    0x50..=0x57 |
                    // Short JMP
                    0xEB |
                    0x74..=0x7F |
                    0xC2 | 0xCC | 0xCB | 0xCA
                );

                let not_mid_instruction = !((b_minus2 == 0x48 || b_minus2 == 0x4C)
                    && (b_minus1 == 0xE8 || b_minus1 == 0xE9));

                is_valid_prefix && not_mid_instruction
            } else {
                false
            };

            if !prefix_valid {
                addr += 1;
                continue;
            }

            let rel_offset = core::ptr::read_unaligned((addr + 1) as *const i32);
            let call_target = (addr as i64 + 5 + rel_offset as i64) as usize;

            if call_target < module_base as usize || call_target >= module_end {
                addr += 1;
                continue;
            }

            if call_target < text_start as usize || call_target >= text_end {
                addr += 1;
                continue;
            }

            let return_addr = (addr + 5) as u64;
            let post_call_byte = *((addr + 5) as *const u8);

            let is_valid_post_call = matches!(
                post_call_byte,
                0x48 | 0x4C | 0x49 | 0x41 | 0x44 | 0x45 |
                0x8B | 0x89 | 0x8D |
                0x85 |
                0x83 |
                // XOR
                0x31 | 0x33 |
                // PUSH
                0x50..=0x57 |
                // NOP
                0x90
            );

            if is_valid_post_call {
                output_pool[count].store(return_addr, Ordering::Release);
                count += 1;

                addr += 48;
                continue;
            }
        }

        addr += 1;
    }

    count
}

pub unsafe fn find_legitimate_return_addresses(
    module_base: *const u8,
    output_pool: &[AtomicU64; MAX_SITES],
) -> usize {
    find_call_site_return_addresses(module_base, output_pool)
}

pub unsafe fn init_candidate_pools() -> bool {
    if SITES_INITIALIZED.load(Ordering::Acquire) != 0 {
        return true;
    }

    crate::trace_log!("[ANALYSIS] Initializing candidate pools");

    let ntdll = match crate::hash::get_module_by_hash(crate::hash::H_NTDLL) {
        Some(m) => m as *const u8,
        None => {
            crate::trace_log!("[ANALYSIS] Ntdll not found");
            return false;
        }
    };

    let kernel32 = crate::hash::get_module_by_hash(crate::hash::H_KERNEL32).map(|m| m as *const u8);

    let kernelbase =
        crate::hash::get_module_by_hash(crate::hash::H_KERNELBASE).map(|m| m as *const u8);

    let _user32 = crate::hash::get_module_by_hash(crate::hash::H_USER32).map(|m| m as *const u8);

    let ntdll_syscall_count = scan_module_for_sites(ntdll, &NTDLL_SITES);
    NTDLL_SITE_COUNT.store(ntdll_syscall_count, Ordering::Release);
    crate::trace_log!("[ANALYSIS] Ntdll syscall sites: {}", ntdll_syscall_count);

    let ntdll_ret_count = find_call_site_return_addresses(ntdll, &NTDLL_RETURN_SITES);
    NTDLL_RETURN_COUNT.store(ntdll_ret_count, Ordering::Release);
    crate::trace_log!("[ANALYSIS] Ntdll return addresses: {}", ntdll_ret_count);

    let k32_count = if let Some(k32) = kernel32 {
        let count = find_call_site_return_addresses(k32, &KERNEL32_SITES);
        KERNEL32_SITE_COUNT.store(count, Ordering::Release);
        crate::trace_log!("[ANALYSIS] Kernel32 return addresses: {}", count);
        count
    } else {
        crate::trace_log!("[ANALYSIS] Kernel32 not found; using fallbacks");
        0
    };

    if let Some(kb) = kernelbase {
        let kb_count = find_call_site_return_addresses(kb, &KERNELBASE_SITES);
        KERNELBASE_SITE_COUNT.store(kb_count, Ordering::Release);
        crate::trace_log!("[ANALYSIS] KernelBase return addresses: {}", kb_count);
    }

    let has_return_addrs =
        k32_count > 0 || KERNELBASE_SITE_COUNT.load(Ordering::Acquire) > 0 || ntdll_ret_count > 0;

    if ntdll_syscall_count > 0 && has_return_addrs {
        SITES_INITIALIZED.store(1, Ordering::Release);
        crate::trace_log!("[ANALYSIS] Candidate pools initialized");
        true
    } else {
        crate::trace_log!(
            "[ANALYSIS] Initialization failed (syscall: {}, return: {})",
            ntdll_syscall_count,
            has_return_addrs
        );
        false
    }
}

fn select_site(pool: &[AtomicU64; MAX_SITES], count: usize) -> Option<u64> {
    if count == 0 {
        return None;
    }

    let start = random_index(count);
    for offset in 0..count {
        let idx = (start + offset) % count;
        let addr = pool[idx].load(Ordering::Acquire);
        if addr != 0 {
            return Some(addr);
        }
    }

    None
}

pub fn get_random_syscall_site() -> u64 {
    let count = NTDLL_SITE_COUNT.load(Ordering::Acquire);
    select_site(&NTDLL_SITES, count).unwrap_or(0)
}

pub fn get_random_return_site() -> u64 {
    let k32_count = KERNEL32_SITE_COUNT.load(Ordering::Acquire);
    if let Some(addr) = select_site(&KERNEL32_SITES, k32_count) {
        return addr;
    }

    let kb_count = KERNELBASE_SITE_COUNT.load(Ordering::Acquire);
    if let Some(addr) = select_site(&KERNELBASE_SITES, kb_count) {
        crate::trace_log!("[ANALYSIS] Using KernelBase fallback");
        return addr;
    }

    let ntdll_count = NTDLL_RETURN_COUNT.load(Ordering::Acquire);
    if let Some(addr) = select_site(&NTDLL_RETURN_SITES, ntdll_count) {
        crate::trace_log!("[ANALYSIS] Using Ntdll fallback");
        return addr;
    }

    crate::trace_log!("[ANALYSIS] No return addresses available");
    0
}

#[inline]
pub fn is_initialized() -> bool {
    SITES_INITIALIZED.load(Ordering::Acquire) != 0
}

#[inline]
pub fn syscall_candidate_count() -> usize {
    NTDLL_SITE_COUNT.load(Ordering::Acquire)
}

#[inline]
pub fn return_site_count() -> usize {
    KERNEL32_SITE_COUNT.load(Ordering::Acquire)
}

#[inline]
pub fn kernel32_return_count() -> usize {
    KERNEL32_SITE_COUNT.load(Ordering::Acquire)
}

#[inline]
pub fn kernelbase_return_count() -> usize {
    KERNELBASE_SITE_COUNT.load(Ordering::Acquire)
}

#[inline]
pub fn ntdll_return_count() -> usize {
    NTDLL_RETURN_COUNT.load(Ordering::Acquire)
}

pub unsafe fn find_return_addresses_on_stack(
    target_module_base: *const u8,
    max_results: usize,
) -> (usize, [u64; 16]) {
    let mut results = [0u64; 16];
    let max = if max_results > 16 { 16 } else { max_results };
    let mut count = 0;

    let stack_base = get_stack_base();
    let stack_limit = get_stack_limit();
    let mut rsp = get_current_rsp();

    if stack_base == 0 || stack_limit == 0 || rsp == 0 {
        return (0, results);
    }

    let module_size = match crate::pe::get_module_size(target_module_base as _) {
        Some(s) => s as usize,
        None => return (0, results),
    };

    let module_end = target_module_base as usize + module_size;

    while rsp < stack_base && rsp > stack_limit && count < max {
        let potential_addr = *(rsp as *const u64);

        let addr = potential_addr as usize;
        if addr >= target_module_base as usize && addr < module_end {
            if is_memory_executable(addr) {
                results[count] = potential_addr;
                count += 1;
            }
        }

        rsp += 8;
    }

    (count, results)
}

#[inline]
pub unsafe fn inspect_stack_for_module_returns(
    target_module_base: *const u8,
    max_results: usize,
) -> (usize, [u64; 16]) {
    find_return_addresses_on_stack(target_module_base, max_results)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RedirectionType {
    /// E9 XX XX XX XX - JMP rel32 (5 bytes)
    JmpRel32,
    /// E8 XX XX XX XX - CALL rel32 (5 bytes)
    CallRel32,
    /// 68 XX XX XX XX C3 - PUSH imm32 + RET (6 bytes)
    PushRet,
    /// 48 B8 XX XX XX XX XX XX XX XX FF E0 - MOV RAX, imm64 + JMP RAX (12 bytes)
    MovJmpRax,
    /// 4C 8B D1 E9 - mov r10,rcx then JMP
    SyscallPrologueRedirect,

    Clean,
}

#[derive(Debug, Clone, Copy)]
pub struct IntegrityFinding {
    pub redirection_type: RedirectionType,
    pub target_address: u64,
    pub redirection_size: usize,
}

pub unsafe fn detect_redirection_at_address(addr: usize) -> IntegrityFinding {
    if addr == 0 {
        return IntegrityFinding {
            redirection_type: RedirectionType::Clean,
            target_address: 0,
            redirection_size: 0,
        };
    }

    let b: [u8; 12] = [
        *(addr as *const u8),
        *((addr + 1) as *const u8),
        *((addr + 2) as *const u8),
        *((addr + 3) as *const u8),
        *((addr + 4) as *const u8),
        *((addr + 5) as *const u8),
        *((addr + 6) as *const u8),
        *((addr + 7) as *const u8),
        *((addr + 8) as *const u8),
        *((addr + 9) as *const u8),
        *((addr + 10) as *const u8),
        *((addr + 11) as *const u8),
    ];

    // Original: 4C 8B D1 B8 XX XX XX XX (mov r10,rcx ; mov eax, SSN)
    // Redirected pattern: 4C 8B D1 E9 XX XX XX XX (mov r10,rcx ; JMP rel32)
    if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xE9 {
        let rel_offset = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let target = (addr as i64 + 8 + rel_offset as i64) as u64;
        return IntegrityFinding {
            redirection_type: RedirectionType::SyscallPrologueRedirect,
            target_address: target,
            redirection_size: 8,
        };
    }

    if b[0] == 0xE9 {
        let rel_offset = i32::from_le_bytes([b[1], b[2], b[3], b[4]]);
        let target = (addr as i64 + 5 + rel_offset as i64) as u64;
        return IntegrityFinding {
            redirection_type: RedirectionType::JmpRel32,
            target_address: target,
            redirection_size: 5,
        };
    }

    if b[0] == 0xE8 {
        let rel_offset = i32::from_le_bytes([b[1], b[2], b[3], b[4]]);
        let target = (addr as i64 + 5 + rel_offset as i64) as u64;
        return IntegrityFinding {
            redirection_type: RedirectionType::CallRel32,
            target_address: target,
            redirection_size: 5,
        };
    }

    if b[0] == 0x68 && b[5] == 0xC3 {
        let target = u32::from_le_bytes([b[1], b[2], b[3], b[4]]) as u64;
        return IntegrityFinding {
            redirection_type: RedirectionType::PushRet,
            target_address: target,
            redirection_size: 6,
        };
    }

    if b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0 {
        let target = u64::from_le_bytes([b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]]);
        return IntegrityFinding {
            redirection_type: RedirectionType::MovJmpRax,
            target_address: target,
            redirection_size: 12,
        };
    }

    IntegrityFinding {
        redirection_type: RedirectionType::Clean,
        target_address: 0,
        redirection_size: 0,
    }
}

#[inline]
pub unsafe fn is_syscall_redirected(entry_addr: usize) -> bool {
    let info = detect_redirection_at_address(entry_addr);
    info.redirection_type != RedirectionType::Clean
}

pub unsafe fn find_clean_syscall_neighbor(
    redirected_entry: usize,
    entry_size: usize,
) -> Option<(usize, i32)> {
    for offset in 1..=5 {
        let neighbor_addr = redirected_entry.saturating_sub(entry_size * offset);
        if neighbor_addr > 0 && !is_syscall_redirected(neighbor_addr) {
            return Some((neighbor_addr, -(offset as i32)));
        }
    }

    for offset in 1..=5 {
        let neighbor_addr = redirected_entry + entry_size * offset;
        if !is_syscall_redirected(neighbor_addr) {
            return Some((neighbor_addr, offset as i32));
        }
    }

    None
}

pub fn verify_sites_integrity() -> bool {
    let syscalls = syscall_candidate_count();
    let returns = return_site_count();

    if syscalls == 0 || returns == 0 {
        crate::trace_log!(
            "[ANALYSIS] Candidate pool incomplete (sys: {}, ret: {}),",
            syscalls,
            returns
        );
        return false;
    }
    true
}
