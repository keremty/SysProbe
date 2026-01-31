//! Syscall mechanism research - analyzing Windows NT syscall internals

use std::arch::global_asm;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

use winapi::shared::minwindef::FARPROC;
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID};
use winapi::um::winnt::{CONTEXT, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE};

use crate::hash::{fnv1a_hash, get_export_by_hash, get_module_by_hash, H_NTDLL};

pub use crate::nt::{
    nt_success, LdrSystemDllInitBlock, CLIENT_ID, IO_STATUS_BLOCK, LDR_DATA_TABLE_ENTRY,
    LIST_ENTRY, OBJECT_ATTRIBUTES, PEB, PEB_LDR_DATA, TEB, UNICODE_STRING,
};

pub use crate::pe::{find_text_section, find_text_section_with_rva};

pub use crate::ssn_resolver::{
    address_in_loaded_module, cache_invalidate_ntdll_change, clear_ssn_cache,
    get_ldr_system_dll_init_block, get_module_timestamp, get_peb, get_preferred_ntdll, get_teb,
    is_amd64_ntdll_module, is_chpe_or_sxs, is_sxs_or_downlevel_ntdll, kernel_system_call_number,
    kernel_system_timestamp, mark_ssn_poisoned, module_full_path_lower,
    reset_ssn_poison_if_allowed, resolve_ssn_by_hash, safe_read_u64, ssn_poisoned, SSN_CACHE,
    SSN_GEN, SSN_POISONED,
};

const H_NT_CLOSE: u64 = fnv1a_hash(b"NtClose");
const H_NT_QUERY_SYSTEM_INFORMATION: u64 = fnv1a_hash(b"NtQuerySystemInformation");
const H_NT_QUERY_INFORMATION_PROCESS: u64 = fnv1a_hash(b"NtQueryInformationProcess");
const H_NT_QUERY_INFORMATION_THREAD: u64 = fnv1a_hash(b"NtQueryInformationThread");
const H_NT_GET_CONTEXT_THREAD: u64 = fnv1a_hash(b"NtGetContextThread");
const H_NT_READ_VIRTUAL_MEMORY: u64 = fnv1a_hash(b"NtReadVirtualMemory");
const H_NT_QUERY_VIRTUAL_MEMORY: u64 = fnv1a_hash(b"NtQueryVirtualMemory");
const H_NT_OPEN_PROCESS: u64 = fnv1a_hash(b"NtOpenProcess");
const H_NT_OPEN_THREAD: u64 = fnv1a_hash(b"NtOpenThread");

const STATUS_UNSUCCESSFUL: i32 = 0xC0000001u32 as i32;

global_asm!(
    r#"
.section .text
.global indirect_syscall_entry
.global asm_get_peb
.global asm_get_teb
.align 16

indirect_syscall_entry:
    .seh_proc indirect_syscall_entry
    sub rsp, 0x28
    .seh_stackalloc 0x28
    .seh_endprologue

    movzx eax, cx             // SSN -> EAX
    mov rcx, r8               // arg1 -> RCX
    mov rdx, r9               // arg2 -> RDX
    mov r8, [rsp + 0x48]      // arg3 -> R8
    mov r9, [rsp + 0x50]      // arg4 -> R9

    mov r10, rcx              // per syscall ABI

    mov rax, [rsp + 0x58]     // arg5
    mov [rsp + 0x20], rax
    mov rax, [rsp + 0x60]     // arg6
    mov [rsp + 0x28], rax
    mov rax, [rsp + 0x68]     // arg7
    mov [rsp + 0x30], rax
    mov rax, [rsp + 0x70]     // arg8
    mov [rsp + 0x38], rax
    mov rax, [rsp + 0x78]     // arg9
    mov [rsp + 0x40], rax
    mov rax, [rsp + 0x80]     // arg10
    mov [rsp + 0x48], rax
    mov rax, [rsp + 0x88]     // arg11
    mov [rsp + 0x50], rax

    syscall

    add rsp, 0x28
    ret
    .seh_endproc


.align 16
asm_get_peb:
    mov rax, gs:[0x60]
    ret

.align 16
asm_get_teb:
    mov rax, gs:[0x30]
    ret
"#
);

extern "C" {

    fn indirect_syscall_entry(
        ssn: u16,
        syscall_addr: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        arg6: u64,
        arg7: u64,
        arg8: u64,
        arg9: u64,
        arg10: u64,
        arg11: u64,
    ) -> NTSTATUS;
}

static SYSCALL_SITE: AtomicU64 = AtomicU64::new(0);
static DIRECT_NTDLL: AtomicBool = AtomicBool::new(false);

type NtCloseFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;
type NtQuerySystemInformationFn =
    unsafe extern "system" fn(u32, PVOID, u32, *mut u32) -> NTSTATUS;
type NtQueryInformationProcessFn =
    unsafe extern "system" fn(HANDLE, u32, PVOID, u32, *mut u32) -> NTSTATUS;
type NtQueryInformationThreadFn =
    unsafe extern "system" fn(HANDLE, u32, PVOID, u32, *mut u32) -> NTSTATUS;
type NtGetContextThreadFn = unsafe extern "system" fn(HANDLE, *mut CONTEXT) -> NTSTATUS;
type NtReadVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, PVOID, PVOID, usize, *mut usize) -> NTSTATUS;
type NtQueryVirtualMemoryFn =
    unsafe extern "system" fn(HANDLE, PVOID, u32, PVOID, usize, *mut usize) -> NTSTATUS;
type NtOpenProcessFn =
    unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> NTSTATUS;
type NtOpenThreadFn =
    unsafe extern "system" fn(*mut HANDLE, u32, *mut OBJECT_ATTRIBUTES, *mut CLIENT_ID) -> NTSTATUS;

static NT_CLOSE: OnceLock<Option<NtCloseFn>> = OnceLock::new();
static NT_QSI: OnceLock<Option<NtQuerySystemInformationFn>> = OnceLock::new();
static NT_QIP: OnceLock<Option<NtQueryInformationProcessFn>> = OnceLock::new();
static NT_QIT: OnceLock<Option<NtQueryInformationThreadFn>> = OnceLock::new();
static NT_GCT: OnceLock<Option<NtGetContextThreadFn>> = OnceLock::new();
static NT_RVM: OnceLock<Option<NtReadVirtualMemoryFn>> = OnceLock::new();
static NT_QVM: OnceLock<Option<NtQueryVirtualMemoryFn>> = OnceLock::new();
static NT_OP: OnceLock<Option<NtOpenProcessFn>> = OnceLock::new();
static NT_OT: OnceLock<Option<NtOpenThreadFn>> = OnceLock::new();

pub fn set_direct_ntdll(enable: bool) {
    DIRECT_NTDLL.store(enable, Ordering::Release);
}

unsafe fn resolve_ntdll_export(hash: u64) -> Option<FARPROC> {
    let ntdll = get_module_by_hash(H_NTDLL)?;
    let proc = get_export_by_hash(ntdll, hash)?;
    Some(proc)
}

pub unsafe fn ensure_syscall_site() -> bool {
    if SYSCALL_SITE.load(Ordering::Acquire) != 0 {
        return true;
    }

    let (text_start, text_end) = match get_ntdll_text_bounds() {
        Some(b) => b,
        None => return false,
    };

    const TARGET_EXPORTS: &[u64] = &[fnv1a_hash(b"NtQuerySystemInformation")];

    for &h in TARGET_EXPORTS {
        if let Some((_ssn, entry)) = resolve_ssn_by_hash(h) {
            let start_addr = entry as usize;

            if start_addr < text_start || start_addr >= text_end {
                continue;
            }
            if start_addr + 32 > text_end {
                continue;
            }

            //(0F 05 C3)
            for i in 0..30 {
                let ptr = (start_addr + i) as *const u8;
                if *ptr == 0x0F && *ptr.add(1) == 0x05 && *ptr.add(2) == 0xC3 {
                    SYSCALL_SITE.store(ptr as u64, Ordering::Release);
                    return true;
                }
            }
        }
    }

    false
}

unsafe fn get_ntdll_text_bounds() -> Option<(usize, usize)> {
    let ntdll = get_module_by_hash(H_NTDLL)?;
    if ntdll.is_null() {
        return None;
    }

    let ntdll_addr = ntdll as usize;
    let dos_header = ntdll as *const IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != 0x5A4D {
        return None;
    }

    let lfanew = (*dos_header).e_lfanew as usize;
    let nt_headers = (ntdll_addr + lfanew) as *const IMAGE_NT_HEADERS64;

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let (text_ptr, text_size) = find_text_section(ntdll as *const u8)?;
    let start = text_ptr as usize;
    let end = start + text_size;

    Some((start, end))
}

#[inline]
pub fn get_syscall_site() -> u64 {
    #[inline(always)]
    fn validate_site(addr: u64) -> bool {
        if addr == 0 {
            return false;
        }
        unsafe {
            let ptr = addr as *const u8;
            // syscall = 0F 05
            let b0 = core::ptr::read_volatile(ptr);
            let b1 = core::ptr::read_volatile(ptr.add(1));
            b0 == 0x0F && b1 == 0x05
        }
    }

    let cached = SYSCALL_SITE.load(Ordering::Acquire);
    if validate_site(cached) {
        return cached;
    }

    unsafe {
        ensure_syscall_site();
    }

    let addr = SYSCALL_SITE.load(Ordering::Acquire);
    if validate_site(addr) {
        return addr;
    }

    crate::trace_log!("[ANALYSIS] No valid site found");
    0
}

#[inline]
pub fn get_instrumented_return_addr() -> u64 {
    static INIT_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    if !INIT_DONE.load(std::sync::atomic::Ordering::Acquire) {
        crate::trace_log!("[ANALYSIS] Initializing candidate pools (first call)");
        unsafe {
            let success = crate::call_chain_analysis::init_candidate_pools();
            if success {
                INIT_DONE.store(true, std::sync::atomic::Ordering::Release);
                crate::trace_log!("[ANALYSIS] Candidate pools ready");
            }
        }
    }

    crate::call_chain_analysis::get_random_return_site()
}

pub fn init_call_chain_analysis() -> bool {
    unsafe {
        let result = crate::call_chain_analysis::init_candidate_pools();
        if result {
            crate::trace_log!(
                "[ANALYSIS] Initialized: {} syscall candidates, {} return sites",
                crate::call_chain_analysis::syscall_candidate_count(),
                crate::call_chain_analysis::return_site_count()
            );
        } else {
            crate::trace_log!("[ANALYSIS] Initialization failed; fallback will be used");
        }
        result
    }
}

#[inline(never)]

pub unsafe fn nt_close(handle: HANDLE) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_CLOSE.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_CLOSE)?;
            Some(mem::transmute::<FARPROC, NtCloseFn>(addr))
        }) {
            return func(handle);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_CLOSE) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        handle as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]

pub unsafe fn nt_query_virtual_memory(
    process: HANDLE,
    base_address: PVOID,
    info_class: u32,
    info_buffer: PVOID,
    info_length: usize,
    return_length: *mut usize,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_QVM.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_QUERY_VIRTUAL_MEMORY)?;
            Some(mem::transmute::<FARPROC, NtQueryVirtualMemoryFn>(addr))
        }) {
            return func(
                process,
                base_address,
                info_class,
                info_buffer,
                info_length,
                return_length,
            );
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_QUERY_VIRTUAL_MEMORY) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        process as u64,
        base_address as u64,
        info_class as u64,
        info_buffer as u64,
        info_length as u64,
        return_length as u64,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]
pub unsafe fn nt_query_system_information(
    info_class: u32,
    info_buffer: PVOID,
    info_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_QSI.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_QUERY_SYSTEM_INFORMATION)?;
            Some(mem::transmute::<FARPROC, NtQuerySystemInformationFn>(addr))
        }) {
            return func(info_class, info_buffer, info_length, return_length);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_QUERY_SYSTEM_INFORMATION) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        info_class as u64,
        info_buffer as u64,
        info_length as u64,
        return_length as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]
pub unsafe fn nt_query_information_process(
    process: HANDLE,
    info_class: u32,
    info_buffer: PVOID,
    info_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_QIP.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_QUERY_INFORMATION_PROCESS)?;
            Some(mem::transmute::<FARPROC, NtQueryInformationProcessFn>(addr))
        }) {
            return func(process, info_class, info_buffer, info_length, return_length);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_QUERY_INFORMATION_PROCESS) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        process as u64,
        info_class as u64,
        info_buffer as u64,
        info_length as u64,
        return_length as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]
pub unsafe fn nt_query_information_thread(
    thread: HANDLE,
    info_class: u32,
    info_buffer: PVOID,
    info_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_QIT.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_QUERY_INFORMATION_THREAD)?;
            Some(mem::transmute::<FARPROC, NtQueryInformationThreadFn>(addr))
        }) {
            return func(thread, info_class, info_buffer, info_length, return_length);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_QUERY_INFORMATION_THREAD) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        thread as u64,
        info_class as u64,
        info_buffer as u64,
        info_length as u64,
        return_length as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]
pub unsafe fn nt_get_context_thread(
    thread: HANDLE,
    context: *mut CONTEXT,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_GCT.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_GET_CONTEXT_THREAD)?;
            Some(mem::transmute::<FARPROC, NtGetContextThreadFn>(addr))
        }) {
            return func(thread, context);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_GET_CONTEXT_THREAD) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        thread as u64,
        context as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]
pub unsafe fn nt_read_virtual_memory(
    process: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    size: usize,
    return_length: *mut usize,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_RVM.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_READ_VIRTUAL_MEMORY)?;
            Some(mem::transmute::<FARPROC, NtReadVirtualMemoryFn>(addr))
        }) {
            return func(process, base_address, buffer, size, return_length);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_READ_VIRTUAL_MEMORY) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        process as u64,
        base_address as u64,
        buffer as u64,
        size as u64,
        return_length as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]
pub unsafe fn nt_open_thread(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_OT.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_OPEN_THREAD)?;
            Some(mem::transmute::<FARPROC, NtOpenThreadFn>(addr))
        }) {
            return func(thread_handle, desired_access, object_attributes, client_id);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_OPEN_THREAD) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        thread_handle as u64,
        desired_access as u64,
        object_attributes as u64,
        client_id as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

#[inline(never)]
pub unsafe fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS {
    if DIRECT_NTDLL.load(Ordering::Acquire) {
        if let Some(func) = *NT_OP.get_or_init(|| unsafe {
            let addr = resolve_ntdll_export(H_NT_OPEN_PROCESS)?;
            Some(mem::transmute::<FARPROC, NtOpenProcessFn>(addr))
        }) {
            return func(process_handle, desired_access, object_attributes, client_id);
        }
    }
    let (ssn, _entry) = match resolve_ssn_by_hash(H_NT_OPEN_PROCESS) {
        Some(s) => s,
        None => return STATUS_UNSUCCESSFUL,
    };

    let syscall_addr = get_syscall_site();
    if syscall_addr == 0 {
        return STATUS_UNSUCCESSFUL;
    }

    indirect_syscall_entry(
        ssn,
        syscall_addr,
        process_handle as u64,
        desired_access as u64,
        object_attributes as u64,
        client_id as u64,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}
