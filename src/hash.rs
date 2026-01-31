use std::sync::atomic::{AtomicU64, Ordering};
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS64,
};

pub use crate::syscalls::{
    get_peb, LDR_DATA_TABLE_ENTRY, LIST_ENTRY, PEB, PEB_LDR_DATA, UNICODE_STRING,
};

pub const FNV_OFFSET: u64 = 0xCBF29CE484222325;
pub const FNV_PRIME: u64 = 0x100000001B3;
pub const HASH_SALT: u64 = 0x0;
pub const HASH_TAG: u64 = 0x0;

pub static HASH_CACHE: [AtomicU64; 46] = [const { AtomicU64::new(0) }; 46];

pub const fn fnv1a_hash(s: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < s.len() {
        hash ^= s[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }

    hash ^ HASH_SALT
}

#[inline]
pub fn fnv1a_hash_runtime(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash ^ HASH_SALT
}

pub const H_NTDLL: u64 = fnv1a_hash(b"ntdll.dll");
pub const H_KERNEL32: u64 = fnv1a_hash(b"kernel32.dll");
pub const H_USER32: u64 = fnv1a_hash(b"user32.dll");
pub const H_KERNELBASE: u64 = fnv1a_hash(b"kernelbase.dll");

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ApiKind {
    NtDelayExecution = 0,
    NtQuerySystemInformation = 4,
    NtTerminateProcess = 5,
    NtQueryPerformanceCounter = 6,
    NtOpenSection = 7,
    NtMapViewOfSection = 8,
    NtUnmapViewOfSection = 9,
    NtClose = 10,
    NtQueryInformationProcess = 11,
    NtWaitForSingleObject = 12,
    NtQuerySystemTime = 13,

    RtlAddVectoredExceptionHandler = 18,
    RtlRemoveVectoredExceptionHandler = 19,
    RtlCaptureStackBackTrace = 20,
    RtlUserThreadStart = 21,

    GetCurrentThread = 22,
    GetCursorPos = 23,
    GetTickCount64 = 24,
    GetLastInputInfo = 25,
    QueryUnbiasedInterruptTime = 28,
    LdrRegisterDllNotification = 29,
    GetModuleFileNameW = 33,
    GetCurrentProcess = 34,
    GetCurrentThreadId = 35,
    QueryInterruptTime = 36,
    QueryInterruptTimePrecise = 37,
    VirtualFree = 39,
    MapViewOfFile = 40,
    UnmapViewOfFile = 41,
    GetSystemTimePreciseAsFileTime = 42,
    LdrUnregisterDllNotification = 43,
    RaiseException = 44,
    OpenThread = 45,
}

pub const KINDS: [ApiKind; 33] = [
    ApiKind::NtDelayExecution,
    ApiKind::NtQuerySystemInformation,
    ApiKind::NtTerminateProcess,
    ApiKind::NtQueryPerformanceCounter,
    ApiKind::NtOpenSection,
    ApiKind::NtMapViewOfSection,
    ApiKind::NtUnmapViewOfSection,
    ApiKind::NtClose,
    ApiKind::NtQueryInformationProcess,
    ApiKind::NtWaitForSingleObject,
    ApiKind::NtQuerySystemTime,
    ApiKind::RtlAddVectoredExceptionHandler,
    ApiKind::RtlRemoveVectoredExceptionHandler,
    ApiKind::RtlCaptureStackBackTrace,
    ApiKind::RtlUserThreadStart,
    ApiKind::GetCurrentThread,
    ApiKind::GetCursorPos,
    ApiKind::GetTickCount64,
    ApiKind::GetLastInputInfo,
    ApiKind::QueryUnbiasedInterruptTime,
    ApiKind::LdrRegisterDllNotification,
    ApiKind::GetModuleFileNameW,
    ApiKind::GetCurrentProcess,
    ApiKind::GetCurrentThreadId,
    ApiKind::QueryInterruptTime,
    ApiKind::QueryInterruptTimePrecise,
    ApiKind::VirtualFree,
    ApiKind::MapViewOfFile,
    ApiKind::UnmapViewOfFile,
    ApiKind::GetSystemTimePreciseAsFileTime,
    ApiKind::LdrUnregisterDllNotification,
    ApiKind::RaiseException,
    ApiKind::OpenThread,
];

#[inline]
fn api_kind_name(kind: ApiKind) -> &'static [u8] {
    match kind {
        ApiKind::NtDelayExecution => b"NtDelayExecution",
        ApiKind::NtQuerySystemInformation => b"NtQuerySystemInformation",
        ApiKind::NtTerminateProcess => b"NtTerminateProcess",
        ApiKind::NtQueryPerformanceCounter => b"NtQueryPerformanceCounter",
        ApiKind::NtOpenSection => b"NtOpenSection",
        ApiKind::NtMapViewOfSection => b"NtMapViewOfSection",
        ApiKind::NtUnmapViewOfSection => b"NtUnmapViewOfSection",
        ApiKind::NtClose => b"NtClose",
        ApiKind::NtQueryInformationProcess => b"NtQueryInformationProcess",
        ApiKind::NtWaitForSingleObject => b"NtWaitForSingleObject",
        ApiKind::NtQuerySystemTime => b"NtQuerySystemTime",
        ApiKind::RtlAddVectoredExceptionHandler => b"RtlAddVectoredExceptionHandler",
        ApiKind::RtlRemoveVectoredExceptionHandler => b"RtlRemoveVectoredExceptionHandler",
        ApiKind::RtlCaptureStackBackTrace => b"RtlCaptureStackBackTrace",
        ApiKind::RtlUserThreadStart => b"RtlUserThreadStart",
        ApiKind::GetCurrentThread => b"GetCurrentThread",
        ApiKind::GetCursorPos => b"GetCursorPos",
        ApiKind::GetTickCount64 => b"GetTickCount64",
        ApiKind::GetLastInputInfo => b"GetLastInputInfo",
        ApiKind::QueryUnbiasedInterruptTime => b"QueryUnbiasedInterruptTime",
        ApiKind::LdrRegisterDllNotification => b"LdrRegisterDllNotification",
        ApiKind::GetModuleFileNameW => b"GetModuleFileNameW",
        ApiKind::GetCurrentProcess => b"GetCurrentProcess",
        ApiKind::GetCurrentThreadId => b"GetCurrentThreadId",
        ApiKind::QueryInterruptTime => b"QueryInterruptTime",
        ApiKind::QueryInterruptTimePrecise => b"QueryInterruptTimePrecise",
        ApiKind::VirtualFree => b"VirtualFree",
        ApiKind::MapViewOfFile => b"MapViewOfFile",
        ApiKind::UnmapViewOfFile => b"UnmapViewOfFile",
        ApiKind::GetSystemTimePreciseAsFileTime => b"GetSystemTimePreciseAsFileTime",
        ApiKind::LdrUnregisterDllNotification => b"LdrUnregisterDllNotification",
        ApiKind::RaiseException => b"RaiseException",
        ApiKind::OpenThread => b"OpenThread",
    }
}

#[inline]
pub fn match_hash(h: u64) -> Option<ApiKind> {
    for &kind in KINDS.iter() {
        if fnv1a_hash(api_kind_name(kind)) == h {
            return Some(kind);
        }
    }
    None
}

#[inline]
pub fn get_decoded_hash(kind: ApiKind) -> u64 {
    let idx = kind as usize;
    if idx >= HASH_CACHE.len() {
        return 0;
    }

    let cached = HASH_CACHE[idx].load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }

    let decoded = fnv1a_hash(api_kind_name(kind));
    HASH_CACHE[idx].store(decoded, Ordering::Relaxed);
    decoded
}

pub const H_NT_DELAY_EXECUTION: u64 = fnv1a_hash(b"NtDelayExecution");
pub const H_NT_QUERY_SYSTEM_INFO: u64 = fnv1a_hash(b"NtQuerySystemInformation");
pub const H_NT_TERMINATE_PROCESS: u64 = fnv1a_hash(b"NtTerminateProcess");
pub const H_NT_QUERY_PERFORMANCE_COUNTER: u64 = fnv1a_hash(b"NtQueryPerformanceCounter");
pub const H_NT_OPEN_SECTION: u64 = fnv1a_hash(b"NtOpenSection");
pub const H_NT_MAP_VIEW_OF_SECTION: u64 = fnv1a_hash(b"NtMapViewOfSection");
pub const H_NT_UNMAP_VIEW_OF_SECTION: u64 = fnv1a_hash(b"NtUnmapViewOfSection");
pub const H_NT_CLOSE: u64 = fnv1a_hash(b"NtClose");
pub const H_NT_QUERY_INFO_PROCESS: u64 = fnv1a_hash(b"NtQueryInformationProcess");
pub const H_NT_WAIT_FOR_SINGLE_OBJECT: u64 = fnv1a_hash(b"NtWaitForSingleObject");
pub const H_RTL_ADD_VEH: u64 = fnv1a_hash(b"RtlAddVectoredExceptionHandler");
pub const H_RTL_REMOVE_VEH: u64 = fnv1a_hash(b"RtlRemoveVectoredExceptionHandler");
pub const H_RTL_CAPTURE_STACK_BACKTRACE: u64 = fnv1a_hash(b"RtlCaptureStackBackTrace");
pub const H_GET_CURRENT_THREAD: u64 = fnv1a_hash(b"GetCurrentThread");
pub const H_GET_CURSOR_POS: u64 = fnv1a_hash(b"GetCursorPos");
pub const H_GET_TICK_COUNT64: u64 = fnv1a_hash(b"GetTickCount64");
pub const H_GET_LAST_INPUT_INFO: u64 = fnv1a_hash(b"GetLastInputInfo");
pub const H_QUERY_UNBIASED_INTERRUPT_TIME: u64 = fnv1a_hash(b"QueryUnbiasedInterruptTime");
pub const H_LDR_REGISTER_DLL_NOTIFICATION: u64 = fnv1a_hash(b"LdrRegisterDllNotification");
pub const H_GET_MODULE_FILE_NAME_W: u64 = fnv1a_hash(b"GetModuleFileNameW");
pub const H_GET_CURRENT_PROCESS: u64 = fnv1a_hash(b"GetCurrentProcess");
pub const H_GET_CURRENT_THREAD_ID: u64 = fnv1a_hash(b"GetCurrentThreadId");
pub const H_QUERY_INTERRUPT_TIME: u64 = fnv1a_hash(b"QueryInterruptTime");
pub const H_NT_QUERY_SYSTEM_TIME: u64 = fnv1a_hash(b"NtQuerySystemTime");
pub const H_QUERY_INTERRUPT_TIME_PRECISE: u64 = fnv1a_hash(b"QueryInterruptTimePrecise");
pub const H_VIRTUAL_FREE: u64 = fnv1a_hash(b"VirtualFree");
pub const H_MAP_VIEW_OF_FILE: u64 = fnv1a_hash(b"MapViewOfFile");
pub const H_UNMAP_VIEW_OF_FILE: u64 = fnv1a_hash(b"UnmapViewOfFile");
pub const H_GET_SYSTEM_TIME_PRECISE: u64 = fnv1a_hash(b"GetSystemTimePreciseAsFileTime");
pub const H_LDR_UNREGISTER_DLL_NOTIFICATION: u64 = fnv1a_hash(b"LdrUnregisterDllNotification");
pub const H_LDR_LOAD_DLL: u64 = fnv1a_hash(b"LdrLoadDll");
pub const H_RAISE_EXCEPTION: u64 = fnv1a_hash(b"RaiseException");
pub const H_OPEN_THREAD: u64 = fnv1a_hash(b"OpenThread");
pub const H_CLOSE_HANDLE: u64 = fnv1a_hash(b"CloseHandle");
pub const H_KI_USER_EXCEPTION_DISPATCHER: u64 = fnv1a_hash(b"KiUserExceptionDispatcher");
pub const H_LDR_DISPATCH_USER_CALL_TARGET: u64 = fnv1a_hash(b"LdrpDispatchUserCallTarget");
pub const H_ADD_VECTORED_EXCEPTION_HANDLER: u64 = fnv1a_hash(b"AddVectoredExceptionHandler");
pub const H_REMOVE_VECTORED_EXCEPTION_HANDLER: u64 = fnv1a_hash(b"RemoveVectoredExceptionHandler");
pub const H_RTL_USER_THREAD_START: u64 = fnv1a_hash(b"RtlUserThreadStart");
pub const H_NT_CONTINUE: u64 = fnv1a_hash(b"NtContinue");

pub unsafe fn get_module_by_hash(target_hash: u64) -> Option<HMODULE> {
    let peb = get_peb();
    if peb.is_null() || (*peb).Ldr.is_null() {
        return None;
    }
    let ldr = (*peb).Ldr;
    let head = &mut (*ldr).InMemoryOrderModuleList as *mut LIST_ENTRY;
    let mut curr = (*head).Flink;

    while curr != head {
        let entry = (curr as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY;
        if !(*entry).BaseDllName.Buffer.is_null() {
            let name_len = (*entry).BaseDllName.Length as usize / 2;
            let name_slice = std::slice::from_raw_parts((*entry).BaseDllName.Buffer, name_len);

            let mut buf = [0u8; 64];
            let len = name_len.min(buf.len());
            for i in 0..len {
                buf[i] = (name_slice[i] as u8).to_ascii_lowercase();
            }

            let computed_hash = fnv1a_hash_runtime(&buf[..len]);
            if computed_hash == target_hash {
                return Some((*entry).DllBase as HMODULE);
            }
        }
        curr = (*curr).Flink;
    }
    None
}

pub unsafe fn get_export_by_hash(module: HMODULE, target_hash: u64) -> Option<FARPROC> {
    let dos_header = module as PIMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return None;
    }

    let nt_headers = (module as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != 0x4550 {
        return None;
    }

    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = (module as usize + export_dir_rva as usize) as PIMAGE_EXPORT_DIRECTORY;
    let names = (module as usize + (*export_dir).AddressOfNames as usize) as *const u32;
    let ordinals = (module as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;
    let functions = (module as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;

    let num_names = (*export_dir).NumberOfNames as usize;

    for i in 0..num_names {
        let name_rva = *names.add(i);
        let name_ptr = (module as usize + name_rva as usize) as *const i8;

        let mut name_len = 0usize;
        while *name_ptr.add(name_len) != 0 && name_len < 256 {
            name_len += 1;
        }
        let name_bytes = std::slice::from_raw_parts(name_ptr as *const u8, name_len);
        let computed_hash = fnv1a_hash_runtime(name_bytes);

        if computed_hash == target_hash {
            let ordinal = *ordinals.add(i) as usize;
            let func_rva = *functions.add(ordinal);
            return Some((module as usize + func_rva as usize) as FARPROC);
        }
    }
    None
}
