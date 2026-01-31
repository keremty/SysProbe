#![allow(non_snake_case, dead_code)]

use std::sync::OnceLock;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::FARPROC;
use winapi::shared::ntdef::NTSTATUS;

use crate::hash::{fnv1a_hash, get_export_by_hash, get_module_by_hash, H_NTDLL};
use crate::syscalls::UNICODE_STRING;

pub(crate) type LdrLoadDllFn = unsafe extern "system" fn(
    DllPath: *const u16,
    DllCharacteristics: *const u32,
    DllName: *mut UNICODE_STRING,
    DllHandle: *mut *mut c_void,
) -> NTSTATUS;

const H_LDR_LOAD_DLL: u64 = fnv1a_hash(b"LdrLoadDll");

static LDR_LOAD_DLL: OnceLock<Option<LdrLoadDllFn>> = OnceLock::new();

#[inline(always)]
unsafe fn resolve_export(module_hash: u64, export_hash: u64) -> Option<FARPROC> {
    let module = match get_module_by_hash(module_hash) {
        Some(m) => m,
        None => {
            crate::trace_log!("[RESOLVER] Module not found");
            return None;
        }
    };
    match get_export_by_hash(module, export_hash) {
        Some(addr) if !addr.is_null() => Some(addr),
        _ => {
            crate::trace_log!("[RESOLVER] Export not found");
            None
        }
    }
}

pub fn resolve_ldr_load_dll() -> Option<LdrLoadDllFn> {
    *LDR_LOAD_DLL.get_or_init(|| unsafe {
        let addr = resolve_export(H_NTDLL, H_LDR_LOAD_DLL)?;
        Some(std::mem::transmute::<FARPROC, LdrLoadDllFn>(addr))
    })
}
