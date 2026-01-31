//! Import Address Table (IAT) structure analysis

use core::ptr;

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThreadId() -> u32;
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut core::ffi::c_void;
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut core::ffi::c_void;
    fn GetProcessHeap() -> *mut core::ffi::c_void;
    fn GetEnvironmentVariableA(lpName: *const u8, lpBuffer: *mut u8, nSize: u32) -> u32;
}

#[link(name = "user32")]
extern "system" {
    fn GetDesktopWindow() -> *mut core::ffi::c_void;
    fn GetForegroundWindow() -> *mut core::ffi::c_void;
    fn GetKeyboardLayout(idThread: u32) -> *mut core::ffi::c_void;
    fn GetKeyState(nVirtKey: i32) -> i16;
    fn GetMessagePos() -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegCloseKey(hKey: *mut core::ffi::c_void) -> i32;
    fn GetUserNameA(lpBuffer: *mut u8, pcbBuffer: *mut u32) -> i32;
}

#[repr(transparent)]
struct SyncFnPtr(*const ());

unsafe impl Sync for SyncFnPtr {}

impl SyncFnPtr {
    const fn new(ptr: *const ()) -> Self {
        Self(ptr)
    }

    #[cfg(debug_assertions)]
    #[inline]
    const fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

#[used]
#[link_section = ".rdata$iat_ref"]
static IAT_REFERENCE_TABLE: [SyncFnPtr; 15] = [
    SyncFnPtr::new(GetLastError as *const ()),
    SyncFnPtr::new(GetCurrentProcessId as *const ()),
    SyncFnPtr::new(GetCurrentThreadId as *const ()),
    SyncFnPtr::new(GetModuleHandleA as *const ()),
    SyncFnPtr::new(GetModuleHandleW as *const ()),
    SyncFnPtr::new(GetProcessHeap as *const ()),
    SyncFnPtr::new(GetEnvironmentVariableA as *const ()),
    SyncFnPtr::new(GetDesktopWindow as *const ()),
    SyncFnPtr::new(GetForegroundWindow as *const ()),
    SyncFnPtr::new(GetKeyboardLayout as *const ()),
    SyncFnPtr::new(GetKeyState as *const ()),
    SyncFnPtr::new(GetMessagePos as *const ()),
    SyncFnPtr::new(RegCloseKey as *const ()),
    SyncFnPtr::new(GetUserNameA as *const ()),
    SyncFnPtr::new(ptr::null()),
];

#[cfg(debug_assertions)]
#[inline(never)]
pub fn validate_iat_integrity() -> bool {
    let entry = unsafe { core::ptr::read_volatile(&IAT_REFERENCE_TABLE[0]) };
    !entry.is_null()
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn validate_iat_integrity() -> bool {
    true
}

#[inline(never)]
pub fn ensure_import_references() {
    unsafe {
        let _ = core::ptr::read_volatile(&(GetLastError as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetCurrentProcessId as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetCurrentThreadId as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetModuleHandleA as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetModuleHandleW as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetProcessHeap as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetEnvironmentVariableA as *const () as usize));

        let _ = core::ptr::read_volatile(&(GetDesktopWindow as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetForegroundWindow as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetKeyboardLayout as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetKeyState as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetMessagePos as *const () as usize));

        let _ = core::ptr::read_volatile(&(RegCloseKey as *const () as usize));
        let _ = core::ptr::read_volatile(&(GetUserNameA as *const () as usize));
    }
}

const _: () = {
    assert!(core::mem::size_of::<SyncFnPtr>() == core::mem::size_of::<*const ()>());
};
