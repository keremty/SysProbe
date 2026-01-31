use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrd};

use winapi::ctypes::c_void;

static VERBOSE_MODE: AtomicBool = AtomicBool::new(false);
static VERBOSE_CHECKED: AtomicBool = AtomicBool::new(false);
static CONSOLE_ALLOCATED: AtomicBool = AtomicBool::new(false);
static STDOUT_HANDLE: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub fn is_verbose_debug() -> bool {
    if !VERBOSE_CHECKED.load(AtomicOrd::Acquire) {
        let enabled = check_env_flag("VERBOSE_DEBUG", false);
        VERBOSE_MODE.store(enabled, AtomicOrd::Release);
        VERBOSE_CHECKED.store(true, AtomicOrd::Release);

        if enabled {
            unsafe {
                ensure_console_allocated();
            }
        }
    }
    VERBOSE_MODE.load(AtomicOrd::Acquire)
}

unsafe fn ensure_console_allocated() {
    if CONSOLE_ALLOCATED.load(AtomicOrd::Acquire) {
        return;
    }

    let k32 = match crate::hash::get_module_by_hash(crate::hash::H_KERNEL32) {
        Some(h) => h,
        None => return,
    };

    type FnAllocConsole = unsafe extern "system" fn() -> i32;
    const H_ALLOC_CONSOLE: u64 = crate::hash::fnv1a_hash(b"AllocConsole");
    if let Some(f) = crate::hash::get_export_by_hash(k32, H_ALLOC_CONSOLE) {
        let alloc_console: FnAllocConsole =
            std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnAllocConsole>(f);
        let _ = alloc_console();
    }

    type FnGetStdHandle = unsafe extern "system" fn(u32) -> *mut c_void;
    const H_GET_STD_HANDLE: u64 = crate::hash::fnv1a_hash(b"GetStdHandle");
    const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5; // -11 as u32

    if let Some(f) = crate::hash::get_export_by_hash(k32, H_GET_STD_HANDLE) {
        let get_std_handle: FnGetStdHandle =
            std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnGetStdHandle>(f);
        let handle = get_std_handle(STD_OUTPUT_HANDLE);
        if !handle.is_null() && handle as isize != -1 {
            STDOUT_HANDLE.store(handle as usize, AtomicOrd::Release);
        }
    }

    CONSOLE_ALLOCATED.store(true, AtomicOrd::Release);
}

#[inline]
pub unsafe fn verbose_log(msg: &str) {
    if !is_verbose_debug() {
        return;
    }

    let handle = STDOUT_HANDLE.load(AtomicOrd::Acquire);
    if handle == 0 {
        return;
    }

    let k32 = match crate::hash::get_module_by_hash(crate::hash::H_KERNEL32) {
        Some(h) => h,
        None => return,
    };

    type FnWriteFile =
        unsafe extern "system" fn(*mut c_void, *const u8, u32, *mut u32, *mut c_void) -> i32;
    const H_WRITE_FILE: u64 = crate::hash::fnv1a_hash(b"WriteFile");

    let write_file = match crate::hash::get_export_by_hash(k32, H_WRITE_FILE) {
        Some(f) => std::mem::transmute::<winapi::shared::minwindef::FARPROC, FnWriteFile>(f),
        None => return,
    };

    let mut buf = [0u8; 512];
    let len = msg.len().min(509);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    buf[len] = b'\r';
    buf[len + 1] = b'\n';

    let mut written: u32 = 0;
    write_file(
        handle as *mut c_void,
        buf.as_ptr(),
        (len + 2) as u32,
        &mut written,
        std::ptr::null_mut(),
    );
}

#[macro_export]
macro_rules! verbose_dbg {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            if $crate::config::is_verbose_debug() {
                let msg = format!($($arg)*);
                unsafe { $crate::config::verbose_log(&msg); }
            }
        }

    }};
}

#[macro_export]
macro_rules! debug_print {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            $crate::verbose_dbg!($($arg)*);
        }

    }};
}

pub fn should_log() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }

    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| std::env::var("TRACE_VERBOSE").is_ok() || is_verbose_debug())
}

pub fn ssn_strict() -> bool {
    check_env_flag("SSN_STRICT", true)
}

pub fn ssn_lenient() -> bool {
    check_env_flag("SSN_LENIENT", true)
}

pub fn ssn_allow_bad_entry() -> bool {
    check_env_flag("SSN_ALLOW_BAD_ENTRY", false)
}

pub fn ssn_reset_allowed() -> bool {
    check_env_flag("SSN_RESET", true)
}

pub fn kernel_ssn_tolerance() -> u32 {
    parse_u32_key("KERNEL_SSN_TOLERANCE").unwrap_or(0x200)
}

fn get_env_var(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn check_env_flag(key: &str, default_if_set: bool) -> bool {
    if let Some(val) = get_env_var(key) {
        let v = val.to_ascii_lowercase();

        if v == "1" || v == "true" || v == "yes" {
            return true;
        }

        if default_if_set && (v == "0" || v == "false" || v == "no") {
            return false;
        }

        return false;
    }
    default_if_set
}

fn parse_u32_key(key: &str) -> Option<u32> {
    get_env_var(key).and_then(|v| v.parse::<u32>().ok())
}
