#![allow(non_snake_case)]

use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;

use crate::nt::nt_success;
use crate::syscalls::nt_read_virtual_memory;

pub const HIGH_ENTROPY_THRESHOLD: f64 = 6.5;
pub const DEFAULT_MAX_READ: usize = 0x10000;

pub fn region_entropy(process: HANDLE, base: usize, size: usize, max_read: usize) -> Option<f64> {
    if base == 0 || size == 0 {
        return None;
    }

    let read_size = size.min(max_read).max(0x1000);
    let mut buf = vec![0u8; read_size];
    let mut read_len: usize = 0;

    let status = unsafe {
        nt_read_virtual_memory(
            process,
            base as *mut c_void,
            buf.as_mut_ptr() as *mut c_void,
            read_size,
            &mut read_len as *mut usize,
        )
    };

    if !nt_success(status) || read_len < 64 {
        return None;
    }

    Some(shannon_entropy(&buf[..read_len]))
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in counts.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}
