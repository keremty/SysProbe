#![allow(non_snake_case)]

use winapi::shared::minwindef::HMODULE;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_PE_SIGNATURE: u32 = 0x4550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B; // PE32
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC_LOCAL: u16 = 0x20B; // PE32+

#[inline]
pub fn safe_read_u64(addr: usize) -> Option<u64> {
    if addr == 0 || addr < 0x10000 {
        return None;
    }

    unsafe { Some(core::ptr::read_unaligned(addr as *const u64)) }
}

#[inline]
pub fn safe_read_u32(addr: usize) -> Option<u32> {
    if addr == 0 || addr < 0x10000 {
        return None;
    }
    unsafe { Some(core::ptr::read_unaligned(addr as *const u32)) }
}

#[inline]
pub fn safe_read_u16(addr: usize) -> Option<u16> {
    if addr == 0 || addr < 0x10000 {
        return None;
    }
    unsafe { Some(core::ptr::read_unaligned(addr as *const u16)) }
}

#[inline]

pub unsafe fn validate_dos_header(base: *const u8) -> Option<u32> {
    if base.is_null() {
        return None;
    }

    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    Some((*dos).e_lfanew as u32)
}

#[inline]

pub unsafe fn validate_pe_header(base: *const u8) -> Option<*const IMAGE_NT_HEADERS64> {
    let e_lfanew = validate_dos_header(base)?;

    let nt = (base as usize + e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    Some(nt)
}

pub unsafe fn is_amd64_pe(module: HMODULE) -> bool {
    if module.is_null() {
        return false;
    }

    let base = module as *const u8;
    let nt = match validate_pe_header(base) {
        Some(h) => h,
        None => return false,
    };

    if (*nt).FileHeader.Machine != 0x8664 {
        return false;
    }

    if (*nt).OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return false;
    }

    true
}

pub unsafe fn find_text_section(base: *const u8) -> Option<(*const u8, usize)> {
    if base.is_null() {
        return None;
    }

    let dos_magic = *(base as *const u16);
    if dos_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let e_lfanew = *(base.add(0x3C) as *const u32);
    let pe_header = base.add(e_lfanew as usize);

    let pe_sig = *(pe_header as *const u32);
    if pe_sig != IMAGE_PE_SIGNATURE {
        return None;
    }

    let optional_header = pe_header.add(0x18);
    let magic = *(optional_header as *const u16);

    let (section_offset, num_sections_offset) = if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC_LOCAL {
        (0x18 + 0xF0, 0x06)
    } else {
        (0x18 + 0xE0, 0x06)
    };

    let num_sections = *(pe_header.add(num_sections_offset) as *const u16);
    let sections = pe_header.add(section_offset);

    for i in 0..num_sections as usize {
        let section = sections.add(i * 0x28);
        let name = core::slice::from_raw_parts(section, 8);

        //(0x2E 0x74 0x65 0x78 0x74)
        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
            let virtual_size = *(section.add(8) as *const u32) as usize;
            let virtual_address = *(section.add(12) as *const u32) as usize;
            let text_start = base.add(virtual_address);
            return Some((text_start, virtual_size));
        }
    }

    None
}

pub unsafe fn find_text_section_with_rva(base: *const u8) -> Option<(*const u8, usize, u32)> {
    if base.is_null() {
        return None;
    }

    let dos_magic = *(base as *const u16);
    if dos_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let e_lfanew = *(base.add(0x3C) as *const u32);
    let pe_header = base.add(e_lfanew as usize);

    let pe_sig = *(pe_header as *const u32);
    if pe_sig != IMAGE_PE_SIGNATURE {
        return None;
    }

    let optional_header = pe_header.add(0x18);
    let magic = *(optional_header as *const u16);

    let (section_offset, num_sections_offset) = if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC_LOCAL {
        (0x18 + 0xF0, 0x06)
    } else {
        (0x18 + 0xE0, 0x06)
    };

    let num_sections = *(pe_header.add(num_sections_offset) as *const u16);
    let sections = pe_header.add(section_offset);

    for i in 0..num_sections as usize {
        let section = sections.add(i * 0x28);
        let name = core::slice::from_raw_parts(section, 8);

        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
            let virtual_size = *(section.add(8) as *const u32) as usize;
            let virtual_address = *(section.add(12) as *const u32);
            let text_start = base.add(virtual_address as usize);
            return Some((text_start, virtual_size, virtual_address));
        }
    }

    None
}

pub unsafe fn get_ntdll_text_bounds() -> Option<(usize, usize)> {
    use crate::hash::{get_module_by_hash, H_NTDLL};

    let ntdll = get_module_by_hash(H_NTDLL)?;
    if ntdll.is_null() {
        return None;
    }

    let base = ntdll as *const u8;

    let (text_start, text_size) = find_text_section(base)?;
    let start = text_start as usize;
    let end = start + text_size;

    Some((start, end))
}

pub unsafe fn get_module_timestamp(module: HMODULE) -> Option<u32> {
    if module.is_null() {
        return None;
    }

    let base = module as *const u8;
    let nt = validate_pe_header(base)?;

    Some((*nt).FileHeader.TimeDateStamp)
}

pub unsafe fn get_module_size(module: HMODULE) -> Option<u32> {
    if module.is_null() {
        return None;
    }

    let base = module as *const u8;
    let nt = validate_pe_header(base)?;

    Some((*nt).OptionalHeader.SizeOfImage)
}

pub unsafe fn address_in_module(addr: usize, module: HMODULE) -> bool {
    if module.is_null() || addr == 0 {
        return false;
    }

    let base = module as usize;
    let size = match get_module_size(module) {
        Some(s) => s as usize,
        None => return false,
    };

    addr >= base && addr < base + size
}

pub unsafe fn address_in_ntdll_text(addr: usize) -> bool {
    match get_ntdll_text_bounds() {
        Some((start, end)) => addr >= start && addr < end,
        None => false,
    }
}
