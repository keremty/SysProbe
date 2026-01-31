#![allow(non_snake_case)]

use core::mem;
use std::sync::OnceLock;

use ntapi::ntpsapi::THREAD_BASIC_INFORMATION;
use serde::Serialize;
use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;
use winapi::um::processthreadsapi::{GetCurrentProcessId, GetProcessId};
use winapi::um::winnt::{CONTEXT, CONTEXT_CONTROL, CONTEXT_INTEGER};

use crate::hash::{fnv1a_hash, fnv1a_hash_runtime, get_export_by_hash, get_module_by_hash, H_NTDLL};
use crate::memory_region_analysis::{MemoryRegion, ModuleInfo, RegionBacking};
use crate::nt::{nt_success, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS};
use crate::syscalls::{nt_get_context_thread, nt_query_information_thread, nt_read_virtual_memory};

const THREAD_BASIC_INFORMATION_CLASS: u32 = 0;
const UNW_FLAG_NHANDLER: u32 = 0;
const MAX_USER_ADDRESS: usize = 0x0000_7FFF_FFFF_FFFF;

const H_RTL_LOOKUP_FUNCTION_ENTRY: u64 = fnv1a_hash(b"RtlLookupFunctionEntry");
const H_RTL_VIRTUAL_UNWIND: u64 = fnv1a_hash(b"RtlVirtualUnwind");

#[repr(C)]
#[derive(Clone, Copy)]
struct RuntimeFunction {
    begin: u32,
    end: u32,
    unwind: u32,
}

type RtlLookupFunctionEntryFn = unsafe extern "system" fn(
    ControlPc: u64,
    ImageBase: *mut u64,
    HistoryTable: *mut c_void,
) -> *const RuntimeFunction;

type RtlVirtualUnwindFn = unsafe extern "system" fn(
    HandlerType: u32,
    ImageBase: u64,
    ControlPc: u64,
    FunctionEntry: *const RuntimeFunction,
    ContextRecord: *mut CONTEXT,
    HandlerData: *mut *mut c_void,
    EstablisherFrame: *mut u64,
    ContextPointers: *mut c_void,
);

static RTL_LOOKUP: OnceLock<Option<RtlLookupFunctionEntryFn>> = OnceLock::new();
static RTL_UNWIND: OnceLock<Option<RtlVirtualUnwindFn>> = OnceLock::new();

#[derive(Debug)]
pub enum AnalysisError {
    InvalidAddress,
    ReadFailed { addr: usize, size: usize, status: i32 },
    ContextUnavailable,
    UnwindUnavailable,
    UnwindFailed(&'static str),
    FrameLimitExceeded,
}

#[derive(Debug, Clone, Copy)]
pub struct ThreadContext {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnwindMethod {
    Api,
    FramePointer,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackFrame {
    pub index: usize,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub module_base: Option<usize>,
    pub module_name: Option<String>,
    pub backing: Option<RegionBacking>,
    pub confidence: i32,
    pub suspicious: bool,
    pub unwind_method: UnwindMethod,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackTrace {
    pub frames: Vec<StackFrame>,
    pub total_confidence: i32,
    pub suspicious_frames: usize,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct UnwindOptions {
    pub max_frames: usize,
    pub max_stack_snapshot: usize,
    pub snapshot_chunk: usize,
    pub enable_fp_fallback: bool,
    pub score_callsite: i32,
    pub score_fp_in_bounds: i32,
    pub score_rsp_in_bounds: i32,
    pub score_private_exec: i32,
    pub score_unknown_module: i32,
}

impl Default for UnwindOptions {
    fn default() -> Self {
        Self {
            max_frames: 64,
            max_stack_snapshot: 512 * 1024,
            snapshot_chunk: 64 * 1024,
            enable_fp_fallback: true,
            score_callsite: 10,
            score_fp_in_bounds: 10,
            score_rsp_in_bounds: 10,
            score_private_exec: -20,
            score_unknown_module: -10,
        }
    }
}

#[derive(Debug, Default)]
pub struct UnwindScratch {
    mirror: Vec<u8>,
    readable: Vec<(usize, usize)>,
}

#[derive(Clone, Copy)]
struct StackMirror<'a> {
    remote_base: usize,
    remote_end: usize,
    data: &'a [u8],
    readable: &'a [(usize, usize)],
}

pub fn unwind_thread(
    process: HANDLE,
    thread: HANDLE,
    modules: Option<&[ModuleInfo]>,
    memory_map: Option<&[MemoryRegion]>,
    options: UnwindOptions,
    scratch: &mut UnwindScratch,
) -> Result<StackTrace, AnalysisError> {
    let context = capture_thread_context(thread)?;
    let (stack_base, stack_limit) = query_stack_bounds(process, thread)?;
    if stack_base <= stack_limit {
        return Err(AnalysisError::InvalidAddress);
    }

    let is_local = is_current_process(process);
    let mirror = if is_local {
        None
    } else {
        build_stack_mirror(process, stack_limit, stack_base, options, scratch).ok()
    };
    let api_allowed = is_local || mirror.is_some();

    let mut frames = Vec::new();
    let mut total_confidence = 0;
    let mut suspicious_frames = 0;
    let mut warnings = Vec::new();

    let mut current = context;
    for index in 0..options.max_frames {
        if current.rip == 0 || current.rsp == 0 {
            break;
        }

        let (frame, method, unwind_result) = analyze_frame(
            process,
            index,
            current,
            stack_base,
            stack_limit,
            modules,
            memory_map,
            mirror.as_ref(),
            options,
            api_allowed,
        )?;

        total_confidence += frame.confidence;
        if frame.suspicious {
            suspicious_frames += 1;
        }

        frames.push(frame);

        let next = match unwind_result {
            Ok(ctx) => ctx,
            Err(reason) => {
                if method == UnwindMethod::None {
                    break;
                }
                warnings.push(reason);
                break;
            }
        };
        current = next;
    }

    if frames.len() >= options.max_frames {
        return Err(AnalysisError::FrameLimitExceeded);
    }

    Ok(StackTrace {
        frames,
        total_confidence,
        suspicious_frames,
        warnings,
    })
}

fn analyze_frame(
    process: HANDLE,
    index: usize,
    context: ThreadContext,
    stack_base: usize,
    stack_limit: usize,
    modules: Option<&[ModuleInfo]>,
    memory_map: Option<&[MemoryRegion]>,
    mirror: Option<&StackMirror>,
    options: UnwindOptions,
    api_allowed: bool,
) -> Result<(StackFrame, UnwindMethod, Result<ThreadContext, &'static str>), AnalysisError> {
    let mut notes = Vec::new();
    let mut confidence = 0;
    let mut suspicious = false;

    if is_addr_in_bounds(context.rsp as usize, stack_limit, stack_base) {
        confidence += options.score_rsp_in_bounds;
    } else {
        notes.push("RSP outside stack");
    }

    if is_addr_in_bounds(context.rbp as usize, stack_limit, stack_base) {
        confidence += options.score_fp_in_bounds;
    }

    let module_info = modules.and_then(|m| find_module_for_address(m, context.rip as usize));
    let module_base = module_info.map(|m| m.base_address);
    let module_name = module_info
        .and_then(|m| m.base_name.clone().or_else(|| m.full_name.clone()));

    let backing = memory_map.and_then(|map| region_backing(map, context.rip as usize));

    if backing == Some(RegionBacking::Private) {
        suspicious = true;
        confidence += options.score_private_exec;
        notes.push("Private exec");
    } else if module_base.is_none() {
        confidence += options.score_unknown_module;
        notes.push("Module not found");
    }

    if is_plausible_return_address(process, context.rip as usize, memory_map, mirror)? {
        confidence += options.score_callsite;
    }

    let (method, next) = unwind_step(
        process,
        context,
        stack_base,
        stack_limit,
        module_info,
        mirror,
        options,
        api_allowed,
    );

    Ok((
        StackFrame {
            index,
            rip: context.rip,
            rsp: context.rsp,
            rbp: context.rbp,
            module_base,
            module_name,
            backing,
            confidence,
            suspicious,
            unwind_method: method,
            notes,
        },
        method,
        next,
    ))
}

fn unwind_step(
    process: HANDLE,
    context: ThreadContext,
    stack_base: usize,
    stack_limit: usize,
    module_info: Option<&ModuleInfo>,
    mirror: Option<&StackMirror>,
    options: UnwindOptions,
    api_allowed: bool,
) -> (UnwindMethod, Result<ThreadContext, &'static str>) {
    if api_allowed {
        if let Some(module) = module_info {
            if let Ok(next) = unwind_with_api(process, context, stack_base, stack_limit, module, mirror) {
                return (UnwindMethod::Api, Ok(next));
            }
        }
    }

    if options.enable_fp_fallback {
        match unwind_fp_chain(process, context, stack_base, stack_limit, mirror) {
            Ok(next) => return (UnwindMethod::FramePointer, Ok(next)),
            Err(reason) => return (UnwindMethod::FramePointer, Err(reason)),
        }
    }

    (UnwindMethod::None, Err("Unwind disabled"))
}

fn unwind_with_api(
    _process: HANDLE,
    context: ThreadContext,
    stack_base: usize,
    stack_limit: usize,
    module: &ModuleInfo,
    mirror: Option<&StackMirror>,
) -> Result<ThreadContext, &'static str> {
    let lookup = resolve_rtl_lookup().ok_or("RtlLookupFunctionEntry not available")?;
    let unwind = resolve_rtl_unwind().ok_or("RtlVirtualUnwind not available")?;

    let local_ok = is_module_mapped_locally(module, context.rip as usize);
    if !local_ok {
        return Err("Local module mismatch");
    }

    let mut image_base: u64 = 0;
    let fn_entry = unsafe { lookup(context.rip, &mut image_base as *mut u64, core::ptr::null_mut()) };
    if fn_entry.is_null() {
        return Err("Function entry not found");
    }

    let mut ctx: CONTEXT = unsafe { mem::zeroed() };
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    ctx.Rip = context.rip;
    ctx.Rsp = context.rsp;
    ctx.Rbp = context.rbp;

    if let Some(m) = mirror {
        let local_rsp = m.remote_to_local(ctx.Rsp as usize).ok_or("RSP outside mirror")? as u64;
        let local_rbp = m.remote_to_local(ctx.Rbp as usize).ok_or("RBP outside mirror")? as u64;
        ctx.Rsp = local_rsp;
        ctx.Rbp = local_rbp;
    }

    let mut handler_data: *mut c_void = core::ptr::null_mut();
    let mut establisher: u64 = 0;
    unsafe {
        unwind(
            UNW_FLAG_NHANDLER,
            image_base,
            context.rip,
            fn_entry,
            &mut ctx as *mut CONTEXT,
            &mut handler_data as *mut *mut c_void,
            &mut establisher as *mut u64,
            core::ptr::null_mut(),
        );
    }

    let (new_rsp, new_rbp) = if let Some(m) = mirror {
        let remote_rsp = m.local_to_remote(ctx.Rsp as usize).ok_or("RSP outside mirror")? as u64;
        let remote_rbp = m.local_to_remote(ctx.Rbp as usize).ok_or("RBP outside mirror")? as u64;
        (remote_rsp, remote_rbp)
    } else {
        (ctx.Rsp, ctx.Rbp)
    };

    if ctx.Rip == 0 {
        return Err("RIP is zero");
    }

    if !is_addr_in_bounds(new_rsp as usize, stack_limit, stack_base) {
        return Err("RSP outside stack");
    }

    if !is_user_address(ctx.Rip as usize) {
        return Err("RIP outside user space");
    }

    Ok(ThreadContext {
        rip: ctx.Rip,
        rsp: new_rsp,
        rbp: new_rbp,
    })
}

fn unwind_fp_chain(
    process: HANDLE,
    context: ThreadContext,
    stack_base: usize,
    stack_limit: usize,
    mirror: Option<&StackMirror>,
) -> Result<ThreadContext, &'static str> {
    let rbp = context.rbp as usize;
    if !is_addr_in_bounds(rbp, stack_limit, stack_base) {
        return Err("RBP outside stack");
    }

    let prev_rbp = read_u64(process, rbp, mirror).ok_or("Failed to read RBP")?;
    let ret_addr = read_u64(process, rbp + 8, mirror).ok_or("Failed to read RIP")?;

    if ret_addr == 0 {
        return Err("RIP is zero");
    }

    Ok(ThreadContext {
        rip: ret_addr,
        rsp: (rbp + 16) as u64,
        rbp: prev_rbp,
    })
}

fn capture_thread_context(thread: HANDLE) -> Result<ThreadContext, AnalysisError> {
    let mut context: CONTEXT = unsafe { mem::zeroed() };
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    let status = unsafe { nt_get_context_thread(thread, &mut context as *mut CONTEXT) };
    if !nt_success(status) {
        return Err(AnalysisError::ContextUnavailable);
    }
    Ok(ThreadContext {
        rip: context.Rip,
        rsp: context.Rsp,
        rbp: context.Rbp,
    })
}

fn query_stack_bounds(process: HANDLE, thread: HANDLE) -> Result<(usize, usize), AnalysisError> {
    let info = query_thread_basic_information(thread)?;
    let teb_addr = info.TebBaseAddress as usize;
    if !is_user_address(teb_addr) {
        return Err(AnalysisError::InvalidAddress);
    }
    let tib: NtTib = read_struct(process, teb_addr)?;
    Ok((tib.stack_base as usize, tib.stack_limit as usize))
}

fn query_thread_basic_information(thread: HANDLE) -> Result<THREAD_BASIC_INFORMATION, AnalysisError> {
    let mut info: THREAD_BASIC_INFORMATION = unsafe { mem::zeroed() };
    let mut return_len: u32 = 0;
    let status = unsafe {
        nt_query_information_thread(
            thread,
            THREAD_BASIC_INFORMATION_CLASS,
            &mut info as *mut _ as *mut c_void,
            mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
            &mut return_len as *mut u32,
        )
    };

    if !nt_success(status) {
        return Err(AnalysisError::ContextUnavailable);
    }

    Ok(info)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NtTib {
    _exception_list: *mut c_void,
    stack_base: *mut c_void,
    stack_limit: *mut c_void,
}

fn build_stack_mirror(
    process: HANDLE,
    stack_limit: usize,
    stack_base: usize,
    options: UnwindOptions,
    scratch: &mut UnwindScratch,
) -> Result<StackMirror<'_>, AnalysisError> {
    let stack_size = stack_base.saturating_sub(stack_limit);
    if stack_size < 16 {
        return Err(AnalysisError::InvalidAddress);
    }

    let snapshot_size = stack_size.min(options.max_stack_snapshot);
    let remote_base = stack_base.saturating_sub(snapshot_size);
    let remote_end = remote_base.saturating_add(snapshot_size);

    scratch.mirror.resize(snapshot_size, 0u8);
    scratch.readable.clear();

    let mut offset = 0usize;
    while offset < snapshot_size {
        let chunk = options.snapshot_chunk.min(snapshot_size - offset).max(0x1000);
        let addr = remote_base.saturating_add(offset);
        let slice = &mut scratch.mirror[offset..offset + chunk];
        if let Ok(read_len) = read_bytes(process, addr, slice) {
            if read_len > 0 {
                scratch.readable.push((addr, addr + read_len));
            }
        }
        offset = offset.saturating_add(chunk);
    }

    if scratch.readable.is_empty() {
        return Err(AnalysisError::ReadFailed {
            addr: remote_base,
            size: snapshot_size,
            status: -1,
        });
    }

    Ok(StackMirror {
        remote_base,
        remote_end,
        data: &scratch.mirror,
        readable: &scratch.readable,
    })
}

impl<'a> StackMirror<'a> {
    fn remote_to_local(&self, remote: usize) -> Option<usize> {
        if remote < self.remote_base || remote >= self.remote_end {
            return None;
        }
        let offset = remote.saturating_sub(self.remote_base);
        Some(self.data.as_ptr() as usize + offset)
    }

    fn local_to_remote(&self, local: usize) -> Option<usize> {
        let base = self.data.as_ptr() as usize;
        if local < base || local >= base + self.data.len() {
            return None;
        }
        Some(self.remote_base + (local - base))
    }

    fn contains(&self, remote: usize, size: usize) -> bool {
        if remote < self.remote_base || remote + size > self.remote_end {
            return false;
        }
        for (start, end) in self.readable {
            if remote >= *start && remote + size <= *end {
                return true;
            }
        }
        false
    }

    fn read_u64(&self, remote: usize) -> Option<u64> {
        if !self.contains(remote, 8) {
            return None;
        }
        let offset = remote.saturating_sub(self.remote_base);
        if offset + 8 > self.data.len() {
            return None;
        }
        let bytes = &self.data[offset..offset + 8];
        Some(u64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&self, remote: usize, size: usize) -> Option<&[u8]> {
        if !self.contains(remote, size) {
            return None;
        }
        let offset = remote.saturating_sub(self.remote_base);
        if offset + size > self.data.len() {
            return None;
        }
        Some(&self.data[offset..offset + size])
    }
}

fn is_plausible_return_address(
    process: HANDLE,
    addr: usize,
    memory_map: Option<&[MemoryRegion]>,
    mirror: Option<&StackMirror>,
) -> Result<bool, AnalysisError> {
    if addr < 6 {
        return Ok(false);
    }

    if let Some(map) = memory_map {
        let read_addr = addr.saturating_sub(6);
        let region = match find_region_for_address(map, read_addr) {
            Some(r) => r,
            None => return Ok(false),
        };
        if region.state != MEM_COMMIT || !is_readable(region.protect) {
            return Ok(false);
        }
    }

    let mut bytes = [0u8; 6];
    if let Some(m) = mirror {
        if let Some(buf) = m.read_bytes(addr.saturating_sub(6), 6) {
            bytes.copy_from_slice(buf);
        } else if read_bytes_exact(process, addr.saturating_sub(6), &mut bytes).is_err() {
            return Ok(false);
        }
    } else if read_bytes_exact(process, addr.saturating_sub(6), &mut bytes).is_err() {
        return Ok(false);
    }

    if bytes[1] == 0xE8 {
        return Ok(true);
    }
    if bytes[0] == 0xFF && bytes[1] == 0x15 {
        return Ok(true);
    }
    if bytes[4] == 0xFF && (bytes[5] & 0xF8) == 0xD0 {
        return Ok(true);
    }

    Ok(false)
}

fn read_bytes_exact(process: HANDLE, addr: usize, buf: &mut [u8]) -> Result<(), AnalysisError> {
    let read_len = read_bytes(process, addr, buf)?;
    if read_len < buf.len() {
        return Err(AnalysisError::ReadFailed {
            addr,
            size: buf.len(),
            status: -1,
        });
    }
    Ok(())
}

fn read_bytes(process: HANDLE, addr: usize, buf: &mut [u8]) -> Result<usize, AnalysisError> {
    let mut read_len: usize = 0;
    let status = unsafe {
        nt_read_virtual_memory(
            process,
            addr as *mut c_void,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut read_len as *mut usize,
        )
    };

    if !nt_success(status) {
        return Err(AnalysisError::ReadFailed {
            addr,
            size: buf.len(),
            status,
        });
    }

    Ok(read_len)
}

fn read_struct<T: Copy>(process: HANDLE, addr: usize) -> Result<T, AnalysisError> {
    let mut out = mem::MaybeUninit::<T>::uninit();
    let mut read_len: usize = 0;
    let status = unsafe {
        nt_read_virtual_memory(
            process,
            addr as *mut c_void,
            out.as_mut_ptr() as *mut c_void,
            mem::size_of::<T>(),
            &mut read_len as *mut usize,
        )
    };

    if !nt_success(status) || read_len != mem::size_of::<T>() {
        return Err(AnalysisError::ReadFailed {
            addr,
            size: mem::size_of::<T>(),
            status,
        });
    }

    Ok(unsafe { out.assume_init() })
}

fn read_u64(process: HANDLE, addr: usize, mirror: Option<&StackMirror>) -> Option<u64> {
    if let Some(m) = mirror {
        if let Some(v) = m.read_u64(addr) {
            return Some(v);
        }
    }

    let mut buf = [0u8; 8];
    if read_bytes(process, addr, &mut buf).is_ok() {
        Some(u64::from_ne_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]))
    } else {
        None
    }
}

fn resolve_rtl_lookup() -> Option<RtlLookupFunctionEntryFn> {
    *RTL_LOOKUP.get_or_init(|| unsafe {
        let ntdll = get_module_by_hash(H_NTDLL)?;
        let proc = get_export_by_hash(ntdll, H_RTL_LOOKUP_FUNCTION_ENTRY)?;
        Some(mem::transmute(proc))
    })
}

fn resolve_rtl_unwind() -> Option<RtlVirtualUnwindFn> {
    *RTL_UNWIND.get_or_init(|| unsafe {
        let ntdll = get_module_by_hash(H_NTDLL)?;
        let proc = get_export_by_hash(ntdll, H_RTL_VIRTUAL_UNWIND)?;
        Some(mem::transmute(proc))
    })
}

fn is_module_mapped_locally(module: &ModuleInfo, addr: usize) -> bool {
    let local_base = match resolve_local_module_base(module) {
        Some(b) => b,
        None => return false,
    };
    if local_base != module.base_address {
        return false;
    }
    addr >= local_base && addr < local_base.saturating_add(module.size)
}

fn resolve_local_module_base(module: &ModuleInfo) -> Option<usize> {
    let name = module
        .base_name
        .as_ref()
        .or(module.full_name.as_ref())?
        .to_ascii_lowercase();

    let base = extract_basename(&name);
    let hash = fnv1a_hash_runtime(base.as_bytes());
    unsafe { get_module_by_hash(hash).map(|h| h as usize) }
}

fn extract_basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn is_user_address(addr: usize) -> bool {
    addr >= 0x10000 && addr <= MAX_USER_ADDRESS
}

fn is_addr_in_bounds(addr: usize, low: usize, high: usize) -> bool {
    addr >= low && addr <= high
}

fn find_module_for_address<'a>(modules: &'a [ModuleInfo], addr: usize) -> Option<&'a ModuleInfo> {
    for module in modules {
        let start = module.base_address;
        let end = start.saturating_add(module.size);
        if addr >= start && addr < end {
            return Some(module);
        }
    }
    None
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

fn region_backing(map: &[MemoryRegion], addr: usize) -> Option<RegionBacking> {
    let region = find_region_for_address(map, addr)?;
    Some(backing_from_type(region.region_type))
}

fn backing_from_type(ty: u32) -> RegionBacking {
    const MEM_PRIVATE: u32 = 0x00020000;
    const MEM_MAPPED: u32 = 0x00040000;
    const MEM_IMAGE: u32 = 0x01000000;
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

fn is_readable(protect: u32) -> bool {
    if (protect & PAGE_NOACCESS) != 0 {
        return false;
    }
    if (protect & PAGE_GUARD) != 0 {
        return false;
    }
    true
}

fn is_current_process(handle: HANDLE) -> bool {
    unsafe {
        let pid = GetProcessId(handle);
        if pid == 0 {
            return false;
        }
        pid == GetCurrentProcessId()
    }
}
