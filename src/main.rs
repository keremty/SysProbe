#![allow(non_snake_case)]

use std::fs::File;
use std::io::{self, BufWriter};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use serde::Serialize;
use winapi::shared::ntdef::HANDLE;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use std::collections::HashSet;
use std::time::Instant;

use SysProbe::engine::{self, CorrelatedFinding, StackTraceReport};
use SysProbe::integrity_verifier::{self, IntegrityOptions, IntegrityReport, IntegrityScratch};
use SysProbe::memory_region_analysis::{self, ProcessScanReport, ScanOptions};
use SysProbe::stack_unwind::{self, UnwindOptions, UnwindScratch};
use SysProbe::syscalls::{
    nt_close, nt_open_process, nt_open_thread, nt_success, set_direct_ntdll, CLIENT_ID,
    OBJECT_ATTRIBUTES,
};
use winapi::um::winnt::{
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
};

#[derive(Parser, Debug)]
#[command(name = "sysprobe", version, about = "SysProbe Memory Forensics CLI")]
struct Args {
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    json: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "fast")]
    scan_mode: ScanMode,
    #[arg(long)]
    no_integrity: bool,
    #[arg(long)]
    no_stack: bool,
    #[arg(long)]
    api_mode: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum ScanMode {
    #[value(alias = "basic")]
    Fast,
    Deep,
}

#[derive(Serialize)]
struct JsonReport {
    summary: Summary,
    pid: u32,
    scan: ProcessScanReport,
    integrity: Vec<IntegrityReport>,
    stacks: Vec<StackTraceReport>,
    correlated: Vec<CorrelatedFinding>,
}

#[derive(Serialize)]
struct Summary {
    scan_duration_ms: u64,
    total_modules_scanned: usize,
    suspicious_threads: usize,
    integrity_violations: usize,
    entropy_alerts: usize,
    risk_score: i32,
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This CLI runs on Windows only.");
}

#[cfg(windows)]
fn main() {
    let args = Args::parse();
    let pid = args.pid.unwrap_or_else(|| unsafe { GetCurrentProcessId() });
    if args.api_mode {
        set_direct_ntdll(true);
    }
    let start_time = Instant::now();

    let mut scan_options = ScanOptions::default();
    match args.scan_mode {
        ScanMode::Fast => {
            scan_options.scan_thread_stacks = false;
            scan_options.collect_mapped_paths = false;
        }
        ScanMode::Deep => {
            scan_options.scan_thread_stacks = true;
            scan_options.collect_mapped_paths = true;
            scan_options.stack_scan_bytes = 0;
        }
    }

    let scan = match memory_region_analysis::scan_process(pid, scan_options) {
        Some(report) => report,
        None => {
            eprintln!("Scan failed for PID {}.", pid);
            std::process::exit(1);
        }
    };
    let memory_map = memory_region_analysis::build_memory_map_for_pid(pid);

    let process = open_process(pid);
    let run_integrity = matches!(args.scan_mode, ScanMode::Deep) && !args.no_integrity;
    let run_stack = matches!(args.scan_mode, ScanMode::Deep) && !args.no_stack;
    let mut integrity_reports = Vec::new();
    let mut stack_reports = Vec::new();

    if let Some(process_handle) = process {
        if run_integrity {
            let mut integrity_opts = IntegrityOptions::default();
            integrity_opts.full_hash = true;
            let mut scratch = IntegrityScratch::default();
            for module in &scan.modules {
            if let Ok(report) = integrity_verifier::verify_module_with_cache(
                process_handle,
                module,
                integrity_opts,
                &mut scratch,
                memory_map.as_deref(),
            ) {
                integrity_reports.push(report);
            }
        }
        }

        if run_stack {
            let mut unwind_opts = UnwindOptions::default();
            unwind_opts.max_frames = 96;
            unwind_opts.max_stack_snapshot = 1024 * 1024;
            let mut unwind_scratch = UnwindScratch::default();
            let mut thread_ids = Vec::new();
            if matches!(args.scan_mode, ScanMode::Deep) {
                thread_ids = memory_region_analysis::list_process_threads(pid);
            }
            if thread_ids.is_empty() {
                thread_ids.extend(scan.thread_findings.iter().map(|t| t.tid));
            }
            let mut seen = HashSet::new();
            for tid in thread_ids.into_iter().filter(|t| seen.insert(*t)) {
                if let Some(thread) = open_thread(tid) {
                    match stack_unwind::unwind_thread(
                        process_handle,
                        thread,
                        if scan.modules_complete { Some(&scan.modules) } else { None },
                        None,
                        unwind_opts,
                        &mut unwind_scratch,
                    ) {
                        Ok(trace) => {
                            stack_reports.push(StackTraceReport {
                                pid,
                                tid,
                                trace,
                            });
                        }
                        Err(_) => {}
                    }

                    unsafe {
                        nt_close(thread);
                    }
                }
            }
        }

        unsafe {
            nt_close(process_handle);
        }
    }

    let correlated = engine::correlate(engine::EngineInput {
        thread_findings: &scan.thread_findings,
        stacks: &stack_reports,
        integrity: &integrity_reports,
        modules: &scan.modules,
        region_findings: &scan.region_findings,
    });

    let integrity_violations = integrity_reports
        .iter()
        .filter(|r| {
            r.inline_diffs.iter().any(|d| !d.allowed)
                || !r.chunk_diffs.is_empty()
                || r.full_hash_match == Some(false)
        })
        .count();
    let risk_score = correlated
        .iter()
        .map(|f| match f.severity {
            engine::Severity::Low => 10,
            engine::Severity::Medium => 40,
            engine::Severity::High => 70,
            engine::Severity::Critical => 100,
        })
        .max()
        .unwrap_or(0);

    let summary = Summary {
        scan_duration_ms: start_time.elapsed().as_millis() as u64,
        total_modules_scanned: scan.modules.len(),
        suspicious_threads: scan.thread_findings.len(),
        integrity_violations,
        entropy_alerts: scan.region_findings.iter().filter(|r| r.entropy_high).count(),
        risk_score,
    };

    let report = JsonReport {
        summary,
        pid,
        scan,
        integrity: integrity_reports,
        stacks: stack_reports,
        correlated,
    };

    if let Some(path) = args.json {
        if let Err(err) = write_json_file(&path, &report) {
            eprintln!("Failed to write JSON: {}", err);
            std::process::exit(1);
        }
        println!("JSON report written: {}", path.display());
    } else {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{}", json),
            Err(err) => {
                eprintln!("Failed to render JSON: {}", err);
                std::process::exit(1);
            }
        }
    }
}

#[cfg(windows)]
fn open_process(pid: u32) -> Option<HANDLE> {
    let mut handle: HANDLE = core::ptr::null_mut();
    let mut obj = OBJECT_ATTRIBUTES::null();
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as usize as HANDLE,
        UniqueThread: core::ptr::null_mut(),
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

#[cfg(windows)]
fn open_thread(tid: u32) -> Option<HANDLE> {
    let mut handle: HANDLE = core::ptr::null_mut();
    let mut obj = OBJECT_ATTRIBUTES::null();
    let mut client_id = CLIENT_ID {
        UniqueProcess: core::ptr::null_mut(),
        UniqueThread: tid as usize as HANDLE,
    };

    let status = unsafe {
        nt_open_thread(
            &mut handle as *mut HANDLE,
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            &mut obj as *mut OBJECT_ATTRIBUTES,
            &mut client_id as *mut CLIENT_ID,
        )
    };

    if !nt_success(status) || handle.is_null() {
        return None;
    }

    Some(handle)
}

#[cfg(windows)]
fn write_json_file(path: &PathBuf, report: &JsonReport) -> io::Result<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, report)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
