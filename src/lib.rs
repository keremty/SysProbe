//! SysProbe - Windows Internals Analysis Library
//!
//! Defensive utilities for inspecting Windows internals, syscall mechanics,
//! and module integrity for Blue Team analysis.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

mod config;
pub mod hash;
mod nt;
pub mod pe;
mod resolver;
pub mod ssn_resolver;
pub mod call_chain_analysis;
pub mod syscalls;
pub mod memory_region_analysis;
pub mod stack_unwind;
pub mod integrity_verifier;
pub mod engine;
pub mod export_gap_analysis;
pub mod iat_analysis;
pub mod entropy;
pub mod signature;

#[macro_export]
macro_rules! trace_log {
    ($($arg:tt)*) => {{
        if $crate::config::should_log() {
            println!($($arg)*);
        }
    }};
}

pub use hash::{fnv1a_hash, get_export_by_hash, get_module_by_hash};
pub use nt::nt_success;
pub use syscalls::UNICODE_STRING;

pub fn run_analysis_demo() {
    println!("=== SysProbe Windows Internals Analysis ===\n");

    println!("[*] Initializing SSN resolver...");
    let ssn_init = syscalls::init_call_chain_analysis();
    println!("    Call-chain analysis init: {}", if ssn_init { "OK" } else { "Unavailable" });

    println!("\n[*] Candidate site statistics:");
    println!(
        "    Syscall entry candidates: {}",
        call_chain_analysis::syscall_candidate_count()
    );
    println!("    Return-site candidates: {}", call_chain_analysis::return_site_count());

    println!("\n[*] Analyzing export gap regions (min 64 bytes)...");
    let report = export_gap_analysis::generate_analysis_report(64);
    println!("{}", report);

    println!("[*] Analysis complete.");
}
