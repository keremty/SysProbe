#![allow(non_snake_case)]

use std::collections::HashMap;

use serde::Serialize;

use crate::integrity_verifier::IntegrityReport;
use crate::memory_region_analysis::{
    ModuleInfo, RegionBacking, RegionFinding, RegionVerdict, ThreadStartFinding, ThreadStartVerdict,
};
use crate::signature::SignatureStatus;
use crate::stack_unwind::StackTrace;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackTraceReport {
    pub pid: u32,
    pub tid: u32,
    pub trace: StackTrace,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelatedFinding {
    pub severity: Severity,
    pub title: &'static str,
    pub details: String,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub module: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EngineInput<'a> {
    pub thread_findings: &'a [ThreadStartFinding],
    pub stacks: &'a [StackTraceReport],
    pub integrity: &'a [IntegrityReport],
    pub modules: &'a [ModuleInfo],
    pub region_findings: &'a [RegionFinding],
}

pub fn correlate(input: EngineInput<'_>) -> Vec<CorrelatedFinding> {
    let mut findings = Vec::new();

    let mut stack_map: HashMap<(u32, u32), &StackTrace> = HashMap::new();
    for s in input.stacks {
        stack_map.insert((s.pid, s.tid), &s.trace);
    }

    for t in input.thread_findings {
        let stack = stack_map.get(&(t.pid, t.tid)).copied();
        let mut score = 0i32;
        let mut reasons = Vec::new();

        match t.verdict {
            ThreadStartVerdict::PrivateExecutable => {
                score += 60;
                reasons.push("Thread start private exec");
            }
            ThreadStartVerdict::MappedNoFile => {
                score += 40;
                reasons.push("Mapped no file");
            }
            ThreadStartVerdict::ImageNotInModuleList => {
                score += 40;
                reasons.push("Image not in module list");
            }
            _ => {}
        }

        if t.backing == RegionBacking::Private {
            score += 30;
            reasons.push("Private backing");
        }

        if t.start_mismatch {
            score += 20;
            reasons.push("Start addr mismatch");
        }

        if let Some(trace) = stack {
            if trace.suspicious_frames > 0 {
                score += 40;
                reasons.push("Suspicious stack");
            }
            if trace.total_confidence < 0 {
                score += 10;
                reasons.push("Low stack confidence");
            }
        }

        let severity = score_to_severity(score);
        if severity != Severity::Low {
            findings.push(CorrelatedFinding {
                severity,
                title: "Thread/Stack correlation",
                details: reasons.join(", "),
                pid: Some(t.pid),
                tid: Some(t.tid),
                module: None,
            });
        }
    }

    for report in input.integrity {
        let mut score = 0i32;
        let mut reasons = Vec::new();

        let has_inline = report.inline_diffs.iter().any(|d| !d.allowed);
        let inline_only = has_inline
            && report.chunk_diffs.is_empty()
            && report.full_hash_match == Some(true);
        if has_inline {
            if inline_only {
                score += 20;
                reasons.push("Inline diff (full hash match)");
            } else {
                score += 50;
                reasons.push("Inline diff");
            }
        }
        if !report.chunk_diffs.is_empty() {
            score += 30;
            reasons.push("Chunk diff");
        }
        if report.full_hash_match == Some(false) {
            score += 40;
            reasons.push("Full hash mismatch");
        }

        let severity = score_to_severity(score);
        if severity != Severity::Low {
            findings.push(CorrelatedFinding {
                severity,
                title: "Integrity violation",
                details: reasons.join(", "),
                pid: Some(report.pid),
                tid: None,
                module: Some(report.module_path.clone()),
            });
        }
    }

    for module in input.modules {
        if module.memory_map_checked && !module.memory_map_present {
            let name = module
                .full_name
                .as_deref()
                .or(module.base_name.as_deref())
                .unwrap_or("<unknown>");
            findings.push(CorrelatedFinding {
                severity: Severity::High,
                title: "PEB/VAD mismatch",
                details: "Module listed in PEB but not backed by MEM_IMAGE".to_string(),
                pid: None,
                tid: None,
                module: Some(name.to_string()),
            });
        }

        let sig = match module.signature.as_ref() {
            Some(s) => s,
            None => continue,
        };
        let name = module
            .full_name
            .as_deref()
            .or(module.base_name.as_deref())
            .unwrap_or("<unknown>");
        let system_path = module
            .full_name
            .as_deref()
            .map(is_system_path)
            .unwrap_or(false);
        match sig.status {
            SignatureStatus::Valid => {}
            SignatureStatus::Unsigned => {
                let severity = if system_path {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(CorrelatedFinding {
                    severity,
                    title: "Unsigned module",
                    details: format_signature_details(sig, "Unsigned module on disk"),
                    pid: None,
                    tid: None,
                    module: Some(name.to_string()),
                });
            }
            SignatureStatus::Invalid => {
                let severity = if system_path {
                    Severity::Critical
                } else {
                    Severity::High
                };
                findings.push(CorrelatedFinding {
                    severity,
                    title: "Invalid module signature",
                    details: format_signature_details(sig, "Signature validation failed"),
                    pid: None,
                    tid: None,
                    module: Some(name.to_string()),
                });
            }
            SignatureStatus::Error => {
                findings.push(CorrelatedFinding {
                    severity: Severity::Low,
                    title: "Signature check error",
                    details: format_signature_details(sig, "Signature status unavailable"),
                    pid: None,
                    tid: None,
                    module: Some(name.to_string()),
                });
            }
        }
    }

    for region in input.region_findings {
        if region.verdict != RegionVerdict::ImageNotInModuleList {
            continue;
        }
        let mut details = String::from("MEM_IMAGE mapping not present in PEB module list");
        if let Some(path) = region.mapped_path.as_ref() {
            details.push_str(": ");
            details.push_str(path);
        }
        findings.push(CorrelatedFinding {
            severity: Severity::High,
            title: "VAD-only image mapping",
            details,
            pid: None,
            tid: None,
            module: region.mapped_path.clone(),
        });
    }

    for report in input.integrity {
        if report.inline_diffs.is_empty() && report.chunk_diffs.is_empty() && report.full_hash_match != Some(false) {
            continue;
        }

        for stack in input.stacks {
            if report.pid != stack.pid {
                continue;
            }
            if stack.trace.suspicious_frames == 0 {
                continue;
            }

            findings.push(CorrelatedFinding {
                severity: Severity::Critical,
                title: "Stack + Integrity correlation",
                details: "Suspicious stack and module integrity mismatch".to_string(),
                pid: Some(stack.pid),
                tid: Some(stack.tid),
                module: Some(report.module_path.clone()),
            });
        }
    }

    findings
}

fn score_to_severity(score: i32) -> Severity {
    if score >= 100 {
        Severity::Critical
    } else if score >= 70 {
        Severity::High
    } else if score >= 40 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn is_system_path(path: &str) -> bool {
    let p = path.trim_start();
    p.len() >= 10 && p[..10].eq_ignore_ascii_case("c:\\windows\\")
}

fn format_signature_details(sig: &crate::signature::SignatureInfo, reason: &str) -> String {
    let mut out = reason.to_string();
    if let Some(ref signer) = sig.signer {
        out.push_str("; signer=");
        out.push_str(signer);
    }
    if let Some(is_ms) = sig.is_microsoft {
        out.push_str("; microsoft=");
        out.push_str(if is_ms { "true" } else { "false" });
    }
    if let Some(err) = sig.error {
        out.push_str("; error=0x");
        out.push_str(&format!("{:08X}", err));
    }
    out
}
