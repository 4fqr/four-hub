// ─── Four-Hub · tools/parser.rs ──────────────────────────────────────────────
//! Real-time output parsing.  Individual parsers extract findings from raw
//! stdout lines with minimal regex overhead.

use crate::{
    db::{Finding, Severity},
    tools::spec::ToolSpec,
};
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;
use once_cell::sync::Lazy;

// ── Compiled regexes (compiled once at startup) ───────────────────────────────

static RE_NMAP_PORT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$").unwrap()
});

static RE_NIKTO_VULN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\+ (OSVDB-\d+|CVE-[\d-]+)?:?\s*(.*)"#).unwrap()
});

static RE_HYDRA_CRED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)").unwrap()
});

static RE_SQLMAP_PARAM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Parameter '(\w+)' is vulnerable").unwrap()
});

static RE_GOBUSTER_DIR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^/(\S+)\s+\(Status:\s*(\d+)\)").unwrap()
});

static RE_FFUF_HIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""url":"([^"]+)","status":(\d+)"#).unwrap()
});

static RE_ENUM4LINUX_SHARE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"//(\S+)/(\S+)\s+Mapping:.*Access:").unwrap()
});

// ── Entry-point ───────────────────────────────────────────────────────────────

/// Parse a single stdout line from the given tool and return zero or more
/// normalised `Finding` objects.
pub fn parse_line(spec: &ToolSpec, line: &str, target: &str) -> Vec<Finding> {
    match spec.name.as_str() {
        "nmap"        => parse_nmap(line, target),
        "nikto"       => parse_nikto(line, target),
        "hydra"       => parse_hydra(line, target),
        "sqlmap"      => parse_sqlmap(line, target),
        "gobuster"    => parse_gobuster(line, target),
        "ffuf"        => parse_ffuf(line, target),
        "enum4linux"  => parse_enum4linux(line, target),
        _             => vec![],
    }
}

// ── Nmap ──────────────────────────────────────────────────────────────────────

fn parse_nmap(line: &str, target: &str) -> Vec<Finding> {
    if let Some(caps) = RE_NMAP_PORT.captures(line.trim()) {
        let port    = caps.get(1).map_or("", |m| m.as_str());
        let proto   = caps.get(2).map_or("", |m| m.as_str());
        let state   = caps.get(3).map_or("", |m| m.as_str());
        let service = caps.get(4).map_or("", |m| m.as_str());
        let version = caps.get(5).map_or("", |m| m.as_str());

        if state == "open" {
            return vec![Finding {
                id:          Uuid::new_v4().to_string(),
                host_id:     None,
                port_id:     None,
                tool:        "nmap".into(),
                title:       format!("Open port {port}/{proto} on {target} ({service})"),
                description: format!(
                    "Port {port}/{proto} is open on {}.\nService: {service}\nVersion: {version}",
                    target
                ),
                severity:    Severity::Info,
                evidence:    Some(line.to_string()),
                created_at:  Utc::now(),
            }];
        }
    }
    vec![]
}

// ── Nikto ─────────────────────────────────────────────────────────────────────

fn parse_nikto(line: &str, target: &str) -> Vec<Finding> {
    if let Some(caps) = RE_NIKTO_VULN.captures(line) {
        let id_str = caps.get(1).map_or("", |m| m.as_str());
        let msg    = caps.get(2).map_or("", |m| m.as_str()).trim();
        if !msg.is_empty() {
            let sev = if id_str.starts_with("CVE") || msg.to_lowercase().contains("inject") {
                Severity::High
            } else {
                Severity::Medium
            };
            return vec![Finding {
                id:          Uuid::new_v4().to_string(),
                host_id:     None,
                port_id:     None,
                tool:        "nikto".into(),
                title:       format!("Nikto: {}", msg.chars().take(60).collect::<String>()),
                description: format!("Target: {target}\n{id_str}\n{msg}"),
                severity:    sev,
                evidence:    Some(line.to_string()),
                created_at:  Utc::now(),
            }];
        }
    }
    vec![]
}

// ── Hydra ─────────────────────────────────────────────────────────────────────

fn parse_hydra(line: &str, _target: &str) -> Vec<Finding> {
    if let Some(caps) = RE_HYDRA_CRED.captures(line) {
        let host  = caps.get(3).map_or("", |m| m.as_str());
        let login = caps.get(4).map_or("", |m| m.as_str());
        let pass  = caps.get(5).map_or("", |m| m.as_str());
        return vec![Finding {
            id:          Uuid::new_v4().to_string(),
            host_id:     None,
            port_id:     None,
            tool:        "hydra".into(),
            title:       format!("Credential found on {host}: {login}"),
            description: format!("Valid credential discovered by Hydra:\nHost: {host}\nLogin: {login}\nPassword: {pass}"),
            severity:    Severity::Critical,
            evidence:    Some(line.to_string()),
            created_at:  Utc::now(),
        }];
    }
    vec![]
}

// ── SQLmap ────────────────────────────────────────────────────────────────────

fn parse_sqlmap(line: &str, target: &str) -> Vec<Finding> {
    if let Some(caps) = RE_SQLMAP_PARAM.captures(line) {
        let param = caps.get(1).map_or("", |m| m.as_str());
        return vec![Finding {
            id:          Uuid::new_v4().to_string(),
            host_id:     None,
            port_id:     None,
            tool:        "sqlmap".into(),
            title:       format!("SQL Injection in parameter '{param}'"),
            description: format!("SQLmap found injectable parameter '{param}' at {target}."),
            severity:    Severity::Critical,
            evidence:    Some(line.to_string()),
            created_at:  Utc::now(),
        }];
    }
    vec![]
}

// ── Gobuster ──────────────────────────────────────────────────────────────────

fn parse_gobuster(line: &str, target: &str) -> Vec<Finding> {
    if let Some(caps) = RE_GOBUSTER_DIR.captures(line.trim()) {
        let path   = caps.get(1).map_or("", |m| m.as_str());
        let status = caps.get(2).map_or("", |m| m.as_str());
        return vec![Finding {
            id:          Uuid::new_v4().to_string(),
            host_id:     None,
            port_id:     None,
            tool:        "gobuster".into(),
            title:       format!("Directory found: /{path} ({status})"),
            description: format!("Gobuster discovered /{path} on {target} (HTTP {status})"),
            severity:    Severity::Info,
            evidence:    Some(line.to_string()),
            created_at:  Utc::now(),
        }];
    }
    vec![]
}

// ── FFUF ──────────────────────────────────────────────────────────────────────

fn parse_ffuf(line: &str, _target: &str) -> Vec<Finding> {
    if let Some(caps) = RE_FFUF_HIT.captures(line) {
        let url    = caps.get(1).map_or("", |m| m.as_str());
        let status = caps.get(2).map_or("", |m| m.as_str());
        return vec![Finding {
            id:          Uuid::new_v4().to_string(),
            host_id:     None,
            port_id:     None,
            tool:        "ffuf".into(),
            title:       format!("FFUF hit: {url} ({status})"),
            description: format!("URL {url} returned HTTP {status}"),
            severity:    Severity::Info,
            evidence:    Some(line.to_string()),
            created_at:  Utc::now(),
        }];
    }
    vec![]
}

// ── Enum4linux ────────────────────────────────────────────────────────────────

fn parse_enum4linux(line: &str, target: &str) -> Vec<Finding> {
    if let Some(caps) = RE_ENUM4LINUX_SHARE.captures(line) {
        let host  = caps.get(1).map_or("", |m| m.as_str());
        let share = caps.get(2).map_or("", |m| m.as_str());
        return vec![Finding {
            id:          Uuid::new_v4().to_string(),
            host_id:     None,
            port_id:     None,
            tool:        "enum4linux".into(),
            title:       format!("SMB share accessible: \\\\{host}\\{share}"),
            description: format!("Enum4linux found accessible SMB share on {target}: {share}"),
            severity:    Severity::Medium,
            evidence:    Some(line.to_string()),
            created_at:  Utc::now(),
        }];
    }
    vec![]
}
