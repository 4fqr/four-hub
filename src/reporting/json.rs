// ─── Four-Hub · reporting/json.rs ────────────────────────────────────────────
//! Export all findings to a JSON report file.

use crate::db::Finding;
use anyhow::Result;
use serde_json::{json, Value};
use std::{io::Write, path::Path};

pub fn export(findings: &[Finding], project: &str, path: &Path) -> Result<()> {
    let arr: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id":          f.id,
                "tool":        f.tool,
                "title":       f.title,
                "description": f.description,
                "severity":    f.severity.as_str(),
                "evidence":    f.evidence,
                "created_at":  f.created_at.to_rfc3339(),
                "host_id":     f.host_id,
                "port_id":     f.port_id,
            })
        })
        .collect();

    let report = json!({
        "project":    project,
        "generated":  chrono::Utc::now().to_rfc3339(),
        "version":    env!("CARGO_PKG_VERSION"),
        "total":      findings.len(),
        "findings":   arr,
    });

    let mut file = std::fs::File::create(path)?;
    file.write_all(serde_json::to_string_pretty(&report)?.as_bytes())?;
    Ok(())
}
