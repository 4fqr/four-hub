// ─── Four-Hub · reporting/html.rs ────────────────────────────────────────────
//! Export all findings to a self-contained, styled HTML report.

use crate::db::{Finding, Severity};
use anyhow::Result;
use std::{io::Write, path::Path};

pub fn export(findings: &[Finding], project: &str, path: &Path) -> Result<()> {
    let generated = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let version   = env!("CARGO_PKG_VERSION");

    let counts = |sev: Severity| findings.iter().filter(|f| f.severity == sev).count();
    let critical = counts(Severity::Critical);
    let high     = counts(Severity::High);
    let medium   = counts(Severity::Medium);
    let low      = counts(Severity::Low);
    let info     = counts(Severity::Info);

    let rows: String = findings
        .iter()
        .map(|f| {
            let sev_class = match f.severity {
                Severity::Critical => "sev-critical",
                Severity::High     => "sev-high",
                Severity::Medium   => "sev-medium",
                Severity::Low      => "sev-low",
                Severity::Info     => "sev-info",
            };
            let evidence = f.evidence.as_deref().unwrap_or("").replace('<', "&lt;").replace('>', "&gt;");
            let desc     = f.description.replace('<', "&lt;").replace('>', "&gt;").replace('\n', "<br>");
            let title    = f.title.replace('<', "&lt;").replace('>', "&gt;");
            format!(
                r#"<tr>
  <td><span class="badge {sev_class}">{sev}</span></td>
  <td>{tool}</td>
  <td>{title}</td>
  <td class="desc">{desc}</td>
  <td class="evidence"><pre>{evidence}</pre></td>
  <td class="ts">{ts}</td>
</tr>"#,
                sev     = f.severity.as_str().to_uppercase(),
                tool    = &f.tool,
                ts      = f.created_at.format("%Y-%m-%d %H:%M"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Four-Hub Report – {project}</title>
<style>
  :root {{
    --bg: #0a0a12; --panel: #10101e; --accent: #00ff99; --cyan: #00e6ff;
    --pink: #ff40c8; --red: #ff3250; --orange: #ff9100; --yellow: #ffea00;
    --fg: #dce6ff; --dim: #8c96af;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--fg); font-family: 'Courier New', monospace;
          font-size: 14px; padding: 2rem; }}
  h1   {{ color: var(--accent); font-size: 2rem; margin-bottom: .25rem; }}
  .meta {{ color: var(--dim); margin-bottom: 2rem; font-size: .85rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: var(--panel); border: 1px solid #32375014; border-radius: 8px;
           padding: 1rem 1.5rem; min-width: 100px; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: var(--panel); color: var(--accent); text-align: left;
        padding: .5rem .75rem; border-bottom: 2px solid #32375014; }}
  td {{ padding: .5rem .75rem; border-bottom: 1px solid #32375014; vertical-align: top; }}
  tr:hover {{ background: #10101e; }}
  .badge {{ display: inline-block; padding: .2rem .5rem; border-radius: 4px;
            font-weight: bold; font-size: .75rem; letter-spacing: .05rem; }}
  .sev-critical {{ background: #ff325020; color: var(--red); }}
  .sev-high     {{ background: #ff910020; color: var(--orange); }}
  .sev-medium   {{ background: #ffea0020; color: var(--yellow); }}
  .sev-low      {{ background: #00e6ff20; color: var(--cyan); }}
  .sev-info     {{ background: #8c96af20; color: var(--dim); }}
  .desc         {{ max-width: 300px; }}
  .evidence pre {{ white-space: pre-wrap; word-break: break-all; font-size: .75rem;
                   color: var(--dim); max-height: 80px; overflow: hidden; }}
  .ts           {{ color: var(--dim); white-space: nowrap; font-size: .8rem; }}
</style>
</head>
<body>
<h1>◆ FOUR-HUB REPORT</h1>
<p class="meta">Project: <strong>{project}</strong> &nbsp;|&nbsp; Generated: {generated} &nbsp;|&nbsp; Version: {version}</p>
<div class="summary">
  <div class="card"><div class="num" style="color:var(--red)">{critical}</div><div>Critical</div></div>
  <div class="card"><div class="num" style="color:var(--orange)">{high}</div><div>High</div></div>
  <div class="card"><div class="num" style="color:var(--yellow)">{medium}</div><div>Medium</div></div>
  <div class="card"><div class="num" style="color:var(--cyan)">{low}</div><div>Low</div></div>
  <div class="card"><div class="num" style="color:var(--dim)">{info}</div><div>Info</div></div>
  <div class="card"><div class="num" style="color:var(--accent)">{total}</div><div>Total</div></div>
</div>
<table>
<thead><tr><th>SEV</th><th>TOOL</th><th>TITLE</th><th>DESCRIPTION</th><th>EVIDENCE</th><th>TIME</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"#,
        total    = findings.len(),
    );

    let mut file = std::fs::File::create(path)?;
    file.write_all(html.as_bytes())?;
    Ok(())
}
