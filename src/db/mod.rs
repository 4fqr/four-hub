
pub mod schema;

use crate::crypto::vault::VaultKey;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id:           String,
    pub address:      String,
    pub hostname:     Option<String>,
    pub os:           Option<String>,
    pub notes:        Option<String>,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub id:       String,
    pub host_id:  String,
    pub port:     u16,
    pub protocol: String,
    pub service:  Option<String>,
    pub version:  Option<String>,
    pub state:    String,
    pub banner:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id:          String,
    pub host_id:     Option<String>,
    pub port_id:     Option<String>,
    pub tool:        String,
    pub title:       String,
    pub description: String,
    pub severity:    Severity,
    pub host:        String,
    pub evidence:    Option<String>,
    pub metadata:    Option<String>,
    pub created_at:  DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity { Critical, High, Medium, Low, Info }

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High     => "high",
            Self::Medium   => "medium",
            Self::Low      => "low",
            Self::Info     => "info",
        }
    }
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high"     => Self::High,
            "medium"   => Self::Medium,
            "low"      => Self::Low,
            _          => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id:         String,
    pub tool:       String,
    pub args:       String,
    pub target:     Option<String>,
    pub status:     String,
    pub exit_code:  Option<i32>,
    pub started_at: DateTime<Utc>,
    pub ended_at:   Option<DateTime<Utc>>,
    pub output:     Option<String>,
}
pub struct Database {
    conn: Mutex<Connection>,
    key:  VaultKey,
}

impl Database {
    pub fn open(path: &Path, key: &VaultKey) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create db directory: {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("open db: {}", path.display()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        schema::initialise(&conn)?;

        Ok(Self { conn: Mutex::new(conn), key: key.clone() })
    }

    fn enc(&self, s: &str) -> Result<String> {
        let blob = self.key.encrypt(s.as_bytes())?;
        Ok(base64::engine::general_purpose::STANDARD.encode(blob))
    }

    fn dec(&self, b64: &str) -> Result<String> {
        let blob  = base64::engine::general_purpose::STANDARD.decode(b64)?;
        let plain = self.key.decrypt(&blob)?;
        String::from_utf8(plain).map_err(Into::into)
    }

    fn dec_opt(&self, opt: Option<String>) -> Option<String> {
        opt.and_then(|s| self.dec(&s).ok())
    }

    pub fn upsert_host(&self, host: &Host) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT INTO hosts (id, address, hostname, os, notes, discovered_at)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(id) DO UPDATE SET
               address=excluded.address,
               hostname=excluded.hostname,
               os=excluded.os,
               notes=excluded.notes",
            params![
                host.id,
                self.enc(&host.address)?,
                host.hostname.as_deref().map(|s| self.enc(s)).transpose()?,
                host.os.as_deref().map(|s| self.enc(s)).transpose()?,
                host.notes.as_deref().map(|s| self.enc(s)).transpose()?,
                host.discovered_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn all_hosts(&self) -> Result<Vec<Host>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, address, hostname, os, notes, discovered_at FROM hosts ORDER BY discovered_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;

        let mut hosts = Vec::new();
        for r in rows {
            let (id, addr_enc, hn_enc, os_enc, notes_enc, ts) = r?;
            hosts.push(Host {
                id:           id.clone(),
                address:      self.dec(&addr_enc).unwrap_or_default(),
                hostname:     self.dec_opt(hn_enc),
                os:           self.dec_opt(os_enc),
                notes:        self.dec_opt(notes_enc),
                discovered_at: DateTime::parse_from_rfc3339(&ts)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            });
        }
        Ok(hosts)
    }

    pub fn upsert_port(&self, port: &Port) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT INTO ports (id, host_id, port, protocol, service, version, state, banner)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(id) DO UPDATE SET
               service=excluded.service,
               version=excluded.version,
               state=excluded.state,
               banner=excluded.banner",
            params![
                port.id,
                port.host_id,
                port.port as i64,
                port.protocol,
                port.service.as_deref().map(|s| self.enc(s)).transpose()?,
                port.version.as_deref().map(|s| self.enc(s)).transpose()?,
                port.state,
                port.banner.as_deref().map(|s| self.enc(s)).transpose()?,
            ],
        )?;
        Ok(())
    }

    pub fn ports_for_host(&self, host_id: &str) -> Result<Vec<Port>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, host_id, port, protocol, service, version, state, banner FROM ports WHERE host_id=?1 ORDER BY port"
        )?;
        let rows = stmt.query_map([host_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?;

        let mut ports = Vec::new();
        for r in rows {
            let (id, hid, p, proto, svc_enc, ver_enc, state, banner_enc) = r?;
            ports.push(Port {
                id,
                host_id:  hid,
                port:     p as u16,
                protocol: proto,
                service:  self.dec_opt(svc_enc),
                version:  self.dec_opt(ver_enc),
                state,
                banner:   self.dec_opt(banner_enc),
            });
        }
        Ok(ports)
    }

    pub fn insert_finding(&self, f: &Finding) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO findings
               (id, host_id, port_id, tool, title, description, severity, host, evidence, metadata, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                f.id,
                f.host_id,
                f.port_id,
                f.tool,
                self.enc(&f.title)?,
                self.enc(&f.description)?,
                f.severity.as_str(),
                self.enc(&f.host)?,
                f.evidence.as_deref().map(|s| self.enc(s)).transpose()?,
                f.metadata.as_deref().map(|s| self.enc(s)).transpose()?,
                f.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn all_findings(&self) -> Result<Vec<Finding>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, host_id, port_id, tool, title, description, severity, host, evidence, metadata, created_at
             FROM findings ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
            ))
        })?;

        let mut findings = Vec::new();
        for r in rows {
            let (id, hid, pid, tool, title_enc, desc_enc, sev, host_enc, ev_enc, meta_enc, ts) = r?;
            findings.push(Finding {
                id,
                host_id:     hid,
                port_id:     pid,
                tool,
                title:       self.dec(&title_enc).unwrap_or_default(),
                description: self.dec(&desc_enc).unwrap_or_default(),
                severity:    Severity::from_str(&sev),
                host:        self.dec(&host_enc).unwrap_or_default(),
                evidence:    self.dec_opt(ev_enc),
                metadata:    self.dec_opt(meta_enc),
                created_at:  DateTime::parse_from_rfc3339(&ts)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            });
        }
        Ok(findings)
    }

    pub fn findings_count(&self) -> Result<u64> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))?;
        Ok(n as u64)
    }

    pub fn insert_job(&self, job: &ScanJob) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT INTO scan_jobs (id, tool, args, target, status, started_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                job.id,
                job.tool,
                self.enc(&job.args)?,
                job.target.as_deref().map(|s| self.enc(s)).transpose()?,
                job.status,
                job.started_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn finish_job(&self, id: &str, exit_code: i32, output: &str) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "UPDATE scan_jobs SET status=?1, exit_code=?2, ended_at=?3, output=?4 WHERE id=?5",
            params![
                if exit_code == 0 { "finished" } else { "failed" },
                exit_code,
                Utc::now().to_rfc3339(),
                self.enc(output)?,
                id,
            ],
        )?;
        Ok(())
    }

    pub fn stats(&self) -> Result<DbStats> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        Ok(DbStats {
            hosts:    conn.query_row("SELECT COUNT(*) FROM hosts", [], |r| r.get::<_,i64>(0))? as u64,
            ports:    conn.query_row("SELECT COUNT(*) FROM ports", [], |r| r.get::<_,i64>(0))? as u64,
            findings: conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get::<_,i64>(0))? as u64,
            jobs:     conn.query_row("SELECT COUNT(*) FROM scan_jobs", [], |r| r.get::<_,i64>(0))? as u64,
        })
    }
}

#[derive(Debug, Default)]
pub struct DbStats {
    pub hosts:    u64,
    pub ports:    u64,
    pub findings: u64,
    pub jobs:     u64,
}
