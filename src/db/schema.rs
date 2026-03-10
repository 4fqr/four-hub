// ─── Four-Hub · db/schema.rs ─────────────────────────────────────────────────
//! DDL: create tables if they do not yet exist.

use anyhow::Result;
use rusqlite::Connection;

pub fn initialise(conn: &Connection) -> Result<()> {
    conn.execute_batch(DDL)?;
    Ok(())
}

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS hosts (
    id            TEXT PRIMARY KEY,
    address       TEXT NOT NULL,
    hostname      TEXT,
    os            TEXT,
    notes         TEXT,
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    id        TEXT PRIMARY KEY,
    host_id   TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port      INTEGER NOT NULL,
    protocol  TEXT NOT NULL,
    service   TEXT,
    version   TEXT,
    state     TEXT NOT NULL DEFAULT 'open',
    banner    TEXT
);

CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    host_id     TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    port_id     TEXT REFERENCES ports(id) ON DELETE SET NULL,
    tool        TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    evidence    TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_host     ON findings(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id         TEXT PRIMARY KEY,
    tool       TEXT NOT NULL,
    args       TEXT NOT NULL,
    target     TEXT,
    status     TEXT NOT NULL DEFAULT 'running',
    exit_code  INTEGER,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    output     TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs(status);

CREATE TABLE IF NOT EXISTS notes (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    host_id    TEXT REFERENCES hosts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

INSERT OR IGNORE INTO schema_version(version) VALUES (1);
"#;
