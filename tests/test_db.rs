


use four_hub::config::CryptoConfig;
use four_hub::crypto::vault::VaultKey;
use four_hub::db::{Database, Finding, Host, Port, Severity};
use tempfile::TempDir;

fn test_vault() -> VaultKey {
    let cfg = CryptoConfig {
        argon2_memory_kib: 8192,
        argon2_time:       1,
        argon2_parallel:   1,

        salt_hex: "aabbccddaabbccddaabbccddaabbccdd".to_owned(),
    };
    VaultKey::derive("test-passphrase", &cfg).unwrap()
}

fn temp_db() -> (TempDir, Database) {
    let dir  = TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let key  = test_vault();
    let db   = Database::open(&path, &key).expect("open db");
    (dir, db)
}

#[test]
fn host_upsert_and_query() {
    let (_dir, db) = temp_db();
    let host = Host {
        id:           uuid::Uuid::new_v4().to_string(),
        address:      "10.0.0.1".to_owned(),
        hostname:     Some("victim.local".to_owned()),
        os:           Some("Linux".to_owned()),
        notes:        None,
        discovered_at: chrono::Utc::now(),
    };
    db.upsert_host(&host).unwrap();

    let hosts = db.all_hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].address, "10.0.0.1");
    assert_eq!(hosts[0].hostname.as_deref(), Some("victim.local"));
}

#[test]
fn port_upsert_and_query() {
    let (_dir, db) = temp_db();
    let host_id = uuid::Uuid::new_v4().to_string();
    let host = Host {
        id:           host_id.clone(),
        address:      "192.168.1.1".to_owned(),
        hostname:     None,
        os:           None,
        notes:        None,
        discovered_at: chrono::Utc::now(),
    };
    db.upsert_host(&host).unwrap();

    let port = Port {
        id:       uuid::Uuid::new_v4().to_string(),
        host_id:  host_id.clone(),
        port:     80,
        protocol: "tcp".to_owned(),
        service:  Some("http".to_owned()),
        version:  None,
        banner:   Some("Apache/2.4".to_owned()),
        state:    "open".to_owned(),
    };
    db.upsert_port(&port).unwrap();

    let ports = db.ports_for_host(&host_id).unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].port, 80);
    assert_eq!(ports[0].service.as_deref(), Some("http"));
}

#[test]
fn finding_insert_and_query() {
    let (_dir, db) = temp_db();
    let finding = Finding {
        id:          uuid::Uuid::new_v4().to_string(),
        host_id:     None,
        port_id:     None,
        tool:        "nmap".to_owned(),
        title:       "Open port 22/tcp".to_owned(),
        description: "SSH service detected.".to_owned(),
        severity:    Severity::Medium,
        evidence:    Some("22/tcp open ssh".to_owned()),
        created_at:  chrono::Utc::now(),
    };
    db.insert_finding(&finding).unwrap();

    let findings = db.all_findings().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "nmap");
    assert!(matches!(findings[0].severity, Severity::Medium));
}

#[test]
fn stats_reflect_data() {
    let (_dir, db) = temp_db();

    for i in 0..3 {
        let host = Host {
            id:           uuid::Uuid::new_v4().to_string(),
            address:      format!("10.0.0.{}", i + 1),
            hostname:     None,
            os:           None,
            notes:        None,
            discovered_at: chrono::Utc::now(),
        };
        db.upsert_host(&host).unwrap();
    }
    let f = Finding {
        id:          uuid::Uuid::new_v4().to_string(),
        host_id:     None,
        port_id:     None,
        tool:        "test".to_owned(),
        title:       "test finding".to_owned(),
        description: String::new(),
        severity:    Severity::High,
        evidence:    None,
        created_at:  chrono::Utc::now(),
    };
    db.insert_finding(&f).unwrap();

    let stats = db.stats().unwrap();
    assert_eq!(stats.hosts, 3);
    assert_eq!(stats.findings, 1);
}
