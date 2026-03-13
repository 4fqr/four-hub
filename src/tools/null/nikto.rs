
use anyhow::Result;
use reqwest::Client;
use tokio::sync::mpsc;
use std::time::Duration;

pub async fn run_4nikto(target: String, tx: mpsc::UnboundedSender<String>) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (NullSector; Elite VulnScan)")
        .build()?;

    let base_url = if target.starts_with("http") { target } else { format!("http://{}", target) };
    let base_url = if base_url.ends_with('/') { base_url } else { format!("{}/", base_url) };

    let _ = tx.send(format!("🚀 4nikto Elite Powerhouse started on {}", base_url));
    let _ = tx.send("[PROGRESS] 10%".into());

    let checks = vec![
        (".env", "Sensitive Environment File exposed"),
        (".git/config", "Critical Git Repository config exposed"),
        ("wp-config.php.bak", "WordPress Backup Configuration exposed"),
        ("info.php", "PHPInfo debug page exposed"),
        ("server-status", "Apache Server Status exposed"),
        ("pma/", "phpMyAdmin access found"),
        (".ssh/id_rsai", "SSH Private Key potentially exposed"),
        ("robots.txt", "Robots.txt found (Check for hidden paths)"),
        (".DS_Store", "macOS metadata file leaked"),
        ("config.json", "Potential configuration file exposed"),
        ("backup.sql", "Database backup found"),
    ];

    let total = checks.len();
    for (i, (path, desc)) in checks.into_iter().enumerate() {
        let url = format!("{}{}", base_url, path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                let _ = tx.send(format!("[VULNERABILITY] {} at {}", desc, url));
            }
        }
        let p = 10 + ((i + 1) as f32 / total as f32 * 90.0) as u32;
        let _ = tx.send(format!("[PROGRESS] {}%", p));
    }

    let _ = tx.send("[PROGRESS] 100%".into());
    let _ = tx.send("🏆 4nikto Elite scan complete.".into());
    Ok(())
}
