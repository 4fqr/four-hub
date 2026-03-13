
use anyhow::{Result, bail};
use tokio::sync::mpsc;
use std::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::lookup_host;

pub async fn run_4subfinder(target: String, wordlist_path: String, tx: mpsc::UnboundedSender<String>) -> Result<()> {
    let wordlist = match std::fs::read_to_string(&wordlist_path) {
        Ok(s) => s,
        Err(_) => {
            let _ = tx.send("Wordlist missing - using internal elite list".into());
            include_str!("../../../python/subdomains.txt").to_string()
        }
    };

    let subdomains: Vec<String> = wordlist.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let _ = tx.send(format!("🚀 4subfinder Architect: Discovering assets for {}", target));
    let _ = tx.send(format!("[PROGRESS] 5%"));

    let mut found = HashSet::new();
    let threads = 100;
    let chunk_size = (subdomains.len() + threads - 1) / threads;
    let mut handles = Vec::new();

    let target_arc = Arc::new(target);
    let subs_arc = Arc::new(subdomains);

    let (res_tx, mut res_rx) = mpsc::channel(100);

    for i in 0..threads {
        let subs = Arc::clone(&subs_arc);
        let t = Arc::clone(&target_arc);
        let tx_res = res_tx.clone();
        
        handles.push(tokio::spawn(async move {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(subs.len());
            for idx in start..end {
                let sub = &subs[idx];
                let host = format!("{}.{}", sub, t);
                if let Ok(mut addrs) = lookup_host(format!("{}:80", host)).await {
                    if let Some(addr) = addrs.next() {
                        let _ = tx_res.send((host, addr.ip().to_string())).await;
                    }
                }
            }
        }));
    }

    drop(res_tx);
    let total = subs_arc.len() as f64;
    let mut scanned = 0;

    while let Some((domain, ip)) = res_rx.recv().await {
        if found.insert(domain.clone()) {
            let _ = tx.send(format!("[+] Found: {:<30} -> {}", domain, ip));
        }
        scanned += 1;
        let p = 5.0 + (scanned as f64 / (total / 90.0));
        if scanned % 50 == 0 { let _ = tx.send(format!("[PROGRESS] {}%", p.min(95.0) as u32)); }
    }

    for h in handles { let _ = h.await; }

    let _ = tx.send(format!("[PROGRESS] 95%"));
    let _ = tx.send(format!("✨ Phase 2: Passive OSINT Scraping (Simulated)..."));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    

    for s in ["staging", "vpn", "jira", "jenkins", "mail", "api-dev"] {
        let host = format!("{}.{}", s, target_arc);
        if !found.contains(&host) {
             if let Ok(mut addrs) = lookup_host(format!("{}:80", host)).await {
                 if let Some(ip) = addrs.next() {
                    let _ = tx.send(format!("[+] OSINT Catch: {:<30} -> {}", host, ip.ip()));
                 }
             }
        }
    }

    let _ = tx.send(format!("[PROGRESS] 100%"));
    let _ = tx.send(format!("🏆 4subfinder complete. {} assets identified.", found.len()));
    Ok(())
}
