
use anyhow::{Result, bail};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use tokio::sync::mpsc;
use std::sync::Arc;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::timeout;
use tokio::io::AsyncReadExt;

pub async fn run_4nmap(target: String, ports: Vec<u16>, threads: usize, timeout_ms: u64, tx: mpsc::UnboundedSender<String>) -> Result<()> {

    let addr: IpAddr = match target.parse() {
        Ok(a) => a,
        Err(_) => {
            match tokio::net::lookup_host(format!("{}:80", target)).await?.next() {
                Some(sa) => sa.ip(),
                None => {
                    let _ = tx.send("Error: Could not resolve target".into());
                    bail!("Resolution fail")
                }
            }
        }
    };

    let _ = tx.send(format!("[PROGRESS] 2%"));
    let _ = tx.send(format!("[INFO] 4nmap Architect Edition starting on {}", target));


    let os_guess = match TcpStream::connect_timeout(&SocketAddr::new(addr, 80), Duration::from_millis(1000))
        .or_else(|_| TcpStream::connect_timeout(&SocketAddr::new(addr, 22), Duration::from_millis(1000))) {
        Ok(s) => {
            if let Ok(ttl) = s.ttl() {
                if ttl > 64 && ttl <= 128 { "Windows (TTL: {})" }
                else if ttl <= 64 { "Linux/Unix (TTL: {})" }
                else { "Network/Legacy (TTL: {})" }
                .replace("{}", &ttl.to_string())
            } else { "Unknown OS".into() }
        }
        Err(_) => "Unknown OS (No response on 80/22)".into(),
    };
    let _ = tx.send(format!("[INFO] Fingerprint: {}", os_guess));
    let _ = tx.send(format!("[PROGRESS] 5%"));


    let mut ports = ports;
    let mut rng_seed = [0u8; 8];
    let _ = getrandom::getrandom(&mut rng_seed);
    let mut seed = u64::from_le_bytes(rng_seed);
    for i in (1..ports.len()).rev() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (seed % (i as u64 + 1)) as usize;
        ports.swap(i, j);
    }

    let ports_arc = Arc::new(ports);
    let chunk_size = (ports_arc.len() + threads - 1) / threads;
    let mut handles = Vec::new();
    let timeout_dur = Duration::from_millis(timeout_ms);
    let (res_tx, mut res_rx) = mpsc::channel(100);

    let _ = tx.send(format!("[INFO] Phase 1: High-speed Parallel Scan ({} threads)...", threads));


    for i in 0..threads {
        let ports_chunk = Arc::clone(&ports_arc);
        let tx_scan = res_tx.clone();
        
        handles.push(tokio::spawn(async move {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(ports_chunk.len());
            for idx in start..end {
                let port = ports_chunk[idx];
                let socket_addr = SocketAddr::new(addr, port);
                if let Ok(Ok(_)) = timeout(timeout_dur, TokioTcpStream::connect(socket_addr)).await {
                    let _ = tx_scan.send(port).await;
                }
            }
        }));
    }

    drop(res_tx);
    let mut open_ports = Vec::new();
    let total_ports = ports_arc.len() as f64;
    let mut scanned = 0;


    while let Some(port) = res_rx.recv().await {
        open_ports.push(port);
        let _ = tx.send(format!("Port {} is OPEN", port));
        scanned += 1;
        let p = 5.0 + (scanned as f64 / (total_ports / 20.0)) * 40.0;
        if scanned % 10 == 0 { let _ = tx.send(format!("[PROGRESS] {}%", p.min(45.0) as u32)); }
    }

    for h in handles { let _ = h.await; }
    
    let _ = tx.send(format!("[PROGRESS] 50%"));
    let _ = tx.send(format!("[INFO] Phase 2: Architect-Level Fingerprinting ({} open ports)...", open_ports.len()));

    let mut current_p = 50.0;
    let p_step = 45.0 / open_ports.len().max(1) as f64;

    for port in open_ports {
        let socket_addr = SocketAddr::new(addr, port);
        match timeout(Duration::from_millis(2000), TokioTcpStream::connect(socket_addr)).await {
            Ok(Ok(mut stream)) => {
                let mut buf = [0u8; 1024];

                match port {
                    80 | 443 | 8080 | 8443 => {
                        let _ = tx.send(format!("  [Service] {}: HTTP/S (Web Server)", port));

                        let _ = stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
                    }
                    21 => { let _ = tx.send(format!("  [Service] {}: FTP (File Transfer)", port)); }
                    22 => { let _ = tx.send(format!("  [Service] {}: SSH (Remote Shell)", port)); }
                    _  => { let _ = tx.send(format!("  [Service] {}: Potential Service detected", port)); }
                }

                if let Ok(Ok(n)) = timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
                    if n > 0 {
                        let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        let banner_clean = banner.replace('\n', " ").replace('\r', " ");
                        let snippet = banner_clean.chars().take(80).collect::<String>();
                        let _ = tx.send(format!("    └ Banner: {}", snippet));
                        check_vulns(&tx, port, &banner).await;
                    }
                }
            }
            _ => {}
        }
        current_p += p_step;
        let _ = tx.send(format!("[PROGRESS] {}%", current_p as u32));
    }

    let _ = tx.send(format!("[PROGRESS] 100%"));
    let _ = tx.send("[FINISH] 4nmap Architect Edition: Operation Complete.".into());
    Ok(())
}

async fn check_vulns(tx: &mpsc::UnboundedSender<String>, port: u16, banner: &str) {
    let b = banner.to_lowercase();
    let checks = [
        ("openssh_7.2", "CVE-2016-6210 (SSH User Enum)"),
        ("apache/2.4.49", "CVE-2021-41773 (RCE/Path Traversal)"),
        ("vsftpd 2.3.4", "VSFTPD Backdoor found!"),
        ("php/7.4", "End-of-life PHP detected"),
        ("iis/7.0", "Legacy IIS 7.0 (Many CVEs)"),
        ("smb", "EternalBlue (MS17-010) potential"),
        ("mysql", "MySQL Authentication Bypass potential"),
    ];

    for (pat, desc) in checks {
        if b.contains(pat) {
            let _ = tx.send(format!("  [!] [VULNERABILITY] {}: {}", port, desc));
        }
    }
}
async fn write_all(stream: &mut TokioTcpStream, data: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(data).await
}
