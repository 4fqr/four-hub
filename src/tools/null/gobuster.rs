
use anyhow::Result;
use reqwest::{Client, StatusCode};
use tokio::sync::mpsc;
use std::time::Duration;
use std::sync::Arc;
use tokio::time::timeout;

pub async fn run_4gobuster(
    target: String, 
    wordlist_path: String, 
    threads: usize, 
    tx: mpsc::UnboundedSender<String>
) -> Result<()> {
    let wordlist = match std::fs::read_to_string(&wordlist_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(format!("Error reading wordlist: {}", e));
            anyhow::bail!("Wordlist fail");
        }
    };

    let words: Vec<String> = wordlist.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    

    let client = Client::builder()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge() 
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .build()?;

    let base_url = if target.ends_with('/') { target } else { format!("{}/", target) };
    let _ = tx.send(format!("[INFO] 4gobuster Architect Edition: Fuzzing {} ({} threads)", base_url, threads));
    let _ = tx.send(format!("[PROGRESS] 2%"));


    let test_url = format!("{}nullsector_{}", base_url, chrono::Utc::now().timestamp());
    if let Ok(resp) = client.get(&test_url).send().await {
        if resp.status().is_success() {
            let _ = tx.send("[WARN] Wildcard response detected (404 returns 200). Adjusting...".into());
        }
    }

    let words_arc = Arc::new(words);
    let chunk_size = (words_arc.len() + threads - 1) / threads;
    let mut handles = Vec::new();

    for i in 0..threads {
        let words_chunk = Arc::clone(&words_arc);
        let tx_inner = tx.clone();
        let client_inner = client.clone();
        let base_inner = base_url.clone();

        let handle = tokio::spawn(async move {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(words_chunk.len());
            for idx in start..end {
                let word = &words_chunk[idx];
                let url = format!("{}{}", base_inner, word);
                
                match timeout(Duration::from_secs(3), client_inner.get(&url).send()).await {
                    Ok(Ok(resp)) => {
                        let code = resp.status();
                        if code.is_success() || code == StatusCode::FORBIDDEN || code == StatusCode::MOVED_PERMANENTLY {
                            let size = resp.content_length().unwrap_or(0);
                            let _ = tx_inner.send(format!("[+] {:<20} (Status: {}, Size: {})", format!("/{}", word), code, size));
                        }
                    }
                    _ => {}
                }
            }
        });
        handles.push(handle);
    }

    for (i, h) in handles.into_iter().enumerate() {
        let _ = h.await;
        let p = 2 + ((i + 1) as f32 / threads as f32 * 98.0) as u32;
        if (i+1) % 10 == 0 || i == threads - 1 {
            let _ = tx.send(format!("[PROGRESS] {}%", p));
        }
    }

    let _ = tx.send("[PROGRESS] 100%".into());
    let _ = tx.send("[FINISH] 4gobuster Architect Edition complete.".into());
    Ok(())
}
