
use std::{path::PathBuf, process::Command};
use tracing::{info, warn};
pub fn wipe_on_exit() {
    wipe_shell_history();
    wipe_temp_files();
}

fn wipe_shell_history() {
    let candidates = vec![
        dirs::home_dir().map(|h| h.join(".bash_history")),
        dirs::home_dir().map(|h| h.join(".zsh_history")),
        dirs::home_dir().map(|h| h.join(".sh_history")),
    ];
    for opt in candidates.into_iter().flatten() {
        if opt.exists() {
            match secure_delete(&opt) {
                Ok(_)  => info!(path = %opt.display(), "wiped shell history"),
                Err(e) => warn!(path = %opt.display(), err = %e, "could not wipe history"),
            }
        }
    }
    std::env::set_var("HISTSIZE", "0");
    std::env::set_var("HISTFILESIZE", "0");
}

fn wipe_temp_files() {
    let patterns = vec![
        "/tmp/fh_*",
        "/tmp/four-hub-*",
    ];
    for pat in patterns {
        let _ = Command::new("sh")
            .args(["-c", &format!("rm -rf {pat} 2>/dev/null")])
            .output();
    }
    info!("temp files wiped");
}
fn secure_delete(path: &PathBuf) -> std::io::Result<()> {
    use std::io::Write;
    let meta = std::fs::metadata(path)?;
    let size = meta.len() as usize;
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; size.min(1024 * 1024)]; // overwrite up to 1 MiB
        let mut written = 0usize;
        while written < size {
            let chunk = zeros.len().min(size - written);
            f.write_all(&zeros[..chunk])?;
            written += chunk;
        }
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}
