// ─── Four-Hub · main.rs ──────────────────────────────────────────────────────
//! Binary entry-point.  All logic lives in the `four_hub` library crate.
//! This file just wires up the async runtime and calls into the library.
#![allow(dead_code)]

use four_hub::app::Application;
use four_hub::config::AppConfig;
use four_hub::crypto::vault::VaultKey;
use four_hub::db::Database;
use four_hub::plugins::runtime::PluginRuntime;
use four_hub::tools::registry::ToolRegistry;

use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // ── 0. Stealth: spoof process name before anything else ──────────────────
    four_hub::stealth::identity::spoof_process_name("kworker/2:1");

    // ── 1. CLI ────────────────────────────────────────────────────────────────
    let cli = CliArgs::parse_env();

    // ── 2. Logging (file + optional TUI ring-buffer) ──────────────────────────
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".four-hub");
    std::fs::create_dir_all(&log_dir)
        .context("failed to create log directory")?;
    let file_appender = tracing_appender::rolling::daily(&log_dir, "four-hub.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "Four-Hub starting");

    // ── 3. Configuration ──────────────────────────────────────────────────────
    let cfg = AppConfig::load(cli.config.as_deref())?;

    // ── 4. Passphrase / vault key ─────────────────────────────────────────────
    let passphrase = if let Some(ref env_key) = cli.passphrase_env {
        std::env::var(env_key)
            .context("passphrase env var not set")?
    } else {
        rpassword::prompt_password("Four-Hub passphrase: ")
            .context("could not read passphrase")?
    };

    let vault_key = VaultKey::derive(&passphrase, &cfg.crypto)?;
    // passphrase is no longer needed – zero memory
    drop(passphrase);

    // ── 5. Encrypted database ─────────────────────────────────────────────────
    let db = Database::open(&cfg.db_path(), &vault_key)
        .context("failed to open encrypted database")?;

    // ── 6. Tool registry ──────────────────────────────────────────────────────
    let registry = ToolRegistry::load(&cfg).await?;

    // ── 7. Plugin runtime ─────────────────────────────────────────────────────
    let plugin_rt = PluginRuntime::new(&cfg).await?;

    // ── 8. Launch TUI ─────────────────────────────────────────────────────────
    let mut application = Application::new(cfg, db, vault_key, registry, plugin_rt)?;
    application.run().await?;

    // ── 9. Anti-forensics on clean exit ──────────────────────────────────────
    four_hub::stealth::anti_forensics::wipe_on_exit();

    info!("Four-Hub exited cleanly");
    Ok(())
}

// ─── minimal CLI parser (avoids heavy clap to keep the binary lean) ───────────
struct CliArgs {
    config:        Option<PathBuf>,
    passphrase_env: Option<String>,
}

impl CliArgs {
    fn parse_env() -> Self {
        let mut args = std::env::args().skip(1);
        let mut config        = None::<PathBuf>;
        let mut passphrase_env = None::<String>;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--config" | "-c" => {
                    config = args.next().map(PathBuf::from);
                }
                "--passphrase-env" | "-p" => {
                    passphrase_env = args.next();
                }
                "--version" | "-V" => {
                    println!("four-hub {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                "--help" | "-h" => {
                    println!(include_str!("../HELP.txt"));
                    std::process::exit(0);
                }
                _ => {}
            }
        }
        Self { config, passphrase_env }
    }
}
