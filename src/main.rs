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
    four_hub::stealth::StealthEngine::engage_all();
    let cli = CliArgs::parse_env();
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
    let cfg = AppConfig::load(cli.config.as_deref())?;
    let passphrase = if let Some(ref env_key) = cli.passphrase_env {
        std::env::var(env_key)
            .context("passphrase env var not set")?
    } else {
        rpassword::prompt_password("Four-Hub passphrase: ")
            .context("could not read passphrase")?
    };

    let vault_key = VaultKey::derive(&passphrase, &cfg.crypto)?;
    drop(passphrase);
    let db = Database::open(&cfg.db_path(), &vault_key)
        .context("failed to open encrypted database")?;
    let registry = ToolRegistry::load(&cfg).await?;
    let plugin_rt = PluginRuntime::new(&cfg).await?;
    let mut application = Application::new(cfg, db, vault_key, registry, plugin_rt)?;
    application.run().await?;
    four_hub::stealth::anti_forensics::wipe_on_exit();

    info!("Four-Hub exited cleanly");
    Ok(())
}
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
