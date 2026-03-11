
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub general:  GeneralConfig,
    #[serde(default)]
    pub crypto:   CryptoConfig,
    #[serde(default)]
    pub network:  NetworkConfig,
    #[serde(default)]
    pub stealth:  StealthConfig,
    #[serde(default)]
    pub ui:       UiConfig,
    #[serde(default)]
    pub api:      ApiConfig,
    #[serde(default)]
    pub logging:  LoggingConfig,
}

impl AppConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let resolved = path
            .map(PathBuf::from)
            .or_else(|| {
                dirs::config_dir().map(|d| d.join("four-hub").join("config.toml"))
            });

        if let Some(p) = resolved {
            if p.exists() {
                let raw = std::fs::read_to_string(&p)
                    .with_context(|| format!("reading config: {}", p.display()))?;
                let cfg: AppConfig = toml::from_str(&raw)
                    .with_context(|| format!("parsing config: {}", p.display()))?;
                return Ok(cfg);
            }
        }

        Ok(AppConfig::default())
    }
    pub fn db_path(&self) -> PathBuf {
        if self.general.db_path.as_os_str().is_empty() {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".four-hub")
                .join("vault.db")
        } else {
            self.general.db_path.clone()
        }
    }
    pub fn tools_dir(&self) -> PathBuf {
        if self.general.tools_dir.as_os_str().is_empty() {
            PathBuf::from("/usr/share/four-hub/tools")
        } else {
            self.general.tools_dir.clone()
        }
    }
    pub fn plugins_dir(&self) -> PathBuf {
        if self.general.plugins_dir.as_os_str().is_empty() {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("four-hub")
                .join("plugins")
        } else {
            self.general.plugins_dir.clone()
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            crypto:  CryptoConfig::default(),
            network: NetworkConfig::default(),
            stealth: StealthConfig::default(),
            ui:      UiConfig::default(),
            api:     ApiConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default)]
    pub db_path:     PathBuf,
    #[serde(default)]
    pub tools_dir:   PathBuf,
    #[serde(default)]
    pub plugins_dir: PathBuf,
    #[serde(default = "default_project_name")]
    pub project_name: String,
}

fn default_project_name() -> String { "default".to_string() }

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            db_path:      PathBuf::new(),
            tools_dir:    PathBuf::new(),
            plugins_dir:  PathBuf::new(),
            project_name: default_project_name(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    #[serde(default = "default_argon2_mem")]
    pub argon2_memory_kib: u32,
    #[serde(default = "default_argon2_time")]
    pub argon2_time:       u32,
    #[serde(default = "default_argon2_parallel")]
    pub argon2_parallel:   u32,
    #[serde(default)]
    pub salt_hex:          String,
}

fn default_argon2_mem()      -> u32 { 65_536 }
fn default_argon2_time()     -> u32 { 3 }
fn default_argon2_parallel() -> u32 { 4 }

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            argon2_memory_kib: default_argon2_mem(),
            argon2_time:       default_argon2_time(),
            argon2_parallel:   default_argon2_parallel(),
            salt_hex:          String::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "true_default")]
    pub use_proxychains:  bool,
    #[serde(default = "default_proxychains_bin")]
    pub proxychains_bin:  String,
    #[serde(default = "true_default")]
    pub randomise_mac:    bool,
    #[serde(default = "default_iface")]
    pub mac_interface:    String,
}

fn true_default()            -> bool   { true }
fn default_proxychains_bin() -> String { "proxychains4".to_string() }
fn default_iface()           -> String { "eth0".to_string() }

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            use_proxychains: true,
            proxychains_bin: default_proxychains_bin(),
            randomise_mac:   true,
            mac_interface:   default_iface(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthConfig {
    #[serde(default = "true_default")]
    pub wipe_history_on_exit:    bool,
    #[serde(default = "true_default")]
    pub wipe_temp_on_exit:       bool,
    #[serde(default = "true_default")]
    pub wipe_logs_on_exit:       bool,
    #[serde(default = "true_default")]
    pub mlock_sensitive_memory: bool,
    #[serde(default = "default_spoof_name")]
    pub process_spoof_name:      String,
}

fn default_spoof_name() -> String { "kworker/2:1".to_string() }

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            wipe_history_on_exit:   true,
            wipe_temp_on_exit:      true,
            wipe_logs_on_exit:      true,
            mlock_sensitive_memory: true,
            process_spoof_name:     default_spoof_name(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    #[serde(default = "default_theme")]
    pub theme:         String,
    #[serde(default = "default_accent")]
    pub accent_color:  String,
    #[serde(default = "true_default")]
    pub mouse_enabled: bool,
    #[serde(default = "default_fps")]
    pub target_fps:    u32,
}

fn default_theme()  -> String { "cyberpunk".to_string() }
fn default_accent() -> String { "#00ff99".to_string() }
fn default_fps()    -> u32    { 60 }

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme:         default_theme(),
            accent_color:  default_accent(),
            mouse_enabled: true,
            target_fps:    default_fps(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_api_addr")]
    pub bind:    String,
    #[serde(default)]
    pub api_key: String,
}

fn default_api_addr() -> String { "127.0.0.1:7878".to_string() }

impl Default for ApiConfig {
    fn default() -> Self {
        Self { enabled: false, bind: default_api_addr(), api_key: String::new() }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "true_default")]
    pub log_to_file: bool,
}

fn default_log_level() -> String { "info".to_string() }

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { level: default_log_level(), log_to_file: true }
    }
}
