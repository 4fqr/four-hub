// ─── Four-Hub · tools/spec.rs ────────────────────────────────────────────────
//! `ToolSpec` – the normalised descriptor for a single tool entry.
//! Loaded from TOML manifests under `tools/`.

use serde::{Deserialize, Serialize};

/// A complete tool descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    /// Human-readable name, e.g. "nmap".
    pub name:         String,
    /// Executable binary name, e.g. "nmap" or "/usr/bin/nmap".
    pub binary:       String,
    /// Short one-line description shown in the launcher.
    pub description:  String,
    /// Logical category: Recon / Web / Exploitation / Wireless / Password / Network / Custom.
    pub category:     String,
    /// Default CLI arguments (may contain the `{target}` placeholder).
    #[serde(default)]
    pub default_args: Vec<String>,
    /// Optional path to a Python wrapper script for output parsing.
    #[serde(default)]
    pub wrapper:      Option<String>,
    /// Whether the tool requires root / sudo.
    #[serde(default)]
    pub needs_root:   bool,
    /// Whether to wrap execution in proxychains.
    #[serde(default = "default_proxychains")]
    pub proxychains:  bool,
    /// If true, the tool runs interactively and is opened in the embedded terminal panel.
    #[serde(default)]
    pub interactive:  bool,
    /// Tags for search.
    #[serde(default)]
    pub tags:         Vec<String>,
}

fn default_proxychains() -> bool { true }

impl ToolSpec {
    /// Build the full argv for this tool given a `target` string.
    /// Replaces `{target}` placeholder in each arg with the actual target.
    pub fn build_argv(&self, target: &str, proxychains_bin: &str, use_proxychains: bool) -> Vec<String> {
        let mut argv = Vec::new();

        if self.proxychains && use_proxychains {
            argv.push(proxychains_bin.to_string());
        }
        if self.needs_root && !running_as_root() {
            argv.push("sudo".to_string());
        }

        argv.push(self.binary.clone());

        for arg in &self.default_args {
            argv.push(arg.replace("{target}", target));
        }

        argv
    }
}

fn running_as_root() -> bool {
    #[cfg(unix)]
    { unsafe { libc::geteuid() == 0 } }
    #[cfg(not(unix))]
    { false }
}
