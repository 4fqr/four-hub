use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    IpOrCidr,
    IpOrDomain,
    Domain,
    Url,
    Port,
    File,
    HashOrWordlist,
    Interface,
    Username,
    IpPort,
    Custom,
}

impl TargetType {
    pub fn hint(&self) -> &'static str {
        match self {
            Self::IpOrCidr       => "IP / CIDR  e.g. 192.168.1.0/24",
            Self::IpOrDomain     => "IP or domain  e.g. 10.0.0.1 / example.com",
            Self::Domain         => "Domain  e.g. example.com",
            Self::Url            => "URL  e.g. https://target.com",
            Self::Port           => "HOST:PORT  e.g. 10.0.0.1:80",
            Self::File           => "File path  e.g. /tmp/hashes.txt",
            Self::HashOrWordlist => "Hash or wordlist path",
            Self::Interface      => "Interface  e.g. wlan0 / eth0",
            Self::Username       => "Username  e.g. admin",
            Self::IpPort         => "IP:PORT  e.g. 10.0.0.1:445",
            Self::Custom         => "Target",
        }
    }
}

impl Default for TargetType {
    fn default() -> Self { Self::IpOrDomain }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name:         String,
    pub binary:       String,
    pub description:  String,
    pub category:     String,
    #[serde(default)]
    pub default_args: Vec<String>,
    #[serde(default)]
    pub wrapper:      Option<String>,
    #[serde(default)]
    pub needs_root:   bool,
    #[serde(default = "default_proxychains")]
    pub proxychains:  bool,
    #[serde(default)]
    pub interactive:  bool,
    #[serde(default)]
    pub tags:         Vec<String>,
    #[serde(default)]
    pub target_type:  TargetType,
    #[serde(default)]
    pub target_hint:  String,
    #[serde(default)]
    pub is_builtin:   bool,
}

fn default_proxychains() -> bool { true }

impl ToolSpec {
    pub fn effective_hint(&self) -> &str {
        if self.target_hint.is_empty() {
            self.target_type.hint()
        } else {
            &self.target_hint
        }
    }

    pub fn build_argv(&self, target: &str, wordlist: &str, proxychains_bin: &str, use_proxychains: bool) -> Vec<String> {
        let mut argv = Vec::new();
        if self.proxychains && use_proxychains {
            argv.push(proxychains_bin.to_string());
        }
        if self.needs_root && !running_as_root() {
            argv.push("sudo".to_string());
        }
        argv.push(self.binary.clone());
        for arg in &self.default_args {
            let mut s = arg.replace("{target}", target);
            if !wordlist.is_empty() {
                s = s.replace("{wordlist}", wordlist);
            }
            argv.push(s);
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
