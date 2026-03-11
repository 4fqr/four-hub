
use std::process::Command;
use tracing::{info, warn};
pub fn randomise_mac(iface: &str) -> anyhow::Result<()> {
    let which_mc = which::which("macchanger");
    if which_mc.is_ok() {
        let out = Command::new("macchanger")
            .args(["-r", iface])
            .output()?;
        if out.status.success() {
            info!(iface, "MAC randomised via macchanger");
            return Ok(());
        }
    }
    let mac = random_mac();
    let out = Command::new("ip")
        .args(["link", "set", "dev", iface, "down"])
        .output()?;
    if !out.status.success() {
        warn!(iface, "ip link set down failed");
    }
    let out = Command::new("ip")
        .args(["link", "set", "dev", iface, "address", &mac])
        .output()?;
    let _ = Command::new("ip")
        .args(["link", "set", "dev", iface, "up"])
        .output();
    if out.status.success() {
        info!(iface, mac = %mac, "MAC randomised via ip");
        Ok(())
    } else {
        anyhow::bail!("MAC randomisation failed on {iface}")
    }
}
fn random_mac() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 6];
    rng.fill_bytes(&mut bytes);
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}
