use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let c_dir = PathBuf::from(&manifest).join("c");

    // Declare the `pcap` cfg key so rustc knows it's intentional.
    println!("cargo:rustc-check-cfg=cfg(pcap)");
    println!("cargo:rerun-if-changed=c/packet_capture.c");
    println!("cargo:rerun-if-changed=c/packet_capture.h");

    // Check whether libpcap headers are present before attempting to compile.
    // If not, set a cfg flag that disables the pcap FFI module at compile time.
    let pcap_available = pcap_headers_present();

    if pcap_available {
        // Compile the raw-packet-capture C extension.
        cc::Build::new()
            .file(c_dir.join("packet_capture.c"))
            .include(&c_dir)
            // Remove duplicate _GNU_SOURCE — already defined by -D_GNU_SOURCE flag via cc.
            .define("_GNU_SOURCE", None)
            .flag_if_supported("-Wall")
            .flag_if_supported("-Wextra")
            .flag_if_supported("-O2")
            .compile("packet_capture");

        // Tell cargo to link libpcap.
        println!("cargo:rustc-link-lib=pcap");
        println!("cargo:rustc-cfg=pcap");
    } else {
        eprintln!(
            "cargo:warning=libpcap-dev not found — packet-capture C extension disabled.\n\
             Install with: sudo apt install libpcap-dev"
        );
    }
}

/// Returns true if pcap/pcap.h can be found in standard include paths.
fn pcap_headers_present() -> bool {
    // Quick probe: ask the compiler to find the header.
    let status = Command::new("sh")
        .arg("-c")
        .arg("printf '#include <pcap/pcap.h>\\nint main(){return 0;}' | \
              ${CC:-cc} -x c - -lpcap -o /dev/null 2>/dev/null")
        .status();

    matches!(status, Ok(s) if s.success())
}

