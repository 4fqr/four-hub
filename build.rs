use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let c_dir = PathBuf::from(&manifest).join("c");


    println!("cargo:rustc-check-cfg=cfg(pcap)");
    println!("cargo:rerun-if-changed=c/packet_capture.c");
    println!("cargo:rerun-if-changed=c/packet_capture.h");



    let pcap_available = pcap_headers_present();

    if pcap_available {

        cc::Build::new()
            .file(c_dir.join("packet_capture.c"))
            .include(&c_dir)

            .define("_GNU_SOURCE", None)
            .flag_if_supported("-Wall")
            .flag_if_supported("-Wextra")
            .flag_if_supported("-O2")
            .compile("packet_capture");


        println!("cargo:rustc-link-lib=pcap");
        println!("cargo:rustc-cfg=pcap");
    } else {
        eprintln!(
            "cargo:warning=libpcap-dev not found — packet-capture C extension disabled.\n\
             Install with: sudo apt install libpcap-dev"
        );
    }
}


fn pcap_headers_present() -> bool {

    let status = Command::new("sh")
        .arg("-c")
        .arg("printf '#include <pcap/pcap.h>\\nint main(){return 0;}' | \
              ${CC:-cc} -x c - -lpcap -o /dev/null 2>/dev/null")
        .status();

    matches!(status, Ok(s) if s.success())
}

