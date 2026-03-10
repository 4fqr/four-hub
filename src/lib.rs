// ─── Four-Hub · lib.rs ────────────────────────────────────────────────────────
//! Library interface – exposes all internal modules for integration tests and
//! for the binary entry-point in `main.rs`.
#![allow(dead_code)]

pub mod app;
pub mod config;
pub mod crypto;
pub mod db;
#[cfg(pcap)]
pub mod pcap_ffi;
pub mod plugins;
pub mod reporting;
pub mod stealth;
pub mod tools;
pub mod tui;
