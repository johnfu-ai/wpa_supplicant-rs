//! IEEE 802.1X-2020 Supplicant — binary entry point.
//!
//! Implements: #70 (REQ-NF-DEPLOY-003: Configuration File Support)
//! Architecture: #85 (ARC-C-WPA-005)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use wpa_supplicant::{Logging, ShutdownHandler};

fn main() {
    let logging = Logging::init("info").expect("failed to initialize logging");

    tracing::info!("wpa_supplicant-rs starting");

    let shutdown = ShutdownHandler::install().expect("failed to install signal handlers");

    // TODO: Load config, create supplicant, run event loop (INT-001 / #109)
    let _ = (logging, shutdown);
}
