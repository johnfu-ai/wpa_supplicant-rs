//! IEEE 802.1X-2020 Supplicant
//!
//! A Rust implementation of the IEEE 802.1X-2020 supplicant role,
//! supporting EAPOL, EAP peer methods, MKA, CP, and the Logon Process.

use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("wpa_supplicant-rs starting");
    // TODO: Initialize supplicant PAE, EAPOL, and event loop
}
