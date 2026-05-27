//! IEEE 802.1X-2020 Supplicant
//!
//! A Rust implementation of the IEEE 802.1X-2020 supplicant role,
//! supporting EAPOL, EAP peer methods, MKA, CP, and the Logon Process.
//!
//! Implements: #70 (REQ-NF-DEPLOY-003: Configuration File Support)
//! Architecture: #85 (ARC-C-WPA-005)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

mod config;
pub mod control;
pub mod network_io;
mod supplicant;

use tracing_subscriber::EnvFilter;

pub use config::{
    Config, ControlConfig, ControlType, EapConfig, EapMethodConfig, LoggingConfig, LogonConfig,
    MacsecConfig, NidGroupConfig,
};
pub use control::{ControlCommand, ControlInterface};
pub use network_io::NetworkIo;
pub use supplicant::{Supplicant, SupplicantState};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("wpa_supplicant-rs starting");
    // TODO: Initialize supplicant PAE, EAPOL, and event loop
}
