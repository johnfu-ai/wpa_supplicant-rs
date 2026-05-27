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
mod logging;
pub mod network_io;
mod shutdown;
mod supplicant;
#[cfg(feature = "systemd")]
mod systemd;

pub use config::{
    Config, ControlConfig, ControlType, EapConfig, EapMethodConfig, LoggingConfig, LogonConfig,
    MacsecConfig, NidGroupConfig,
};
pub use control::{ControlCommand, ControlInterface};
pub use logging::Logging;
pub use network_io::NetworkIo;
pub use shutdown::ShutdownHandler;
pub use supplicant::{Supplicant, SupplicantState};

#[cfg(feature = "systemd")]
pub use systemd::{generate_socket_unit, generate_unit_file, SystemdActivation};

fn main() {
    let logging = Logging::init("info").expect("failed to initialize logging");

    tracing::info!("wpa_supplicant-rs starting");

    let shutdown = ShutdownHandler::install().expect("failed to install signal handlers");

    // TODO: Load config, create supplicant, run event loop
    let _ = (logging, shutdown);
}
