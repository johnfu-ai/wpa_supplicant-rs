//! EAP Peer — EAP authentication methods for the supplicant.
//!
//! Implements EAP peer methods used by the IEEE 802.1X-2020 supplicant:
//! - EAP-TLS (feature: `eap-tls`, enabled by default)
//! - EAP-PEAP (feature: `eap-peap`)
//! - EAP-TEAP (feature: `eap-teap`)

#![warn(missing_docs)]

/// EAP peer core types and state machine.
pub mod peer;

/// EAP-TLS method.
#[cfg(feature = "eap-tls")]
pub mod eap_tls;

/// EAP-PEAP method.
#[cfg(feature = "eap-peap")]
pub mod eap_peap;

/// EAP-TEAP method per RFC 7170.
#[cfg(feature = "eap-teap")]
pub mod eap_teap;

/// Error type for EAP peer operations.
#[derive(Debug, thiserror::Error)]
pub enum EapError {
    /// Authentication failed.
    #[error("EAP authentication failed: {0}")]
    AuthFailed(String),

    /// Invalid EAP packet.
    #[error("invalid EAP packet: {0}")]
    InvalidPacket(String),

    /// TLS handshake error.
    #[error("TLS error: {0}")]
    TlsError(String),
}
