//! EAP Peer — EAP authentication methods for the supplicant.
//!
//! Implements the EAP peer framework per IETF RFC 3748, with key
//! derivation per RFC 5247 ("EAP Key Management Framework") feeding
//! MKA (IEEE 802.1X-2020 Clause 9) via the `key_derivation` module.
//!
//! Implements: #38 (REQ-F-EAP-001: EAP Peer Framework)
//! Architecture: #74 (ADR-SM-002), #78 (ADR-FF-006)
//!
//! IMPORTANT: This implementation is based on understanding of the
//! cited RFCs and IEEE 802.1X-2020. No copyrighted content from those
//! documents is reproduced.

#![warn(missing_docs)]

/// EAP peer core types and state machine per RFC 3748.
///
/// Implements: #38 (REQ-F-EAP-001)
pub mod peer;

/// EAP method key derivation for MKA, per RFC 5247.
///
/// Implements: #43 (REQ-F-EAP-006)
pub mod key_derivation;

/// EAP-TLS method per RFC 5216.
///
/// Implements: #39 (REQ-F-EAP-002)
#[cfg(feature = "eap-tls")]
pub mod eap_tls;

/// EAP-PEAP method per draft-josefsson-pppext-eap-tls-eap-10.
///
/// Implements: #40 (REQ-F-EAP-003)
#[cfg(feature = "eap-peap")]
pub mod eap_peap;

/// EAP-TEAP method per RFC 7170.
///
/// Implements: #41 (REQ-F-EAP-004)
#[cfg(feature = "eap-teap")]
pub mod eap_teap;

/// Error type for EAP peer operations.
///
/// Per ADR-ERR-005 (#77).
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

    /// No acceptable EAP method (NAK exhausted).
    #[error("no acceptable EAP method")]
    NoAcceptableMethod,

    /// Method negotiation failed.
    #[error("method negotiation failed: proposed {proposed:?}, available {available:?}")]
    NegotiationFailed {
        /// Proposed EAP type numbers by authenticator.
        proposed: Vec<u8>,
        /// Available EAP type numbers on the peer.
        available: Vec<u8>,
    },

    /// Retransmission timeout.
    #[error("retransmission timeout after {attempts} attempts")]
    RetransmitTimeout {
        /// Number of retransmission attempts.
        attempts: u32,
    },

    /// PAE core error propagated from `pae` crate.
    #[error("PAE error: {0}")]
    Pae(#[from] pae::PaeError),
}

// Re-export key types for convenience
pub use peer::{
    EapCode, EapContext, EapMethod, EapMethodOutput, EapPacket, EapPeer, EapPeerState, EapType,
    TlsClientConfig,
};

#[cfg(feature = "eap-tls")]
pub use eap_tls::{EapTls, EapTlsState, TlsEngine};

#[cfg(feature = "eap-peap")]
pub use eap_peap::{EapPeap, EapPeapState};

#[cfg(feature = "eap-teap")]
pub use eap_teap::{EapTeap, EapTeapState};
