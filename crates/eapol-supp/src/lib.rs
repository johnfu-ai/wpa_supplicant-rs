//! EAPOL Supplicant — Supplicant EAPOL state machine.
//!
//! Implements IEEE 802.1X-2020 Clause 8 — Supplicant PAE state machine
//! and Clause 11 — EAPOL frame types.
//!
//! Implements: #11 (REQ-F-PAE-001), #44 (REQ-F-EAPOL-001)
//! Architecture: #74 (ADR-SM-002), #79 (ADR-EVT-007)

#![warn(missing_docs)]

/// Supplicant PAE state machine per IEEE 802.1X-2020, Clause 8.
pub mod supplicant_pae;

/// EAPOL frame types and parsing per IEEE 802.1X-2020, Clause 11.
pub mod frame;

/// Error type for EAPOL supplicant operations.
///
/// Per ADR-ERR-005 (#77).
#[derive(Debug, thiserror::Error)]
pub enum EapolError {
    /// Invalid EAPOL frame (malformed, truncated, oversized).
    #[error("invalid EAPOL frame: {0}")]
    InvalidFrame(String),

    /// EAPOL send failed (L2 socket error).
    #[error("EAPOL send failed: {0}")]
    SendFailed(String),

    /// Timeout waiting for authenticator response.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Invalid PACP state transition.
    #[error("invalid PACP transition: from {from} to {to}")]
    InvalidTransition {
        /// Source state.
        from: String,
        /// Target state.
        to: String,
    },

    /// Maximum retransmission retries exceeded.
    #[error("max retries ({0}) exceeded")]
    MaxRetriesExceeded(u32),

    /// PAE core error propagated from `pae` crate.
    #[error("PAE error: {0}")]
    Pae(#[from] pae::PaeError),
}

// Re-export key types for convenience
pub use frame::{EapolFrame, EapolPacketType, EapolVersion};
pub use supplicant_pae::{PaeCounters, PaeState, SupplicantPae, SupplicantPaeContext};
