//! EAPOL Supplicant — Supplicant EAPOL state machine.
//!
//! Implements IEEE 802.1X-2020 Clause 8 — Supplicant PAE state machine
//! and Clause 11 — EAPOL frame types.
//!
//! Implements: #11 (REQ-F-PAE-001), #12 (REQ-F-PAE-002), #13 (REQ-F-PAE-003), #14 (REQ-F-PAE-004), #15 (REQ-F-PAE-005), #16 (REQ-F-PAE-006), #17 (REQ-F-PAE-007), #18 (REQ-F-PAE-008), #44 (REQ-F-EAPOL-001), #45 (REQ-F-EAPOL-002), #46 (REQ-F-EAPOL-003), #35 (REQ-F-LOGON-003)
//! Architecture: #74 (ADR-SM-002), #79 (ADR-EVT-007)

#![warn(missing_docs)]

/// Supplicant PAE state machine per IEEE 802.1X-2020, Clause 8.
pub mod supplicant_pae;

/// EAPOL frame types and parsing per IEEE 802.1X-2020, Clause 11.
pub mod frame;

/// EAPOL frame transmission per IEEE 802.1X-2020, Clause 11.1.
pub mod transmitter;

/// EAPOL frame reception and dispatch per IEEE 802.1X-2020, Clause 11.1.
pub mod receiver;

/// EAPOL-Announcement parsing per IEEE 802.1X-2020, Clauses 10.3 and 11.12.
pub mod announcement;

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
pub use announcement::{AccessStatus, AnnouncementNidEntry, EapolAnnouncement};
pub use frame::{EapolFrame, EapolPacketType, EapolVersion};
pub use receiver::{
    AnnouncementHandler, DispatchResult, EapHandler, EapolReceiver, FrameReceiver, MkaHandler,
};
pub use supplicant_pae::{AuthResult, PaeCounters, PaeState, SupplicantPae, SupplicantPaeContext};
pub use transmitter::{EapolTransmitter, FrameSender, PAE_GROUP_MAC};
