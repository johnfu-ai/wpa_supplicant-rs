//! Logon Process — NID-based network selection per IEEE 802.1X-2020, Clause 12.
//!
//! Implements the Logon Process state machine that handles NID (Network Identity)
//! group management and supplicant-side network selection before EAPOL
//! authentication.
//!
//! Implements: #33 (REQ-F-LOGON-001: Logon Process State Machine)
//! Architecture: #74 (ADR-SM-002), #79 (ADR-EVT-007)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

#![warn(missing_docs)]

/// Logon Process state machine per IEEE 802.1X-2020, Clause 12.
pub mod logon_sm;

/// NID (Network Identity) group types per IEEE 802.1X-2020, Clause 12.5.
pub mod nid;

/// Error type for Logon Process operations.
///
/// Per ADR-ERR-005 (#77).
#[derive(Debug, thiserror::Error)]
pub enum LogonError {
    /// Invalid NID group.
    #[error("invalid NID group: {0}")]
    InvalidNid(String),

    /// Logon state machine error.
    #[error("logon state machine error: {0}")]
    StateError(String),

    /// No matching NID group found.
    #[error("no matching NID group for advertised: {0:?}")]
    NoMatchingNid(Vec<u8>),

    /// CAK cache miss.
    #[error("CAK cache miss for CKN")]
    CakCacheMiss,

    /// CAK cache expired.
    #[error("CAK cache entry expired")]
    CakCacheExpired,

    /// Authentication failed and no fallback available.
    #[error("authentication failed, no fallback available")]
    NoFallback,

    /// Invalid Logon state transition.
    #[error("invalid logon transition: from {from} to {to}")]
    InvalidTransition {
        /// Source state.
        from: String,
        /// Target state.
        to: String,
    },

    /// EAPOL error propagated from `eapol-supp` crate.
    #[error("EAPOL error: {0}")]
    Eapol(#[from] eapol_supp::EapolError),

    /// PAE error propagated from `pae` crate.
    #[error("PAE error: {0}")]
    Pae(#[from] pae::PaeError),
}

pub use logon_sm::{LogonContext, LogonProcess, LogonState};
pub use nid::NidGroup;
