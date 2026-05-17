//! Logon Process — NID-based network selection per IEEE 802.1X-2020, Clause 12.
//!
//! Implements the Logon Process state machine that handles NID (Network Identity)
//! group management and supplicant-side network selection before EAPOL
//! authentication.

#![warn(missing_docs)]

/// Logon Process state machine per IEEE 802.1X-2020, Clause 12.
pub mod logon_sm;

/// NID (Network Identity) group types per IEEE 802.1X-2020, Clause 12.5.
pub mod nid;

/// Error type for Logon Process operations.
#[derive(Debug, thiserror::Error)]
pub enum LogonError {
    /// Invalid NID group.
    #[error("invalid NID group: {0}")]
    InvalidNid(String),

    /// State machine error.
    #[error("logon state machine error: {0}")]
    StateError(String),
}
