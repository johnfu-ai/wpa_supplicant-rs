//! EAPOL Supplicant — Supplicant EAPOL state machine.
//!
//! Implements IEEE 802.1X-2020 Clause 8 — Supplicant PAE state machine.
//!
//! This crate provides the Supplicant PAE state machine that handles
//! EAPOL frame processing, state transitions, and authentication flow
//! from the supplicant perspective.

#![warn(missing_docs)]

/// Supplicant PAE state machine per IEEE 802.1X-2020, Clause 8.
pub mod supplicant_pae;

/// EAPOL frame types and parsing.
pub mod frame;

/// Error type for EAPOL supplicant operations.
#[derive(Debug, thiserror::Error)]
pub enum EapolError {
    /// EAPOL frame parsing error.
    #[error("invalid EAPOL frame: {0}")]
    InvalidFrame(String),

    /// Send operation failed.
    #[error("EAPOL send failed: {0}")]
    SendFailed(String),

    /// Timeout waiting for response.
    #[error("timeout: {0}")]
    Timeout(String),
}
