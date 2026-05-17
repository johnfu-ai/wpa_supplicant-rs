//! PAE — Port Access Entity core types and state machines.
//!
//! Implements IEEE 802.1X-2020 Clauses 9-10 (MKA and CP) from the
//! supplicant perspective.
//!
//! This crate provides the core types shared across the workspace:
//! - MKA (MACsec Key Agreement) state machine types
//! - CP (Controlled Port) state machine types
//! - PAE port state definitions

#![warn(missing_docs)]

/// MKA key agreement types per IEEE 802.1X-2020, Clause 9.
pub mod mka;

/// Controlled Port state machine types per IEEE 802.1X-2020, Clause 10.
pub mod cp;

/// PAE port state definitions.
pub mod port;

/// Core error type for PAE operations.
#[derive(Debug, thiserror::Error)]
pub enum PaeError {
    /// Invalid state transition attempted.
    #[error("invalid state transition: from {from} to {to}")]
    InvalidTransition {
        /// Source state.
        from: String,
        /// Target state.
        to: String,
    },

    /// Key operation failed.
    #[error("key error: {0}")]
    KeyError(String),
}
