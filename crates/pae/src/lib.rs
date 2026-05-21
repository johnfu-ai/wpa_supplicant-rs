//! PAE — Port Access Entity core types and state machines.
//!
//! Implements IEEE 802.1X-2020 Clauses 9-10 (MKA and CP) from the
//! supplicant perspective.
//!
//! This crate provides the core types shared across the workspace:
//! - MKA (MACsec Key Agreement) state machine types
//! - CP (Controlled Port) state machine types
//! - PAE port state definitions
//! - Protocol timer wheel
//!
//! Implements: #19 (REQ-F-MKA-001), #20 (REQ-F-MKA-002), #23 (REQ-F-MKA-005), #25 (REQ-F-MKA-007), #27 (REQ-F-MKA-009), #28 (REQ-F-MKA-010), #29 (REQ-F-CP-001), #30 (REQ-F-CP-002), #31 (REQ-F-CP-003), #32 (REQ-F-CP-004), #47 (REQ-F-EAPOL-004)
//! Architecture: #74 (ADR-SM-002), #76 (ADR-SEC-004), #80 (ADR-KDF-008)

#![warn(missing_docs)]

/// MKA key agreement types per IEEE 802.1X-2020, Clause 9.
pub mod mka;

/// MKPDU format per IEEE 802.1X-2020, Clause 11.11.
pub mod mkpdu;

/// Controlled Port state machine types per IEEE 802.1X-2020, Clause 10.
pub mod cp;

/// PAE port state definitions.
pub mod port;

/// Protocol timer wheel per ADR-TMR-003 (#75).
pub mod timer;

/// Core error type for PAE operations.
///
/// Per ADR-ERR-005 (#77).
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

    /// Peer list is full (supplicant limit reached).
    #[error("peer list full: {which}")]
    PeerListFull {
        /// Which list is full ("live" or "potential").
        which: String,
    },

    /// Operation requires Key Server role.
    #[error("not key server")]
    NotKeyServer,

    /// ICV verification failed.
    #[error("ICV verification failed")]
    IcvFailed,

    /// MKPDU parsing failed.
    #[error("invalid MKPDU: {0}")]
    InvalidMkpdu(String),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    CryptoError(String),
}

// Re-export key types for convenience
pub use cp::{CpEvent, CpState, CpStateMachine, CpTransition, SecureAssociation, SecureChannel};
pub use mka::{
    common_cipher_suite, compute_icv, elect_key_server, verify_icv, AesCmacKdf, Cak, CakEntry,
    CakStore, CipherSuite, Ckn, Ick, Kdf, Kek, KeyServerRole, MkaContext, MkaParticipant, MkaPeer,
    MkaPeerList, MkaPeerStatus, MkaState, PaeEvent, Rng, Sak, Sci, SystemRng,
};
pub use mkpdu::{
    BasicParameterSet, DistribSakParameterSet, Mkpdu, ParameterSet, PeerEntry, SakUseParameterSet,
    ICV_LEN, MKPDU_VERSION,
};
pub use port::PortState;
pub use timer::{
    TimerId, TimerWheel, MKA_BOUNDED_HELLO_TIME, MKA_HELLO_TIME, MKA_LIFE_TIME, SAK_RETIRE_TIME,
};
