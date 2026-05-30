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
//!
//! # no_std support
//!
//! Per REQ-NF-PORT-002 (#61): core protocol logic compiles with `#![no_std]`
//! when the `std` feature is disabled. Crypto implementations (AES-CMAC KDF,
//! SystemRng) require the `std` feature.
//!
//! Implements: #61 (REQ-NF-PORT-002: no_std Capability)

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[cfg(not(feature = "std"))]
extern crate alloc;

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
/// Implements: #61 (REQ-NF-PORT-002: no_std error type without thiserror)
#[derive(Debug)]
pub enum PaeError {
    /// Invalid state transition attempted.
    InvalidTransition {
        /// Source state.
        from: PaeString,
        /// Target state.
        to: PaeString,
    },

    /// Key operation failed.
    KeyError(PaeString),

    /// Peer list is full (supplicant limit reached).
    PeerListFull {
        /// Which list is full ("live" or "potential").
        which: PaeString,
    },

    /// Operation requires Key Server role.
    NotKeyServer,

    /// ICV verification failed.
    IcvFailed,

    /// MKPDU parsing failed.
    InvalidMkpdu(PaeString),

    /// Crypto operation failed.
    CryptoError(PaeString),
}

#[cfg(feature = "std")]
use std::string::String as PaeString;

#[cfg(not(feature = "std"))]
use alloc::string::String as PaeString;

#[cfg(feature = "std")]
impl std::error::Error for PaeError {}

impl core::fmt::Display for PaeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid state transition: from {} to {}", from, to)
            }
            Self::KeyError(s) => write!(f, "key error: {}", s),
            Self::PeerListFull { which } => write!(f, "peer list full: {}", which),
            Self::NotKeyServer => write!(f, "not key server"),
            Self::IcvFailed => write!(f, "ICV verification failed"),
            Self::InvalidMkpdu(s) => write!(f, "invalid MKPDU: {}", s),
            Self::CryptoError(s) => write!(f, "crypto error: {}", s),
        }
    }
}

// Re-export key types for convenience
pub use cp::{CpEvent, CpState, CpStateMachine, CpTransition, SecureAssociation, SecureChannel};
pub use mka::{
    common_cipher_suite, elect_key_server, Cak, CipherSuite, Ckn, Ick, Kdf, Kek, KeyServerRole,
    MkaContext, MkaParticipant, MkaPeer, MkaPeerList, MkaPeerStatus, MkaState, Msk, PaeEvent, Rng,
    Sak, Sci,
};
#[cfg(feature = "std")]
pub use mka::{compute_icv, verify_icv, AesCmacKdf, CakEntry, CakStore, SystemRng};
pub use mkpdu::{
    BasicParameterSet, DistribSakParameterSet, Mkpdu, ParameterSet, PeerEntry, SakUseParameterSet,
    ICV_LEN, MKPDU_VERSION,
};
pub use port::PortState;
pub use timer::{
    TimerId, TimerWheel, MKA_BOUNDED_HELLO_TIME, MKA_HELLO_TIME, MKA_LIFE_TIME, SAK_RETIRE_TIME,
};
