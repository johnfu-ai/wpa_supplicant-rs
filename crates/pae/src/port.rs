//! Controlled Port authorization state per IEEE 802.1X-2020, Clause 6.4.
//!
//! The Controlled Port forwards user traffic only when its authorization
//! status is `Authorized`. The PAE (Port Access Entity) drives this status
//! based on the result of the Supplicant PAE state machine (Clause 8) and,
//! when MKA is configured, the CP state machine (Clause 10).
//!
//! IMPORTANT: This implementation is based on understanding of IEEE
//! 802.1X-2020. No copyrighted content from the standard is reproduced.

/// Controlled Port authorization status per IEEE 802.1X-2020, Clause 6.4.
///
/// Distinct from the port's enabled/disabled administrative status —
/// this enum models whether the Controlled Port is allowed to forward
/// user traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlledPortState {
    /// Port is administratively disabled.
    Disabled,
    /// Port is enabled but not yet authorized; user traffic blocked.
    Unauthorized,
    /// Port is authorized; user traffic permitted.
    Authorized,
}
