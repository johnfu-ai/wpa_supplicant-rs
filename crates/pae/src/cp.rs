//! Controlled Port state machine types per IEEE 802.1X-2020, Clause 10.

/// Controlled Port state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpState {
    /// Port is unauthenticated (blocked).
    Unauthenticated,
    /// Port is authenticated (open).
    Authenticated,
    /// Port is secured (MACsec active).
    Secured,
}
