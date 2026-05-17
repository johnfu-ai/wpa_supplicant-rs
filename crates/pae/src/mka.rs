//! MKA key agreement types per IEEE 802.1X-2020, Clause 9.

/// MKA key agreement entity (KaY) state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkaState {
    /// Initial state, no key agreement established.
    Initial,
    /// Key agreement in progress.
    Pending,
    /// Key agreement established.
    Established,
}
