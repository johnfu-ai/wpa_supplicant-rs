//! Supplicant PAE state machine per IEEE 802.1X-2020, Clause 8.

/// Supplicant PAE state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaeState {
    /// No connection.
    Disconnected,
    /// Initiating authentication.
    Connecting,
    /// Authentication in progress.
    Authenticating,
    /// Authentication held off.
    Held,
    /// Authenticated.
    Authenticated,
    /// Force authentication.
    ForceAuth,
    /// Force unauthenticated.
    ForceUnauth,
}
