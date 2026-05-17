//! Logon Process state machine per IEEE 802.1X-2020, Clause 12.

/// Logon Process state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonState {
    /// Initial state.
    Initial,
    /// NID selection in progress.
    NidSelection,
    /// Waiting for authentication.
    Waiting,
    /// Authenticated.
    Authenticated,
}
