//! EAP-TLS method.

/// EAP-TLS state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapTlsState {
    /// Initial state.
    Initial,
    /// TLS handshake in progress.
    Handshake,
    /// TLS tunnel established.
    Established,
}
