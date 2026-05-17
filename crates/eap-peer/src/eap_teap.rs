//! EAP-TEAP method per RFC 7170.

/// EAP-TEAP state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapTeapState {
    /// Initial state.
    Initial,
    /// TLS tunnel establishment.
    TunnelEstablish,
    /// Inner authentication.
    InnerAuth,
    /// Result indication.
    Result,
    /// Authentication complete.
    Complete,
}
