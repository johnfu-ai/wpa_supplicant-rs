//! EAP-PEAP method.

/// EAP-PEAP state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapPeapState {
    /// Initial state.
    Initial,
    /// Phase 1 (TLS tunnel) in progress.
    Phase1,
    /// Phase 2 (inner authentication).
    Phase2,
    /// Authentication complete.
    Complete,
}
