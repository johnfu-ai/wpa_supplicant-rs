//! PAE port state definitions.

/// Port administrative state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Port is disabled.
    Disabled,
    /// Port is enabled but not yet authenticated.
    Unauthorized,
    /// Port is authenticated.
    Authorized,
}
