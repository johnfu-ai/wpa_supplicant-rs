//! NID (Network Identity) group types per IEEE 802.1X-2020, Clause 12.5.

/// NID group identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NidGroup {
    /// NID name.
    pub name: String,
    /// NID identifier bytes.
    pub id: Vec<u8>,
}
