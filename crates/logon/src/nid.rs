//! NID (Network Identity) group types per IEEE 802.1X-2020, Clause 12.5.
//!
//! Implements: #34 (REQ-F-LOGON-002: NID Selection)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

/// NID group — identifies a target network.
///
/// Per IEEE 802.1X-2020, Clause 12.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NidGroup {
    /// NID name (human-readable).
    name: String,
    /// NID identifier bytes (from EAPOL-Announcement).
    id: Vec<u8>,
    /// Associated cipher suite for this NID group.
    cipher_suite: pae::CipherSuite,
    /// Whether PSK is available for this NID group.
    has_psk: bool,
}

impl NidGroup {
    /// Create a NID group. Per Cl.12.5.
    pub fn new(name: String, id: Vec<u8>, cipher_suite: pae::CipherSuite, has_psk: bool) -> Self {
        Self {
            name,
            id,
            cipher_suite,
            has_psk,
        }
    }

    /// NID name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// NID identifier bytes.
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// Cipher suite for this NID group.
    pub fn cipher_suite(&self) -> pae::CipherSuite {
        self.cipher_suite
    }

    /// Whether PSK is available for this NID group.
    pub fn has_psk(&self) -> bool {
        self.has_psk
    }

    /// Match this NID group against an advertised NID from EAPOL-Announcement.
    /// Per Cl.12.5.
    pub fn matches(&self, advertised_nid: &[u8]) -> bool {
        self.id == advertised_nid
    }
}
