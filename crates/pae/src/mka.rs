//! MKA key agreement types per IEEE 802.1X-2020, Clause 9.
//!
//! Implements: #19 (REQ-F-MKA-001: MKA Key Hierarchy), #27 (REQ-F-MKA-009: CAK Identification)
//! Architecture: #74 (ADR-SM-002), #76 (ADR-SEC-004), #80 (ADR-KDF-008)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use cmac::{Cmac, Mac};
use digest::KeyInit;
use zeroize::ZeroizeOnDrop;

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

/// Connectivity Association Key — the root key for MKA key hierarchy.
///
/// Per IEEE 802.1X-2020, Clause 9.3.
/// Zeroized on drop; no Clone to prevent key duplication.
#[derive(ZeroizeOnDrop)]
pub struct Cak {
    /// Raw key bytes (fixed-size array, up to 32 bytes for AES-256).
    key: [u8; Self::MAX_LEN],
    /// Active key length in bytes.
    len: usize,
}

impl Cak {
    /// Maximum CAK length (AES-256).
    const MAX_LEN: usize = 32;

    /// Valid CAK lengths: 16 bytes (AES-128) or 32 bytes (AES-256).
    const VALID_LENGTHS: [usize; 2] = [16, 32];

    /// Create a CAK from raw bytes. Per Cl.9.3.
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if `key` is not 16 or 32 bytes.
    pub fn from_bytes(key: &[u8]) -> Result<Self, crate::PaeError> {
        if !Self::VALID_LENGTHS.contains(&key.len()) {
            return Err(crate::PaeError::KeyError(format!(
                "CAK must be 16 or 32 bytes, got {}",
                key.len()
            )));
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: buf,
            len: key.len(),
        })
    }

    /// CAK length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the CAK is empty (should not occur after construction).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Key bytes as a slice (for KDF operations only).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.key[..self.len]
    }
}

impl std::fmt::Debug for Cak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cak([REDACTED])")
    }
}

/// CAK Name — identifies a Connectivity Association.
///
/// Per IEEE 802.1X-2020, Clause 9.3.
/// Clonable for peer list lookup; zeroized on drop.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Ckn {
    /// CKN bytes (variable length).
    value: Vec<u8>,
}

impl Ckn {
    /// Maximum CKN length per IEEE 802.1X-2020, Clause 9.3.1.
    const MAX_LEN: usize = 32;

    /// Create a CKN from raw bytes. Per Cl.9.3.1.
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if `value` is empty or exceeds 32 bytes.
    pub fn from_bytes(value: Vec<u8>) -> Result<Self, crate::PaeError> {
        if value.is_empty() {
            return Err(crate::PaeError::KeyError("CKN must not be empty".into()));
        }
        if value.len() > Self::MAX_LEN {
            return Err(crate::PaeError::KeyError(format!(
                "CKN must be at most {} bytes, got {}",
                Self::MAX_LEN,
                value.len()
            )));
        }
        Ok(Self { value })
    }

    /// CKN bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// CKN length in bytes.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the CKN is empty (should not occur after construction).
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl std::fmt::Debug for Ckn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ckn([REDACTED])")
    }
}

/// Integrity Check Key — derived from CAK for MKPDU integrity.
///
/// Per IEEE 802.1X-2020, Clause 9.6.
/// Zeroized on drop; no Clone.
#[derive(ZeroizeOnDrop)]
pub struct Ick {
    key: [u8; Self::MAX_LEN],
    len: usize,
}

impl Ick {
    /// Maximum ICK length (AES-256).
    const MAX_LEN: usize = 32;

    /// Create an ICK from raw bytes. Per Cl.9.6.
    pub(crate) fn from_bytes(key: &[u8]) -> Result<Self, crate::PaeError> {
        if key.is_empty() || key.len() > Self::MAX_LEN {
            return Err(crate::PaeError::KeyError(format!(
                "ICK length must be 1..={}, got {}",
                Self::MAX_LEN,
                key.len()
            )));
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: buf,
            len: key.len(),
        })
    }

    /// ICK length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the ICK is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Key bytes as a slice (for ICV operations).
    /// Used by REQ-F-MKA-002 (MKPDU transport) for ICV computation.
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.key[..self.len]
    }
}

impl std::fmt::Debug for Ick {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ick([REDACTED])")
    }
}

/// Key Encryption Key — derived from CAK for SAK wrapping.
///
/// Per IEEE 802.1X-2020, Clause 9.6.
/// Zeroized on drop; no Clone.
#[derive(ZeroizeOnDrop)]
pub struct Kek {
    key: [u8; Self::MAX_LEN],
    len: usize,
}

impl Kek {
    /// Maximum KEK length (AES-256).
    const MAX_LEN: usize = 32;

    /// Create a KEK from raw bytes. Per Cl.9.6.
    pub(crate) fn from_bytes(key: &[u8]) -> Result<Self, crate::PaeError> {
        if key.is_empty() || key.len() > Self::MAX_LEN {
            return Err(crate::PaeError::KeyError(format!(
                "KEK length must be 1..={}, got {}",
                Self::MAX_LEN,
                key.len()
            )));
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: buf,
            len: key.len(),
        })
    }

    /// KEK length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the KEK is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Key bytes as a slice (for key wrap operations).
    /// Used by REQ-F-MKA-007 (SAK wrap/unwrap) for key encryption.
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.key[..self.len]
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek([REDACTED])")
    }
}

/// Secure Association Key — ephemeral per-session key.
///
/// Per IEEE 802.1X-2020, Clause 9.8.
/// Zeroized on drop; no Clone.
#[derive(ZeroizeOnDrop)]
pub struct Sak {
    /// SAK key bytes.
    key: [u8; Self::MAX_LEN],
    /// Active key length.
    len: usize,
    /// Association Number (AN) for this SAK.
    an: u8,
}

impl Sak {
    /// Maximum SAK length (AES-256).
    const MAX_LEN: usize = 32;

    /// Valid SAK lengths: 16 bytes (AES-128) or 32 bytes (AES-256).
    const VALID_LENGTHS: [usize; 2] = [16, 32];

    /// Create a SAK from raw bytes with an AN. Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if `key` is not 16 or 32 bytes, or AN > 3.
    pub fn from_bytes(key: &[u8], an: u8) -> Result<Self, crate::PaeError> {
        if !Self::VALID_LENGTHS.contains(&key.len()) {
            return Err(crate::PaeError::KeyError(format!(
                "SAK must be 16 or 32 bytes, got {}",
                key.len()
            )));
        }
        if an > 3 {
            return Err(crate::PaeError::KeyError(format!(
                "AN must be 0-3, got {}",
                an
            )));
        }
        let mut buf = [0u8; Self::MAX_LEN];
        buf[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: buf,
            len: key.len(),
            an,
        })
    }

    /// Association Number (0-3). Per Cl.9.8.
    pub fn an(&self) -> u8 {
        self.an
    }

    /// SAK length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the SAK is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Key bytes as a slice (internal use only).
    /// Used by REQ-F-MKA-007 (SAK wrap/unwrap) for key encryption.
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.key[..self.len]
    }
}

impl std::fmt::Debug for Sak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sak").field("an", &self.an).finish()
    }
}

/// Secure Channel Identifier.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sci {
    /// System MAC address (6 bytes).
    mac: [u8; 6],
    /// Port number.
    port: u16,
}

impl Sci {
    /// Create an SCI from MAC and port number.
    pub fn new(mac: [u8; 6], port: u16) -> Self {
        Self { mac, port }
    }

    /// MAC address bytes.
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Port number.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Key Derivation Function trait.
///
/// Per ADR-KDF-008 (#80) and IEEE 802.1X-2020, Clause 9.6.
/// Abstracts KDF operations for testability.
pub trait Kdf: Send + Sync {
    /// Derive ICK from CAK and CKN. Per Cl.9.6.
    fn derive_ick(&self, cak: &Cak, ckn: &Ckn) -> Result<Ick, crate::PaeError>;

    /// Derive KEK from CAK and CKN. Per Cl.9.6.
    fn derive_kek(&self, cak: &Cak, ckn: &Ckn) -> Result<Kek, crate::PaeError>;
}

/// AES-CMAC KDF implementation per IEEE 802.1X-2020, Clause 6.2.1.
///
/// Uses AES-CMAC (RFC 4493) as the KDF primitive.
/// KDF(label, context, key) = AES-CMAC(key, label || context)[0..length]
pub struct AesCmacKdf;

/// KDF label for ICK derivation. Per Cl.9.6.
const KDF_LABEL_ICK: &[u8] = b"IEEE8021 ICK";
/// KDF label for KEK derivation. Per Cl.9.6.
const KDF_LABEL_KEK: &[u8] = b"IEEE8021 KEK";

impl AesCmacKdf {
    /// Derive key material using AES-CMAC KDF.
    ///
    /// Per IEEE 802.1X-2020, Clause 6.2.1:
    /// result = AES-CMAC(CAK, label || CKN_first_16)
    fn kdf_cmac(
        cak: &Cak,
        label: &[u8],
        ckn: &Ckn,
        out_len: usize,
    ) -> Result<Vec<u8>, crate::PaeError> {
        // Build the CMAC input: label || CKN[0..15] (first 16 bytes of CKN)
        let ckn_prefix_len = 16.min(ckn.as_bytes().len());
        let mut input = Vec::with_capacity(label.len() + ckn_prefix_len);
        input.extend_from_slice(label);
        input.extend_from_slice(&ckn.as_bytes()[..ckn_prefix_len]);

        // AES-CMAC with the CAK as the key
        let mut cmac =
            <Cmac<aes::Aes128> as KeyInit>::new_from_slice(cak.as_bytes()).map_err(|e| {
                crate::PaeError::CryptoError(format!("AES-CMAC key init failed: {}", e))
            })?;
        cmac.update(&input);
        let mac = cmac.finalize().into_bytes();

        let result = &mac[..out_len.min(mac.len())];
        Ok(result.to_vec())
    }
}

impl Kdf for AesCmacKdf {
    fn derive_ick(&self, cak: &Cak, ckn: &Ckn) -> Result<Ick, crate::PaeError> {
        let ick_len = cak.len(); // ICK length matches CAK length
        let derived = Self::kdf_cmac(cak, KDF_LABEL_ICK, ckn, ick_len)?;
        Ick::from_bytes(&derived)
    }

    fn derive_kek(&self, cak: &Cak, ckn: &Ckn) -> Result<Kek, crate::PaeError> {
        let kek_len = cak.len(); // KEK length matches CAK length
        let derived = Self::kdf_cmac(cak, KDF_LABEL_KEK, ckn, kek_len)?;
        Kek::from_bytes(&derived)
    }
}

/// MACsec cipher suite identifiers.
///
/// Per IEEE 802.1X-2020, Clause 9.7.
/// Implements: #23 (REQ-F-MKA-005: Cipher Suite Selection)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// GCM-AES-128 (default). Per Cl.9.7.
    GcmAes128,
    /// GCM-AES-256. Per Cl.9.7.
    GcmAes256,
    /// GCM-AES-XPN-256 (extended packet number). Per Cl.9.7.
    GcmAesXpn256,
    /// Null cipher suite (no encryption, authentication only). Per Cl.9.7.
    Null,
}

impl CipherSuite {
    /// Key length in bytes for this cipher suite.
    pub fn key_len(&self) -> usize {
        match self {
            Self::GcmAes128 => 16,
            Self::GcmAes256 => 32,
            Self::GcmAesXpn256 => 32,
            Self::Null => 0,
        }
    }

    /// Whether this cipher suite uses XPN (extended packet number).
    pub fn is_xpn(&self) -> bool {
        matches!(self, Self::GcmAesXpn256)
    }

    /// Priority value for cipher suite selection. Higher is preferred.
    ///
    /// Per Cl.9.7: GCM-AES-256 > GCM-AES-128 > GCM-AES-XPN-256 > Null.
    pub fn priority(&self) -> u8 {
        match self {
            Self::GcmAes256 => 4,
            Self::GcmAes128 => 3,
            Self::GcmAesXpn256 => 2,
            Self::Null => 1,
        }
    }
}

/// Select the highest-priority cipher suite common to all participants.
///
/// Per IEEE 802.1X-2020, Clause 9.7.
/// Implements: #23 (REQ-F-MKA-005: Cipher Suite Selection)
///
/// Returns `None` if no cipher suite is common to both lists.
pub fn common_cipher_suite(
    actor_suites: &[CipherSuite],
    peer_suites: &[CipherSuite],
) -> Option<CipherSuite> {
    let mut best: Option<CipherSuite> = None;
    for suite in actor_suites {
        if peer_suites.contains(suite) && best.map_or(true, |b| suite.priority() > b.priority()) {
            best = Some(*suite);
        }
    }
    best
}

/// Random Number Generator trait.
///
/// Per ADR-KDF-008 (#80) and IEEE 802.1X-2020, Clause 9.2.1.
/// Implements: #28 (REQ-F-MKA-010: Random Number Generation)
/// Abstracts RNG for testability.
pub trait Rng: Send + Sync {
    /// Fill buffer with cryptographically secure random bytes.
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), crate::PaeError>;

    /// Generate a random MI (Member Identifier, 12 bytes). Per Cl.9.4.
    fn random_mi(&self) -> Result<[u8; 12], crate::PaeError>;
}

/// System RNG using the OS cryptographic random source.
///
/// Per IEEE 802.1X-2020, Clause 9.2.1.
/// Uses `getrandom` crate which prefers hardware RNG when available.
pub struct SystemRng;

impl Rng for SystemRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), crate::PaeError> {
        getrandom::getrandom(buf)
            .map_err(|e| crate::PaeError::CryptoError(format!("RNG failed: {}", e)))
    }

    fn random_mi(&self) -> Result<[u8; 12], crate::PaeError> {
        let mut mi = [0u8; 12];
        self.fill_bytes(&mut mi)?;
        Ok(mi)
    }
}

/// A CAK identified by its CKN — the unit of key selection.
///
/// Per IEEE 802.1X-2020, Clause 9.3.1: each CAK is identified by its CKN.
/// When an MKPDU arrives with a given CKN, the correct CAK-derived keys
/// (ICK, KEK) are selected by matching against the CKN.
///
/// Implements: #27 (REQ-F-MKA-009: CAK Identification)
pub struct CakEntry {
    /// The CAK (root key).
    cak: Cak,
    /// The CKN identifying this CAK.
    ckn: Ckn,
    /// Derived ICK for this CAK/CKN pair.
    ick: Ick,
    /// Derived KEK for this CAK/CKN pair.
    kek: Kek,
}

impl CakEntry {
    /// Create a new CakEntry by deriving ICK and KEK from CAK and CKN.
    ///
    /// Per IEEE 802.1X-2020, Clause 9.3.1 and 9.6.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` if key derivation fails.
    pub fn new(cak: Cak, ckn: Ckn, kdf: &dyn Kdf) -> Result<Self, crate::PaeError> {
        let ick = kdf.derive_ick(&cak, &ckn)?;
        let kek = kdf.derive_kek(&cak, &ckn)?;
        Ok(Self { cak, ckn, ick, kek })
    }

    /// The CKN identifying this CAK.
    pub fn ckn(&self) -> &Ckn {
        &self.ckn
    }

    /// The CAK (root key).
    pub fn cak(&self) -> &Cak {
        &self.cak
    }

    /// The ICK derived from this CAK/CKN pair. Per Cl.9.6.
    pub fn ick(&self) -> &Ick {
        &self.ick
    }

    /// The KEK derived from this CAK/CKN pair. Per Cl.9.6.
    pub fn kek(&self) -> &Kek {
        &self.kek
    }
}

impl std::fmt::Debug for CakEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CakEntry")
            .field("ckn", &self.ckn)
            .field("cak", &self.cak)
            .finish()
    }
}

/// CAK store — CKN-based key selection for MKA participants.
///
/// Per IEEE 802.1X-2020, Clause 9.3.1: when MKPDUs for different CKNs
/// are processed, the correct CAK-derived keys must be used for ICV
/// verification and SAK unwrapping.
///
/// Implements: #27 (REQ-F-MKA-009: CAK Identification)
pub struct CakStore {
    entries: Vec<CakEntry>,
}

impl CakStore {
    /// Create an empty CAK store.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a CakEntry. Replaces any existing entry with the same CKN.
    pub fn insert(&mut self, entry: CakEntry) {
        if let Some(existing) = self.find_by_ckn_mut(entry.ckn()) {
            // Replace existing entry — CKN is the unique key
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Find a CakEntry by CKN. Per Cl.9.3.1.
    pub fn find_by_ckn(&self, ckn: &Ckn) -> Option<&CakEntry> {
        self.entries.iter().find(|e| e.ckn() == ckn)
    }

    /// Find a CakEntry by CKN (mutable). Per Cl.9.3.1.
    fn find_by_ckn_mut(&mut self, ckn: &Ckn) -> Option<&mut CakEntry> {
        self.entries.iter_mut().find(|e| e.ckn() == ckn)
    }

    /// Number of entries in the store.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for CakStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- REQ-F-MKA-001: MKA Key Hierarchy ---

    /// Verifies: #19 (REQ-F-MKA-001)
    /// Per IEEE 802.1X-2020, Clause 9.3.
    /// CAK can be constructed from 16 bytes (AES-128).
    #[test]
    fn test_cak_from_16_bytes() {
        let key_bytes = [0xAAu8; 16];
        let cak = Cak::from_bytes(&key_bytes).expect("CAK from 16 bytes should succeed");
        assert_eq!(cak.len(), 16);
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// Per IEEE 802.1X-2020, Clause 9.3.
    /// CAK can be constructed from 32 bytes (AES-256).
    #[test]
    fn test_cak_from_32_bytes() {
        let key_bytes = [0xBBu8; 32];
        let cak = Cak::from_bytes(&key_bytes).expect("CAK from 32 bytes should succeed");
        assert_eq!(cak.len(), 32);
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// CAK construction fails for empty bytes.
    #[test]
    fn test_cak_rejects_empty() {
        let result = Cak::from_bytes(&[]);
        assert!(result.is_err());
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// CAK construction fails for invalid length (not 16 or 32).
    #[test]
    fn test_cak_rejects_invalid_length() {
        let result = Cak::from_bytes(&[0xCC; 24]);
        assert!(result.is_err());
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// CAK debug output shows [REDACTED], never exposes key bytes.
    #[test]
    fn test_cak_debug_redacted() {
        let cak = Cak::from_bytes(&[0xDD; 16]).unwrap();
        let debug_str = format!("{:?}", cak);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("DD"));
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// Per IEEE 802.1X-2020, Clause 9.3.
    /// CKN can be constructed from bytes.
    #[test]
    fn test_ckn_from_bytes() {
        let ckn_bytes: Vec<u8> = vec![0x11; 16];
        let ckn = Ckn::from_bytes(ckn_bytes.clone()).expect("CKN from bytes should succeed");
        assert_eq!(ckn.as_bytes(), ckn_bytes);
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// Per IEEE 802.1X-2020, Clause 9.3.
    /// KDF derives ICK from CAK and CKN: ICK = KDF(CAK, "IEEE8021 ICK", CKN[0..15], ICKLength).
    #[test]
    fn test_kdf_derive_ick() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();

        let kdf = AesCmacKdf;
        let ick = kdf
            .derive_ick(&cak, &ckn)
            .expect("ICK derivation should succeed");
        assert_eq!(ick.len(), 16);
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// Per IEEE 802.1X-2020, Clause 9.3.
    /// KDF derives KEK from CAK and CKN: KEK = KDF(CAK, "IEEE8021 KEK", CKN[0..15], KEKLength).
    #[test]
    fn test_kdf_derive_kek() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();

        let kdf = AesCmacKdf;
        let kek = kdf
            .derive_kek(&cak, &ckn)
            .expect("KEK derivation should succeed");
        assert_eq!(kek.len(), 16);
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// Per IEEE 802.1X-2020, Clause 9.3.
    /// Given a different CAK, derived ICK and KEK are different (key isolation).
    #[test]
    fn test_kdf_key_isolation() {
        let cak1 = Cak::from_bytes(&[0x01; 16]).unwrap();
        let cak2 = Cak::from_bytes(&[0x03; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();

        let kdf = AesCmacKdf;

        let ick1 = kdf.derive_ick(&cak1, &ckn).unwrap();
        let ick2 = kdf.derive_ick(&cak2, &ckn).unwrap();
        assert_ne!(
            ick1.as_bytes(),
            ick2.as_bytes(),
            "Different CAKs must produce different ICKs"
        );

        let kek1 = kdf.derive_kek(&cak1, &ckn).unwrap();
        let kek2 = kdf.derive_kek(&cak2, &ckn).unwrap();
        assert_ne!(
            kek1.as_bytes(),
            kek2.as_bytes(),
            "Different CAKs must produce different KEKs"
        );
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// ICK and KEK derived from same CAK/CKN are different from each other.
    #[test]
    fn test_kdf_ick_kek_different() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();

        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();
        let kek = kdf.derive_kek(&cak, &ckn).unwrap();
        assert_ne!(ick.as_bytes(), kek.as_bytes(), "ICK and KEK must differ");
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// ICK debug output shows [REDACTED].
    #[test]
    fn test_ick_debug_redacted() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();
        let debug_str = format!("{:?}", ick);
        assert!(debug_str.contains("REDACTED"));
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// KEK debug output shows [REDACTED].
    #[test]
    fn test_kek_debug_redacted() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let kek = kdf.derive_kek(&cak, &ckn).unwrap();
        let debug_str = format!("{:?}", kek);
        assert!(debug_str.contains("REDACTED"));
    }

    /// Verifies: #19 (REQ-F-MKA-001)
    /// KDF is deterministic: same inputs produce same outputs.
    #[test]
    fn test_kdf_deterministic() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();

        let kdf = AesCmacKdf;
        let ick_a = kdf.derive_ick(&cak, &ckn).unwrap();
        let ick_b = kdf.derive_ick(&cak, &ckn).unwrap();
        assert_eq!(
            ick_a.as_bytes(),
            ick_b.as_bytes(),
            "KDF must be deterministic"
        );
    }

    // --- REQ-F-MKA-005: Cipher Suite Selection ---

    /// Verifies: #23 (REQ-F-MKA-005)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// GCM-AES-128 has 16-byte key length.
    #[test]
    fn test_cipher_suite_gcm_aes_128_key_len() {
        assert_eq!(CipherSuite::GcmAes128.key_len(), 16);
    }

    /// Verifies: #23 (REQ-F-MKA-005)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// GCM-AES-256 has 32-byte key length.
    #[test]
    fn test_cipher_suite_gcm_aes_256_key_len() {
        assert_eq!(CipherSuite::GcmAes256.key_len(), 32);
    }

    /// Verifies: #23 (REQ-F-MKA-005)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// GCM-AES-XPN-256 has 32-byte key length and uses XPN.
    #[test]
    fn test_cipher_suite_xpn_256() {
        assert_eq!(CipherSuite::GcmAesXpn256.key_len(), 32);
        assert!(CipherSuite::GcmAesXpn256.is_xpn());
    }

    /// Verifies: #23 (REQ-F-MKA-005)
    /// Non-XPN cipher suites report is_xpn() as false.
    #[test]
    fn test_cipher_suite_not_xpn() {
        assert!(!CipherSuite::GcmAes128.is_xpn());
        assert!(!CipherSuite::GcmAes256.is_xpn());
        assert!(!CipherSuite::Null.is_xpn());
    }

    /// Verifies: #23 (REQ-F-MKA-005)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// Priority order: GcmAes256 > GcmAes128 > GcmAesXpn256 > Null.
    #[test]
    fn test_cipher_suite_priority() {
        assert!(CipherSuite::GcmAes256.priority() > CipherSuite::GcmAes128.priority());
        assert!(CipherSuite::GcmAes128.priority() > CipherSuite::GcmAesXpn256.priority());
        assert!(CipherSuite::GcmAesXpn256.priority() > CipherSuite::Null.priority());
    }

    /// Verifies: #23 (REQ-F-MKA-005)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// Key Server selects highest-priority cipher suite common to all live peers.
    #[test]
    fn test_common_cipher_suite_selects_highest() {
        // Actor supports 128 and 256; peer supports 128 and XPN-256
        // Common: 128 only → GcmAes128 selected
        let actor = vec![CipherSuite::GcmAes256, CipherSuite::GcmAes128];
        let peer = vec![CipherSuite::GcmAes128, CipherSuite::GcmAesXpn256];
        let selected = common_cipher_suite(&actor, &peer);
        assert_eq!(selected, Some(CipherSuite::GcmAes128));
    }

    /// Verifies: #23 (REQ-F-MKA-005)
    /// When only Null is common, Null is selected.
    #[test]
    fn test_common_cipher_suite_null_only() {
        let actor = vec![CipherSuite::Null];
        let peer = vec![CipherSuite::Null];
        let selected = common_cipher_suite(&actor, &peer);
        assert_eq!(selected, Some(CipherSuite::Null));
    }

    /// Verifies: #23 (REQ-F-MKA-005)
    /// When no cipher suites are common, returns None.
    #[test]
    fn test_common_cipher_suite_no_common() {
        let actor = vec![CipherSuite::GcmAes256];
        let peer = vec![CipherSuite::GcmAes128];
        let selected = common_cipher_suite(&actor, &peer);
        assert_eq!(selected, None);
    }

    // --- REQ-F-MKA-010: Random Number Generation ---

    /// Verifies: #28 (REQ-F-MKA-010)
    /// Per IEEE 802.1X-2020, Clause 9.2.1.
    /// Rng trait fills buffer with non-zero bytes (statistical check).
    #[test]
    fn test_rng_fill_bytes() {
        let rng = SystemRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf).expect("fill_bytes should succeed");
        // Extremely unlikely all 32 bytes are zero
        assert_ne!(buf, [0u8; 32], "RNG output must not be all zeros");
    }

    /// Verifies: #28 (REQ-F-MKA-010)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// random_mi returns 12 bytes that are not all zero.
    #[test]
    fn test_rng_random_mi() {
        let rng = SystemRng;
        let mi = rng.random_mi().expect("random_mi should succeed");
        assert_eq!(mi.len(), 12, "MI must be 12 bytes");
        assert_ne!(mi, [0u8; 12], "MI must not be all zeros");
    }

    /// Verifies: #28 (REQ-F-MKA-010)
    /// Two consecutive RNG calls produce different values.
    #[test]
    fn test_rng_different_values() {
        let rng = SystemRng;
        let mi1 = rng.random_mi().unwrap();
        let mi2 = rng.random_mi().unwrap();
        assert_ne!(mi1, mi2, "Consecutive RNG calls must differ");
    }

    // --- REQ-F-MKA-009: CAK Identification ---

    /// Verifies: #27 (REQ-F-MKA-009)
    /// Per IEEE 802.1X-2020, Clause 9.3.1.
    /// CKN accepts 1 byte (minimum valid length).
    #[test]
    fn test_ckn_min_length() {
        let ckn = Ckn::from_bytes(vec![0x01]);
        assert!(ckn.is_ok());
        assert_eq!(ckn.unwrap().len(), 1);
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// Per IEEE 802.1X-2020, Clause 9.3.1.
    /// CKN accepts 32 bytes (maximum valid length).
    #[test]
    fn test_ckn_max_length() {
        let ckn = Ckn::from_bytes(vec![0xAA; 32]);
        assert!(ckn.is_ok());
        assert_eq!(ckn.unwrap().len(), 32);
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// Per IEEE 802.1X-2020, Clause 9.3.1.
    /// CKN rejects values exceeding 32 bytes.
    #[test]
    fn test_ckn_rejects_over_max() {
        let result = Ckn::from_bytes(vec![0x00; 33]);
        assert!(result.is_err());
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// CKN len() and is_empty() work correctly.
    #[test]
    fn test_ckn_len_and_is_empty() {
        let ckn = Ckn::from_bytes(vec![0x01; 16]).unwrap();
        assert_eq!(ckn.len(), 16);
        assert!(!ckn.is_empty());
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// Per IEEE 802.1X-2020, Clause 9.3.1.
    /// CakEntry pairs a CAK with its CKN and derives ICK/KEK.
    #[test]
    fn test_cak_entry_derives_keys() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let entry =
            CakEntry::new(cak, ckn.clone(), &kdf).expect("CakEntry creation should succeed");
        assert_eq!(entry.ckn().as_bytes(), ckn.as_bytes());
        assert_eq!(entry.ick().len(), 16);
        assert_eq!(entry.kek().len(), 16);
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// CakEntry debug output redacts key material.
    #[test]
    fn test_cak_entry_debug_redacted() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let entry = CakEntry::new(cak, ckn, &kdf).unwrap();
        let debug = format!("{:?}", entry);
        assert!(debug.contains("REDACTED"));
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// Per IEEE 802.1X-2020, Clause 9.3.1.
    /// CakStore finds entries by CKN for key selection.
    #[test]
    fn test_cak_store_find_by_ckn() {
        let cak1 = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn1 = Ckn::from_bytes(vec![0x10; 16]).unwrap();
        let cak2 = Cak::from_bytes(&[0x02; 16]).unwrap();
        let ckn2 = Ckn::from_bytes(vec![0x20; 16]).unwrap();
        let kdf = AesCmacKdf;

        let entry1 = CakEntry::new(cak1, ckn1.clone(), &kdf).unwrap();
        let entry2 = CakEntry::new(cak2, ckn2.clone(), &kdf).unwrap();

        let mut store = CakStore::new();
        store.insert(entry1);
        store.insert(entry2);

        // Find by CKN1 returns entry1's ICK
        let found = store.find_by_ckn(&ckn1).expect("CKN1 should be found");
        assert_eq!(found.ckn().as_bytes(), ckn1.as_bytes());

        // Find by CKN2 returns entry2's ICK (different from entry1)
        let found2 = store.find_by_ckn(&ckn2).expect("CKN2 should be found");
        assert_eq!(found2.ckn().as_bytes(), ckn2.as_bytes());
        assert_ne!(found.ick().as_bytes(), found2.ick().as_bytes());
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// Per IEEE 802.1X-2020, Clause 9.3.1.
    /// Given MKPDUs for different CKNs, the correct CAK-derived keys
    /// are used (the core acceptance criterion).
    #[test]
    fn test_cak_store_selects_correct_keys_by_ckn() {
        let cak_a = Cak::from_bytes(&[0xAA; 16]).unwrap();
        let ckn_a = Ckn::from_bytes(vec![0x0A; 16]).unwrap();
        let cak_b = Cak::from_bytes(&[0xBB; 16]).unwrap();
        let ckn_b = Ckn::from_bytes(vec![0x0B; 16]).unwrap();
        let kdf = AesCmacKdf;

        // Derive keys independently for comparison
        let ick_a_direct = kdf.derive_ick(&cak_a, &ckn_a).unwrap();
        let ick_b_direct = kdf.derive_ick(&cak_b, &ckn_b).unwrap();

        let entry_a = CakEntry::new(cak_a, ckn_a.clone(), &kdf).unwrap();
        let entry_b = CakEntry::new(cak_b, ckn_b.clone(), &kdf).unwrap();

        let mut store = CakStore::new();
        store.insert(entry_a);
        store.insert(entry_b);

        // Look up by CKN_A: ICK must match CAK_A's derived ICK
        let found_a = store.find_by_ckn(&ckn_a).expect("CKN_A should be found");
        assert_eq!(found_a.ick().as_bytes(), ick_a_direct.as_bytes());

        // Look up by CKN_B: ICK must match CAK_B's derived ICK
        let found_b = store.find_by_ckn(&ckn_b).expect("CKN_B should be found");
        assert_eq!(found_b.ick().as_bytes(), ick_b_direct.as_bytes());

        // Cross-verification: different CKNs yield different ICKs
        assert_ne!(found_a.ick().as_bytes(), found_b.ick().as_bytes());
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// CakStore returns None for unknown CKN.
    #[test]
    fn test_cak_store_unknown_ckn() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x10; 16]).unwrap();
        let kdf = AesCmacKdf;
        let entry = CakEntry::new(cak, ckn, &kdf).unwrap();

        let mut store = CakStore::new();
        store.insert(entry);

        let unknown_ckn = Ckn::from_bytes(vec![0xFF; 16]).unwrap();
        assert!(store.find_by_ckn(&unknown_ckn).is_none());
    }

    /// Verifies: #27 (REQ-F-MKA-009)
    /// CakStore replaces entry when same CKN is inserted.
    #[test]
    fn test_cak_store_replace_same_ckn() {
        let cak1 = Cak::from_bytes(&[0x01; 16]).unwrap();
        let cak2 = Cak::from_bytes(&[0x02; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x10; 16]).unwrap();
        let kdf = AesCmacKdf;

        let entry1 = CakEntry::new(cak1, ckn.clone(), &kdf).unwrap();
        let ick1 = entry1.ick().as_bytes().to_vec();

        let mut store = CakStore::new();
        store.insert(entry1);
        assert_eq!(store.len(), 1);

        // Insert with same CKN but different CAK
        let entry2 = CakEntry::new(cak2, ckn.clone(), &kdf).unwrap();
        store.insert(entry2);
        assert_eq!(store.len(), 1); // Still 1 entry (replaced)

        let found = store.find_by_ckn(&ckn).unwrap();
        // ICK should be different (different CAK)
        assert_ne!(found.ick().as_bytes(), ick1.as_slice());
    }
}
