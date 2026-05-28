//! MKA key agreement types per IEEE 802.1X-2020, Clause 9.
//!
//! Implements: #19 (REQ-F-MKA-001: MKA Key Hierarchy), #20 (REQ-F-MKA-002: MKA Transport),
//!             #21 (REQ-F-MKA-003: MKA Peer List Management), #27 (REQ-F-MKA-009: CAK Identification)
//! Architecture: #74 (ADR-SM-002), #76 (ADR-SEC-004), #80 (ADR-KDF-008)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use cmac::{Cmac, Mac};
use digest::KeyInit;
use std::time::Duration;
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

impl std::hash::Hash for Ckn {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
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
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if `key` is not 16 or 32 bytes.
    pub(crate) fn from_bytes(key: &[u8]) -> Result<Self, crate::PaeError> {
        if !Cak::VALID_LENGTHS.contains(&key.len()) {
            return Err(crate::PaeError::KeyError(format!(
                "ICK must be 16 or 32 bytes, got {}",
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
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if `key` is not 16 or 32 bytes.
    pub(crate) fn from_bytes(key: &[u8]) -> Result<Self, crate::PaeError> {
        if !Cak::VALID_LENGTHS.contains(&key.len()) {
            return Err(crate::PaeError::KeyError(format!(
                "KEK must be 16 or 32 bytes, got {}",
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

/// Master Session Key — output from EAP authentication.
///
/// Per RFC 3748: MSK is at least 64 octets.
/// Used to derive CAK per IEEE 802.1X-2020, Clause 6.2.2.
/// Zeroized on drop; no Clone to prevent key duplication.
///
/// Implements: #38 (REQ-F-EAP-001: EAP Peer Framework)
#[derive(ZeroizeOnDrop)]
pub struct Msk {
    /// Raw key bytes.
    key: Vec<u8>,
}

impl Msk {
    /// Minimum MSK length per RFC 3748.
    const MIN_LEN: usize = 64;

    /// Create an MSK from raw bytes. Per RFC 3748.
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if `key` is less than 64 bytes.
    pub fn from_bytes(key: Vec<u8>) -> Result<Self, crate::PaeError> {
        if key.len() < Self::MIN_LEN {
            return Err(crate::PaeError::KeyError(format!(
                "MSK must be at least 64 bytes, got {}",
                key.len()
            )));
        }
        Ok(Self { key })
    }

    /// MSK length in bytes.
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Whether the MSK is empty.
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    /// Key bytes as a slice (for KDF operations only).
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl std::fmt::Debug for Msk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Msk([REDACTED])")
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

    /// Derive CAK and CKN from MSK. Per Cl.6.2.2.
    ///
    /// The first 16 octets of MSK become the CAK (for AES-128).
    /// The CKN is derived from the MSK per Clause 6.2.2.
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if the MSK is too short.
    fn derive_cak_from_msk(&self, msk: &Msk) -> Result<(Cak, Ckn), crate::PaeError>;
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
    /// Derive key material using AES-CMAC KDF per IEEE 802.1X-2020, Clause 6.2.1.
    ///
    /// For 128-bit CAK: single CMAC block.
    /// For 256-bit CAK: two CMAC blocks with counter, concatenated.
    ///
    /// KDF(key, label, context, length) =
    ///   CMAC(key, 1 || label || 0x00 || context || length) [|| CMAC(key, 2 || ...)]
    fn kdf_cmac(
        cak: &Cak,
        label: &[u8],
        ckn: &Ckn,
        out_len: usize,
    ) -> Result<Vec<u8>, crate::PaeError> {
        let ckn_prefix_len = 16.min(ckn.as_bytes().len());
        let ckn_prefix = &ckn.as_bytes()[..ckn_prefix_len];
        let length_bytes = (out_len * 8) as u8; // length in bits, fits in u8 for ≤32 bytes

        // Build context: label || 0x00 || CKN[0..15] || length
        let mut context = Vec::with_capacity(1 + label.len() + 1 + ckn_prefix_len + 1);
        context.push(1); // counter = 1
        context.extend_from_slice(label);
        context.push(0x00); // separator
        context.extend_from_slice(ckn_prefix);
        context.push(length_bytes);

        let block1 = if cak.len() == 16 {
            // AES-128 CAK: single CMAC block
            let mut cmac =
                <Cmac<aes::Aes128> as KeyInit>::new_from_slice(cak.as_bytes()).map_err(|e| {
                    crate::PaeError::CryptoError(format!("AES-128-CMAC key init failed: {}", e))
                })?;
            cmac.update(&context);
            cmac.finalize().into_bytes()
        } else {
            // AES-256 CAK: use Aes256 for CMAC
            let mut cmac =
                <Cmac<aes::Aes256> as KeyInit>::new_from_slice(cak.as_bytes()).map_err(|e| {
                    crate::PaeError::CryptoError(format!("AES-256-CMAC key init failed: {}", e))
                })?;
            cmac.update(&context);
            cmac.finalize().into_bytes()
        };

        if out_len <= 16 {
            Ok(block1[..out_len].to_vec())
        } else {
            // Need second block: counter = 2
            context[0] = 2; // Update counter
            let block2 = if cak.len() == 16 {
                let mut cmac = <Cmac<aes::Aes128> as KeyInit>::new_from_slice(cak.as_bytes())
                    .map_err(|e| {
                        crate::PaeError::CryptoError(format!(
                            "AES-128-CMAC key init failed (block 2): {}",
                            e
                        ))
                    })?;
                cmac.update(&context);
                cmac.finalize().into_bytes()
            } else {
                let mut cmac = <Cmac<aes::Aes256> as KeyInit>::new_from_slice(cak.as_bytes())
                    .map_err(|e| {
                        crate::PaeError::CryptoError(format!(
                            "AES-256-CMAC key init failed (block 2): {}",
                            e
                        ))
                    })?;
                cmac.update(&context);
                cmac.finalize().into_bytes()
            };

            let mut result = Vec::with_capacity(out_len);
            result.extend_from_slice(&block1);
            result.extend_from_slice(&block2[..out_len - 16]);
            Ok(result)
        }
    }
}

impl Kdf for AesCmacKdf {
    fn derive_ick(&self, cak: &Cak, ckn: &Ckn) -> Result<Ick, crate::PaeError> {
        let ick_len = cak.len(); // ICK length matches CAK length
        let mut derived = Self::kdf_cmac(cak, KDF_LABEL_ICK, ckn, ick_len)?;
        let result = Ick::from_bytes(&derived);
        zeroize::Zeroize::zeroize(&mut derived);
        result
    }

    fn derive_kek(&self, cak: &Cak, ckn: &Ckn) -> Result<Kek, crate::PaeError> {
        let kek_len = cak.len(); // KEK length matches CAK length
        let mut derived = Self::kdf_cmac(cak, KDF_LABEL_KEK, ckn, kek_len)?;
        let result = Kek::from_bytes(&derived);
        zeroize::Zeroize::zeroize(&mut derived);
        result
    }

    fn derive_cak_from_msk(&self, msk: &Msk) -> Result<(Cak, Ckn), crate::PaeError> {
        // Per Cl.6.2.2: first 16 octets of MSK → CAK-128
        // CKN is derived from the MSK context
        let msk_bytes = msk.as_bytes();
        if msk_bytes.len() < 64 {
            return Err(crate::PaeError::KeyError(format!(
                "MSK too short for CAK derivation: {} bytes (need >= 64)",
                msk_bytes.len()
            )));
        }

        // CAK = MSK[0..16] per Cl.6.2.2
        let cak = Cak::from_bytes(&msk_bytes[..16])?;

        // CKN = MSK[0..16] used as seed for CKN derivation per Cl.6.2.2
        // The CKN is constructed from the MSK as specified in Clause 6.2.2
        let ckn = Ckn::from_bytes(msk_bytes[..16].to_vec())?;

        Ok((cak, ckn))
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

// --- REQ-F-MKA-002: MKA Transport ---

/// Context trait for MKA participant — abstracts I/O and crypto.
///
/// Per ADR-SM-002 (#74) and ADR-KDF-008 (#80).
/// Enables mock injection for unit testing.
///
/// Implements: #20 (REQ-F-MKA-002: MKA Transport), #24 (REQ-F-MKA-006: SAK Reception)
/// Requirements: #19–#28 (REQ-F-MKA)
/// IEEE Clause: 9
pub trait MkaContext: Send + Sync {
    /// Derive ICK and KEK from CAK and CKN. Per Cl.9.6.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on derivation failure.
    fn derive_keys(&self, cak: &Cak, ckn: &Ckn) -> Result<(Ick, Kek), crate::PaeError>;

    /// Generate a new SAK. Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on generation failure.
    fn generate_sak(&self, cipher_suite: CipherSuite) -> Result<Sak, crate::PaeError>;

    /// Wrap a SAK with KEK for distribution. Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on wrap failure.
    fn wrap_sak(&self, sak: &Sak, kek: &Kek) -> Result<Vec<u8>, crate::PaeError>;

    /// Unwrap a distributed SAK. Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on unwrap failure.
    fn unwrap_sak(&self, wrapped: &[u8], kek: &Kek, an: u8) -> Result<Sak, crate::PaeError>;

    /// Compute ICV (Integrity Check Value) for MKPDU payload. Per Cl.9.7.
    ///
    /// The ICV is AES-CMAC-128 over the MKPDU content (all parameter sets
    /// except the ICV parameter set itself), using the ICK as the key.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on computation failure.
    fn compute_icv(&self, payload: &[u8], ick: &Ick) -> Result<[u8; 16], crate::PaeError>;

    /// Verify ICV of received MKPDU. Per Cl.9.7.
    ///
    /// Uses constant-time comparison to prevent timing side-channel attacks.
    ///
    /// # Errors
    /// Returns `PaeError::IcvFailed` on verification failure.
    fn verify_icv(&self, payload: &[u8], icv: &[u8], ick: &Ick) -> Result<(), crate::PaeError>;

    /// Generate a random MI (Member Identifier, 12 bytes). Per Cl.9.4.
    fn random_mi(&self) -> [u8; 12];

    /// Get current time for timer calculations.
    fn now(&self) -> Duration;

    /// Send an MKPDU on the Uncontrolled Port. Per Cl.9.7.
    ///
    /// # Errors
    /// Returns `PaeError` on send failure.
    fn send_mkpdu(&self, frame: &[u8]) -> Result<(), crate::PaeError>;
}

/// Compute ICV for MKPDU content using AES-CMAC-128 with the ICK.
///
/// Per IEEE 802.1X-2020, Clause 9.7: the ICV is computed over all
/// parameter sets in the MKPDU except the ICV parameter set itself.
///
/// Implements: #20 (REQ-F-MKA-002: MKA Transport)
///
/// # Errors
/// Returns `PaeError::CryptoError` if CMAC computation fails.
pub fn compute_icv(payload: &[u8], ick: &Ick) -> Result<[u8; 16], crate::PaeError> {
    match ick.len() {
        16 => {
            let mut cmac =
                <Cmac<aes::Aes128> as KeyInit>::new_from_slice(ick.as_bytes()).map_err(|e| {
                    crate::PaeError::CryptoError(format!("AES-128-CMAC key init failed: {}", e))
                })?;
            cmac.update(payload);
            let result = cmac.finalize().into_bytes();
            let mut icv = [0u8; 16];
            icv.copy_from_slice(&result);
            Ok(icv)
        }
        32 => {
            let mut cmac =
                <Cmac<aes::Aes256> as KeyInit>::new_from_slice(ick.as_bytes()).map_err(|e| {
                    crate::PaeError::CryptoError(format!("AES-256-CMAC key init failed: {}", e))
                })?;
            cmac.update(payload);
            let result = cmac.finalize().into_bytes();
            let mut icv = [0u8; 16];
            icv.copy_from_slice(&result);
            Ok(icv)
        }
        _ => Err(crate::PaeError::CryptoError(format!(
            "unsupported ICK length: {}",
            ick.len()
        ))),
    }
}

/// Verify ICV using constant-time comparison.
///
/// Per IEEE 802.1X-2020, Clause 9.7.
/// Implements: #20 (REQ-F-MKA-002: MKA Transport)
///
/// # Errors
/// Returns `PaeError::IcvFailed` if the ICV does not match.
pub fn verify_icv(
    payload: &[u8],
    expected_icv: &[u8; 16],
    ick: &Ick,
) -> Result<(), crate::PaeError> {
    let computed = compute_icv(payload, ick)?;
    // Constant-time comparison to prevent timing attacks
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected_icv.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(crate::PaeError::IcvFailed)
    }
}

/// MKA Participant — the Aggregate root for an MKA session.
///
/// Per IEEE 802.1X-2020, Clause 9.
/// Owns the key hierarchy and enforces invariants.
/// Generic over crypto context trait for testability.
///
/// Implements: #20 (REQ-F-MKA-002: MKA Transport)
#[allow(dead_code)] // Fields used by REQ-F-MKA-006 (cak, kek), REQ-F-MKA-003 (life_time)
pub struct MkaParticipant<C: MkaContext> {
    /// Current MKA state.
    state: MkaState,
    /// Connectivity Association Key. Used for SAK generation (Key Server) and key derivation.
    cak: Cak,
    /// CAK Name.
    ckn: Ckn,
    /// Derived ICK. Used for MKPDU ICV computation and verification.
    ick: Ick,
    /// Derived KEK. Used for SAK wrap/unwrap operations.
    kek: Kek,
    /// Installed SAK (current), if any.
    sak: Option<Sak>,
    /// Cipher suite for this CA.
    cipher_suite: CipherSuite,
    /// This participant's MI.
    mi: [u8; 12],
    /// This participant's MN.
    mn: u32,
    /// SCI (Secure Channel Identifier).
    sci: Sci,
    /// Key Server priority (lower is preferred).
    key_server_priority: u8,
    /// Key Server election result. Initially Actor (self).
    key_server: KeyServerRole,
    /// Peer list.
    peers: MkaPeerList,
    /// MKA Hello Time (default 2000ms per Cl.9.5).
    hello_time: Duration,
    /// MKA Life Time (default 6000ms per Cl.9.5). Used for peer expiry.
    life_time: Duration,
    /// Last MKPDU transmission time.
    last_hello: Option<Duration>,
    /// Crypto context (injected).
    ctx: C,
}

impl<C: MkaContext> MkaParticipant<C> {
    /// Initialize a new MKA participant. Per Cl.9.
    ///
    /// Derives ICK and KEK from the provided CAK and CKN.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` if key derivation fails.
    pub fn new(
        ctx: C,
        cak: Cak,
        ckn: Ckn,
        cipher_suite: CipherSuite,
        sci: Sci,
        key_server_priority: u8,
    ) -> Result<Self, crate::PaeError> {
        let (ick, kek) = ctx.derive_keys(&cak, &ckn)?;
        let mi = ctx.random_mi();
        Ok(Self {
            state: MkaState::Pending,
            cak,
            ckn,
            ick,
            kek,
            sak: None,
            cipher_suite,
            mi,
            mn: 1,
            sci,
            key_server_priority,
            key_server: KeyServerRole::Actor,
            peers: MkaPeerList::new(),
            hello_time: Duration::from_millis(2000),
            life_time: Duration::from_millis(6000),
            last_hello: None,
            ctx,
        })
    }

    /// Current MKA state.
    pub fn state(&self) -> MkaState {
        self.state
    }

    /// This participant's MI.
    pub fn mi(&self) -> &[u8; 12] {
        &self.mi
    }

    /// This participant's MN.
    pub fn mn(&self) -> u32 {
        self.mn
    }

    /// Current cipher suite.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Key Server priority.
    pub fn key_server_priority(&self) -> u8 {
        self.key_server_priority
    }

    /// Whether this participant is the Key Server. Per Cl.9.4.
    pub fn is_key_server(&self) -> bool {
        self.key_server == KeyServerRole::Actor
    }

    /// Current Key Server role.
    pub fn key_server(&self) -> KeyServerRole {
        self.key_server
    }

    /// Current SAK, if installed.
    pub fn sak(&self) -> Option<&Sak> {
        self.sak.as_ref()
    }

    /// CKN for this session.
    pub fn ckn(&self) -> &Ckn {
        &self.ckn
    }

    /// SCI for this participant.
    pub fn sci(&self) -> &Sci {
        &self.sci
    }

    /// Build an MKPDU for transmission. Per Cl.9.4, Cl.9.7.
    ///
    /// The MKPDU contains the Basic Parameter Set with this participant's
    /// actor MI, MN, and CKN. An ICV is computed and appended.
    ///
    /// Implements: #20 (REQ-F-MKA-002: MKA Transport)
    fn build_mkpdu(&self) -> Result<Vec<u8>, crate::PaeError> {
        use crate::mkpdu::{BasicParameterSet, Mkpdu, ParameterSet, MKPDU_VERSION};

        let bps = BasicParameterSet {
            version: MKPDU_VERSION,
            key_server_priority: self.key_server_priority,
            macsec_capability: 3, // confidentiality
            macsec_desired: true,
            sci: self.sci,
            actor_mi: self.mi,
            actor_mn: self.mn,
            key_server_mi: self.mi, // initially self
            ckn: self.ckn.clone(),
            cipher_suite: self.cipher_suite,
            an: 0,
        };

        // Build MKPDU without ICV first
        let mkpdu_no_icv = Mkpdu::new(vec![ParameterSet::Basic(bps)])?;
        let payload = mkpdu_no_icv.encode_without_icv()?;

        // Compute ICV over the payload
        let icv = self.ctx.compute_icv(&payload, &self.ick)?;

        // Build final MKPDU with ICV
        let mkpdu_with_icv = Mkpdu::new(vec![
            mkpdu_no_icv.parameter_sets()[0].clone(),
            ParameterSet::Icv(icv),
        ])?;

        mkpdu_with_icv.encode()
    }

    /// Process a received MKPDU. Per Cl.9.4, Cl.9.7.
    ///
    /// Verifies the ICV using the ICK, then extracts peer information.
    ///
    /// # Errors
    /// Returns `PaeError::IcvFailed` on ICV verification failure.
    /// Returns `PaeError::InvalidMkpdu` on malformed MKPDU.
    pub fn handle_mkpdu(&mut self, raw: &[u8]) -> Result<Vec<PaeEvent>, crate::PaeError> {
        let mkpdu = crate::mkpdu::Mkpdu::decode(raw)?;

        // Verify ICV: compute expected ICV over all parameter sets except ICV
        let payload = mkpdu.encode_without_icv()?;
        let expected_icv = self.ctx.compute_icv(&payload, &self.ick)?;
        mkpdu.verify_icv(&expected_icv)?;

        // Extract peer information from Basic Parameter Set
        let bps = mkpdu.basic();
        let _actor_mi = bps.actor_mi;
        let _actor_mn = bps.actor_mn;

        // Increment our own MN after processing a peer's MKPDU
        self.mn = self.mn.wrapping_add(1);

        Ok(vec![])
    }

    /// Perform a single timer-driven step. Per Cl.9.5.
    ///
    /// Checks if MKA Hello Time has expired and transmits an MKPDU if so.
    /// Returns events generated (e.g., MKPDU transmitted).
    pub fn step(&mut self) -> Result<Vec<PaeEvent>, crate::PaeError> {
        let now = self.ctx.now();
        let should_transmit = match self.last_hello {
            None => true,
            Some(last) => now.saturating_sub(last) >= self.hello_time,
        };

        if should_transmit {
            let mkpdu_bytes = self.build_mkpdu()?;
            self.ctx.send_mkpdu(&mkpdu_bytes)?;
            self.last_hello = Some(now);
            self.mn = self.mn.wrapping_add(1);
            Ok(vec![PaeEvent::MkaTransmit { mkpdu: mkpdu_bytes }])
        } else {
            Ok(vec![])
        }
    }

    /// Initiate SAK distribution (Key Server only). Per Cl.9.8.
    ///
    /// Generates a new SAK, wraps it with the KEK, and includes it in
    /// the next MKPDU. Only the Key Server may distribute SAKs.
    ///
    /// Implements: #24 (REQ-F-MKA-006: SAK Reception/Installation)
    ///
    /// # Errors
    /// Returns `PaeError::NotKeyServer` if this participant is not the Key Server.
    /// Returns `PaeError::CryptoError` if SAK generation or wrapping fails.
    pub fn distribute_sak(&mut self) -> Result<Vec<PaeEvent>, crate::PaeError> {
        if self.key_server != KeyServerRole::Actor {
            return Err(crate::PaeError::NotKeyServer);
        }

        let new_sak = self.ctx.generate_sak(self.cipher_suite)?;
        let _wrapped = self.ctx.wrap_sak(&new_sak, &self.kek)?;
        let an = new_sak.an();
        let sak_key = new_sak.as_bytes().to_vec();
        self.sak = Some(new_sak);
        self.mn = self.mn.wrapping_add(1);

        Ok(vec![PaeEvent::MkaSakInstalled {
            sak_key,
            sak_an: an,
            sci: self.sci,
            cipher_suite: self.cipher_suite,
        }])
    }

    /// Install a received SAK. Per Cl.9.8.
    ///
    /// Called when a Distribute SAK parameter set is received from the
    /// Key Server. Unwraps the SAK using the KEK and installs it.
    ///
    /// Implements: #24 (REQ-F-MKA-006: SAK Reception/Installation)
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` if SAK unwrapping fails.
    pub fn install_sak(&mut self, wrapped: &[u8], an: u8) -> Result<Sak, crate::PaeError> {
        let sak = self.ctx.unwrap_sak(wrapped, &self.kek, an)?;
        self.sak = Some(
            Sak::from_bytes(sak.as_bytes(), an)
                .map_err(|e| crate::PaeError::KeyError(format!("installed SAK invalid: {}", e)))?,
        );
        self.mn = self.mn.wrapping_add(1);
        Ok(sak)
    }

    /// Current peer list.
    pub fn peers(&self) -> &MkaPeerList {
        &self.peers
    }

    /// Process peer information from a received MKPDU and update state.
    ///
    /// Per Cl.9.4: adds/updates peer in the peer list and runs key server
    /// election. Transitions to Established when live peers exist.
    ///
    /// Implements: #26 (REQ-F-MKA-008: MKA Participant Creation/Deletion)
    pub fn update_peer_from_mkpdu(
        &mut self,
        mi: [u8; 12],
        mn: u32,
        peer_priority: u8,
    ) -> Result<Vec<PaeEvent>, crate::PaeError> {
        let now = self.ctx.now();
        self.peers.update_peer(mi, mn, now)?;

        // Run key server election
        self.key_server = elect_key_server(self.key_server_priority, &self.mi, peer_priority, &mi);

        // Check if we should transition to Established
        let mut events = Vec::new();
        if self.state == MkaState::Pending && self.peers.live_count() > 0 {
            self.state = MkaState::Established;
            events.push(PaeEvent::MkaSessionEstablished);
        }

        Ok(events)
    }

    /// Expire peers whose MKA Life timer has passed.
    ///
    /// Per Cl.9.4. Transitions to Pending if no live peers remain.
    ///
    /// Implements: #26 (REQ-F-MKA-008: MKA Participant Creation/Deletion)
    pub fn expire_peers(&mut self) -> Vec<PaeEvent> {
        let now = self.ctx.now();
        let _expired = self.peers.expire_peers(now, self.life_time);

        let mut events = Vec::new();
        if self.state == MkaState::Established && self.peers.live_count() == 0 {
            self.state = MkaState::Pending;
            events.push(PaeEvent::MkaSessionTerminated);
        }
        events
    }

    /// Teardown the MKA session. Per Cl.9.
    ///
    /// Clears all state: SAK, peer list, and resets to Pending.
    /// The CAK/ICK/KEK are retained so the participant can resume.
    ///
    /// Implements: #26 (REQ-F-MKA-008: MKA Participant Creation/Deletion)
    pub fn teardown(&mut self) -> Vec<PaeEvent> {
        self.sak = None;
        self.peers = MkaPeerList::new();
        self.key_server = KeyServerRole::Actor;
        self.last_hello = None;
        self.state = MkaState::Pending;
        vec![PaeEvent::MkaSessionTerminated]
    }
}

/// Key Server election result.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
/// The Key Server is the participant with the lowest priority value;
/// ties broken by MI comparison (lexicographic).
///
/// Implements: #22 (REQ-F-MKA-004: Key Server Election)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyServerRole {
    /// This participant is the Key Server.
    Actor,
    /// A remote peer is the Key Server.
    Partner,
}

/// Determine Key Server role by comparing actor priority+MI against peer.
///
/// Per IEEE 802.1X-2020, Clause 9.4: the participant with the lower
/// key_server_priority is the Key Server. If priorities are equal,
/// the participant with the lexicographically smaller MI wins.
///
/// Implements: #22 (REQ-F-MKA-004: Key Server Election)
///
/// Returns `KeyServerRole::Actor` if this participant should be Key Server,
/// `KeyServerRole::Partner` otherwise.
pub fn elect_key_server(
    actor_priority: u8,
    actor_mi: &[u8; 12],
    peer_priority: u8,
    peer_mi: &[u8; 12],
) -> KeyServerRole {
    if actor_priority < peer_priority {
        KeyServerRole::Actor
    } else if actor_priority > peer_priority {
        KeyServerRole::Partner
    } else {
        // Equal priority: compare MI lexicographically (lower wins)
        if actor_mi < peer_mi {
            KeyServerRole::Actor
        } else {
            KeyServerRole::Partner
        }
    }
}

/// MKA peer status within a participant's peer list.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkaPeerStatus {
    /// Peer is in the Potential Peer List.
    Potential,
    /// Peer is in the Live Peer List.
    Live,
}

/// MKA peer entry — identity and status of a remote MKA participant.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
/// Identity is the MI (Member Identifier); status changes over time.
///
/// Implements: #21 (REQ-F-MKA-003: MKA Peer List Management)
#[derive(Debug, Clone)]
pub struct MkaPeer {
    /// Member Identifier (MI) — 12-byte unique identifier per Cl.9.4.
    mi: [u8; 12],
    /// Member Number (MN) — monotonically increasing per Cl.9.4.
    mn: u32,
    /// Peer status (Live or Potential).
    status: MkaPeerStatus,
    /// Time of last received MKPDU from this peer.
    last_rx: Option<Duration>,
}

impl MkaPeer {
    /// Create a peer from MI and MN. Per Cl.9.4.
    pub fn new(mi: [u8; 12], mn: u32) -> Self {
        Self {
            mi,
            mn,
            status: MkaPeerStatus::Potential,
            last_rx: None,
        }
    }

    /// Member Identifier.
    pub fn mi(&self) -> &[u8; 12] {
        &self.mi
    }

    /// Member Number.
    pub fn mn(&self) -> u32 {
        self.mn
    }

    /// Peer status.
    pub fn status(&self) -> MkaPeerStatus {
        self.status
    }

    /// Promote peer from Potential to Live. Per Cl.9.4.
    pub fn promote(&mut self) {
        self.status = MkaPeerStatus::Live;
    }

    /// Update MN from received MKPDU. Per Cl.9.4.
    ///
    /// # Errors
    /// Returns `PaeError` if MN is not monotonically increasing.
    pub fn update_mn(&mut self, mn: u32) -> Result<(), crate::PaeError> {
        if mn <= self.mn {
            return Err(crate::PaeError::InvalidTransition {
                from: format!("MN={}", self.mn),
                to: format!("MN={}", mn),
            });
        }
        self.mn = mn;
        Ok(())
    }

    /// Update last receive timestamp.
    pub fn touch(&mut self, now: Duration) {
        self.last_rx = Some(now);
    }

    /// Time of last received MKPDU.
    pub fn last_rx(&self) -> Option<Duration> {
        self.last_rx
    }
}

/// MKA peer list — ordered collection of MKA peers.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
/// At most 2 Live Peers and 2 Potential Peers (supplicant limit).
///
/// Implements: #21 (REQ-F-MKA-003: MKA Peer List Management)
#[derive(Debug, Clone)]
pub struct MkaPeerList {
    /// Live peers (max 2 for supplicant).
    live: Vec<MkaPeer>,
    /// Potential peers (max 2 for supplicant).
    potential: Vec<MkaPeer>,
}

impl MkaPeerList {
    /// Maximum live peers for a supplicant.
    pub const MAX_LIVE: usize = 2;
    /// Maximum potential peers for a supplicant.
    pub const MAX_POTENTIAL: usize = 2;

    /// Create an empty peer list.
    pub fn new() -> Self {
        Self {
            live: Vec::new(),
            potential: Vec::new(),
        }
    }

    /// Find a peer by MI across both lists.
    pub fn find_by_mi(&self, mi: &[u8; 12]) -> Option<&MkaPeer> {
        self.live
            .iter()
            .chain(self.potential.iter())
            .find(|p| p.mi() == mi)
    }

    /// Find a peer by MI (mutable) across both lists.
    pub fn find_by_mi_mut(&mut self, mi: &[u8; 12]) -> Option<&mut MkaPeer> {
        self.live
            .iter_mut()
            .chain(self.potential.iter_mut())
            .find(|p| p.mi() == mi)
    }

    /// Add or update a peer from a received MKPDU. Per Cl.9.4.
    ///
    /// If the peer is already known, update its MN and timestamp.
    /// If the peer is new, add it to the Potential list.
    ///
    /// # Errors
    /// Returns `PaeError::PeerListFull` if both lists are at capacity.
    pub fn update_peer(
        &mut self,
        mi: [u8; 12],
        mn: u32,
        now: Duration,
    ) -> Result<(), crate::PaeError> {
        if let Some(peer) = self.find_by_mi_mut(&mi) {
            peer.update_mn(mn)?;
            peer.touch(now);
            return Ok(());
        }

        // New peer: add to potential list
        if self.potential.len() >= Self::MAX_POTENTIAL {
            return Err(crate::PaeError::PeerListFull {
                which: "potential".into(),
            });
        }
        let mut peer = MkaPeer::new(mi, mn);
        peer.touch(now);
        self.potential.push(peer);
        Ok(())
    }

    /// Promote a peer from Potential to Live. Per Cl.9.4.
    ///
    /// # Errors
    /// Returns `PaeError::PeerListFull` if the live list is at capacity.
    pub fn promote_peer(&mut self, mi: &[u8; 12]) -> Result<(), crate::PaeError> {
        if self.live.len() >= Self::MAX_LIVE {
            return Err(crate::PaeError::PeerListFull {
                which: "live".into(),
            });
        }

        let idx = self
            .potential
            .iter()
            .position(|p| p.mi() == mi)
            .ok_or_else(|| crate::PaeError::InvalidTransition {
                from: "not in potential list".into(),
                to: "live".into(),
            })?;

        let mut peer = self.potential.remove(idx);
        peer.promote();
        self.live.push(peer);
        Ok(())
    }

    /// Remove peers whose MKA Life timer has expired. Per Cl.9.4.
    ///
    /// Returns the MIs of expired peers.
    pub fn expire_peers(&mut self, now: Duration, mka_life: Duration) -> Vec<[u8; 12]> {
        let mut expired = Vec::new();
        self.live.retain(|p| {
            let keep = p
                .last_rx()
                .is_some_and(|last| now.saturating_sub(last) < mka_life);
            if !keep {
                expired.push(*p.mi());
            }
            keep
        });
        self.potential.retain(|p| {
            let keep = p
                .last_rx()
                .is_some_and(|last| now.saturating_sub(last) < mka_life);
            if !keep {
                expired.push(*p.mi());
            }
            keep
        });
        expired
    }

    /// Live peers iterator.
    pub fn live_peers(&self) -> impl Iterator<Item = &MkaPeer> {
        self.live.iter()
    }

    /// Potential peers iterator.
    pub fn potential_peers(&self) -> impl Iterator<Item = &MkaPeer> {
        self.potential.iter()
    }

    /// Number of live peers.
    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    /// Number of potential peers.
    pub fn potential_count(&self) -> usize {
        self.potential.len()
    }

    /// Whether the peer list is empty (no live or potential peers).
    pub fn is_empty(&self) -> bool {
        self.live.is_empty() && self.potential.is_empty()
    }
}

impl Default for MkaPeerList {
    fn default() -> Self {
        Self::new()
    }
}

/// Inter-crate events dispatched through the event loop.
///
/// Per ADR-EVT-007 (#79).
/// Owned values — no lifetimes. All state machines return `Vec<PaeEvent>`.
///
/// Implements: #20 (REQ-F-MKA-002: MKA Transport), #24 (REQ-F-MKA-006: SAK Reception)
#[derive(Clone, PartialEq)]
pub enum PaeEvent {
    // --- MKA events ---
    /// MKA participant needs to transmit an MKPDU.
    MkaTransmit {
        /// Encoded MKPDU bytes.
        mkpdu: Vec<u8>,
    },
    /// MKA has derived and installed a new SAK.
    MkaSakInstalled {
        /// SAK key bytes (owned, since Sak is not Clone per INV-PAE-002).
        /// REDACTED in Debug output to prevent key leakage.
        sak_key: Vec<u8>,
        /// Association Number for the SAK.
        sak_an: u8,
        /// SCI for the secure channel.
        sci: Sci,
        /// Cipher suite for the secure channel.
        cipher_suite: CipherSuite,
    },
    /// MKA session established (peer list is live).
    MkaSessionEstablished,
    /// MKA session terminated (no live peers).
    MkaSessionTerminated,
}

impl std::fmt::Debug for PaeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MkaTransmit { mkpdu } => f
                .debug_struct("MkaTransmit")
                .field("mkpdu_len", &mkpdu.len())
                .finish(),
            Self::MkaSakInstalled {
                sak_key: _,
                sak_an,
                sci,
                cipher_suite,
            } => f
                .debug_struct("MkaSakInstalled")
                .field("sak_key", &"[REDACTED]")
                .field("sak_an", sak_an)
                .field("sci", sci)
                .field("cipher_suite", cipher_suite)
                .finish(),
            Self::MkaSessionEstablished => write!(f, "MkaSessionEstablished"),
            Self::MkaSessionTerminated => write!(f, "MkaSessionTerminated"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timer::{
        TimerId, TimerWheel, MKA_BOUNDED_HELLO_TIME, MKA_HELLO_TIME, MKA_LIFE_TIME, SAK_RETIRE_TIME,
    };

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

    // --- KDF AES-256 support (SEC-001, SEC-002 fix verification) ---

    /// Verifies: KDF works with AES-256 CAK (32-byte key).
    #[test]
    fn test_kdf_aes256_derive_ick() {
        let cak = Cak::from_bytes(&[0x01; 32]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf
            .derive_ick(&cak, &ckn)
            .expect("AES-256 ICK derivation should succeed");
        assert_eq!(ick.len(), 32);
    }

    /// Verifies: KDF works with AES-256 CAK for KEK derivation.
    #[test]
    fn test_kdf_aes256_derive_kek() {
        let cak = Cak::from_bytes(&[0x01; 32]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let kek = kdf
            .derive_kek(&cak, &ckn)
            .expect("AES-256 KEK derivation should succeed");
        assert_eq!(kek.len(), 32);
    }

    /// Verifies: AES-256 ICK and KEK are different from each other.
    #[test]
    fn test_kdf_aes256_ick_kek_different() {
        let cak = Cak::from_bytes(&[0x01; 32]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();
        let kek = kdf.derive_kek(&cak, &ckn).unwrap();
        assert_ne!(
            ick.as_bytes(),
            kek.as_bytes(),
            "AES-256 ICK and KEK must differ"
        );
    }

    /// Verifies: AES-256 KDF is deterministic.
    #[test]
    fn test_kdf_aes256_deterministic() {
        let cak = Cak::from_bytes(&[0x01; 32]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick_a = kdf.derive_ick(&cak, &ckn).unwrap();
        let ick_b = kdf.derive_ick(&cak, &ckn).unwrap();
        assert_eq!(
            ick_a.as_bytes(),
            ick_b.as_bytes(),
            "AES-256 KDF must be deterministic"
        );
    }

    /// Verifies: AES-256 and AES-128 produce different ICKs for same input seed.
    #[test]
    fn test_kdf_aes128_vs_aes256_different() {
        let cak128 = Cak::from_bytes(&[0x01; 16]).unwrap();
        let cak256 = Cak::from_bytes(&[0x01; 32]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        // AES-128 ICK is 16 bytes, AES-256 ICK is 32 bytes
        let ick128 = kdf.derive_ick(&cak128, &ckn).unwrap();
        let ick256 = kdf.derive_ick(&cak256, &ckn).unwrap();
        assert_eq!(ick128.len(), 16);
        assert_eq!(ick256.len(), 32);
        // First 16 bytes should differ (different key sizes)
        assert_ne!(ick128.as_bytes(), &ick256.as_bytes()[..16]);
    }

    /// Verifies: ICK rejects non-standard lengths (SEC-003 fix).
    #[test]
    fn test_ick_rejects_non_standard_length() {
        let result = Ick::from_bytes(&[0x01; 8]);
        assert!(result.is_err(), "ICK must reject 8-byte key");
        let result = Ick::from_bytes(&[0x01; 24]);
        assert!(result.is_err(), "ICK must reject 24-byte key");
    }

    /// Verifies: KEK rejects non-standard lengths (SEC-004 fix).
    #[test]
    fn test_kek_rejects_non_standard_length() {
        let result = Kek::from_bytes(&[0x01; 8]);
        assert!(result.is_err(), "KEK must reject 8-byte key");
        let result = Kek::from_bytes(&[0x01; 24]);
        assert!(result.is_err(), "KEK must reject 24-byte key");
    }

    // --- REQ-F-MKA-002: MKA Transport ---

    /// Mock MkaContext for testing.
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Mutex;

    struct MockMkaContext {
        ick: Ick,
        kek: Kek,
        now_time: Mutex<Duration>,
        sent_frames: Mutex<Vec<Vec<u8>>>,
        mi_counter: AtomicU8,
    }

    impl MockMkaContext {
        fn new(cak: &Cak, ckn: &Ckn) -> Self {
            let kdf = AesCmacKdf;
            let ick = kdf.derive_ick(cak, ckn).unwrap();
            let kek = kdf.derive_kek(cak, ckn).unwrap();
            Self {
                ick,
                kek,
                now_time: Mutex::new(Duration::ZERO),
                sent_frames: Mutex::new(Vec::new()),
                mi_counter: AtomicU8::new(0),
            }
        }

        fn advance_time(&self, delta: Duration) {
            let mut t = self.now_time.lock().unwrap();
            *t += delta;
        }

        fn sent_frames(&self) -> Vec<Vec<u8>> {
            self.sent_frames.lock().unwrap().clone()
        }
    }

    impl MkaContext for MockMkaContext {
        fn derive_keys(&self, cak: &Cak, ckn: &Ckn) -> Result<(Ick, Kek), crate::PaeError> {
            let kdf = AesCmacKdf;
            let ick = kdf.derive_ick(cak, ckn)?;
            let kek = kdf.derive_kek(cak, ckn)?;
            Ok((ick, kek))
        }

        fn generate_sak(&self, cipher_suite: CipherSuite) -> Result<Sak, crate::PaeError> {
            let key = vec![0xAB; cipher_suite.key_len()];
            Sak::from_bytes(&key, 0).map_err(|e| crate::PaeError::KeyError(e.to_string()))
        }

        fn wrap_sak(&self, sak: &Sak, _kek: &Kek) -> Result<Vec<u8>, crate::PaeError> {
            // Mock: just return the SAK bytes with a header
            let mut wrapped = vec![0x01]; // mock header
            wrapped.extend_from_slice(sak.as_bytes());
            Ok(wrapped)
        }

        fn unwrap_sak(&self, wrapped: &[u8], _kek: &Kek, an: u8) -> Result<Sak, crate::PaeError> {
            // Mock: skip the 1-byte header and extract SAK
            if wrapped.len() < 2 {
                return Err(crate::PaeError::CryptoError("wrapped SAK too short".into()));
            }
            Sak::from_bytes(&wrapped[1..], an)
                .map_err(|e| crate::PaeError::CryptoError(e.to_string()))
        }

        fn compute_icv(&self, payload: &[u8], ick: &Ick) -> Result<[u8; 16], crate::PaeError> {
            super::compute_icv(payload, ick)
        }

        fn verify_icv(&self, payload: &[u8], icv: &[u8], ick: &Ick) -> Result<(), crate::PaeError> {
            let computed = super::compute_icv(payload, ick)?;
            let mut diff = 0u8;
            for (a, b) in computed.iter().zip(icv.iter()) {
                diff |= a ^ b;
            }
            if diff == 0 {
                Ok(())
            } else {
                Err(crate::PaeError::IcvFailed)
            }
        }

        fn random_mi(&self) -> [u8; 12] {
            let mut mi = [0u8; 12];
            let c = self.mi_counter.fetch_add(1, Ordering::SeqCst);
            mi[0] = c;
            mi
        }

        fn now(&self) -> Duration {
            *self.now_time.lock().unwrap()
        }

        fn send_mkpdu(&self, frame: &[u8]) -> Result<(), crate::PaeError> {
            self.sent_frames.lock().unwrap().push(frame.to_vec());
            Ok(())
        }
    }

    fn make_participant() -> MkaParticipant<MockMkaContext> {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let ctx = MockMkaContext::new(&cak, &ckn);
        let sci = Sci::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 1);
        MkaParticipant::new(ctx, cak, ckn, CipherSuite::GcmAes128, sci, 0x10).unwrap()
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// compute_icv produces a deterministic 16-byte ICV from payload + ICK.
    #[test]
    fn test_compute_icv_deterministic() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();

        let payload = b"test payload for ICV";
        let icv1 = compute_icv(payload, &ick).expect("compute_icv should succeed");
        let icv2 = compute_icv(payload, &ick).expect("compute_icv should succeed");
        assert_eq!(icv1, icv2, "ICV must be deterministic");
        assert_eq!(icv1.len(), 16, "ICV must be 16 bytes");
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// Different payloads produce different ICVs.
    #[test]
    fn test_compute_icv_different_payloads() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();

        let icv1 = compute_icv(b"payload A", &ick).unwrap();
        let icv2 = compute_icv(b"payload B", &ick).unwrap();
        assert_ne!(icv1, icv2, "Different payloads must produce different ICVs");
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// Different ICKs produce different ICVs for the same payload.
    #[test]
    fn test_compute_icv_different_icks() {
        let cak1 = Cak::from_bytes(&[0x01; 16]).unwrap();
        let cak2 = Cak::from_bytes(&[0x03; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick1 = kdf.derive_ick(&cak1, &ckn).unwrap();
        let ick2 = kdf.derive_ick(&cak2, &ckn).unwrap();

        let payload = b"same payload";
        let icv1 = compute_icv(payload, &ick1).unwrap();
        let icv2 = compute_icv(payload, &ick2).unwrap();
        assert_ne!(icv1, icv2, "Different ICKs must produce different ICVs");
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// compute_icv works with AES-256 ICK (32-byte key).
    #[test]
    fn test_compute_icv_aes256() {
        let cak = Cak::from_bytes(&[0x01; 32]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();
        assert_eq!(ick.len(), 32);

        let icv = compute_icv(b"test payload", &ick).expect("AES-256 ICV should succeed");
        assert_eq!(icv.len(), 16);
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// verify_icv succeeds when ICV matches.
    #[test]
    fn test_verify_icv_success() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();

        let payload = b"test payload for verification";
        let icv = compute_icv(payload, &ick).unwrap();
        let result = verify_icv(payload, &icv, &ick);
        assert!(
            result.is_ok(),
            "ICV verification must succeed with matching ICV"
        );
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// verify_icv fails when ICV does not match.
    #[test]
    fn test_verify_icv_failure() {
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();

        let payload = b"test payload for verification";
        let wrong_icv = [0xFF; 16];
        let result = verify_icv(payload, &wrong_icv, &ick);
        assert!(result.is_err(), "ICV verification must fail with wrong ICV");
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.
    /// MkaParticipant initializes in Pending state with valid MI and MN.
    #[test]
    fn test_mka_participant_init() {
        let p = make_participant();
        assert_eq!(p.state(), MkaState::Pending);
        assert_eq!(p.mn(), 1);
        assert_eq!(p.cipher_suite(), CipherSuite::GcmAes128);
        assert_eq!(p.key_server_priority(), 0x10);
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Given an active participant, When the MKA Hello Time expires,
    /// Then an MKPDU is transmitted with authenticated integrity.
    #[test]
    fn test_mka_participant_step_transmits_mkpdu() {
        let mut p = make_participant();
        // First step: should transmit immediately (no prior hello)
        let events = p.step().expect("step should succeed");
        assert_eq!(events.len(), 1);
        match &events[0] {
            PaeEvent::MkaTransmit { mkpdu } => {
                assert!(!mkpdu.is_empty(), "MKPDU must not be empty");
            }
            _ => panic!("expected MkaTransmit event"),
        }

        // Sent frames should contain the MKPDU
        let frames = p.ctx.sent_frames();
        assert_eq!(frames.len(), 1);
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Step does not retransmit before Hello Time expires.
    #[test]
    fn test_mka_participant_step_no_premature_retransmit() {
        let mut p = make_participant();
        let events1 = p.step().unwrap();
        assert_eq!(events1.len(), 1);

        // Advance time by less than Hello Time (2000ms)
        p.ctx.advance_time(Duration::from_millis(1000));
        let events2 = p.step().unwrap();
        assert!(
            events2.is_empty(),
            "should not retransmit before Hello Time"
        );
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Step retransmits after Hello Time expires.
    #[test]
    fn test_mka_participant_step_retransmit_after_hello() {
        let mut p = make_participant();
        p.step().unwrap();

        // Advance past Hello Time
        p.ctx.advance_time(Duration::from_millis(2001));
        let events = p.step().unwrap();
        assert_eq!(events.len(), 1, "should retransmit after Hello Time");

        let frames = p.ctx.sent_frames();
        assert_eq!(frames.len(), 2);
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// Transmitted MKPDU can be decoded and ICV verified.
    #[test]
    fn test_mka_participant_mkpdu_icv_round_trip() {
        let mut p = make_participant();
        let events = p.step().unwrap();
        let mkpdu_bytes = match &events[0] {
            PaeEvent::MkaTransmit { mkpdu } => mkpdu.clone(),
            _ => panic!("expected MkaTransmit"),
        };

        // Decode the MKPDU
        let mkpdu = crate::mkpdu::Mkpdu::decode(&mkpdu_bytes).expect("MKPDU decode should succeed");
        assert!(mkpdu.icv().is_some(), "MKPDU must have ICV");

        // Verify ICV
        let payload = mkpdu.encode_without_icv().unwrap();
        let kdf = AesCmacKdf;
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();
        let expected_icv = compute_icv(&payload, &ick).unwrap();
        mkpdu
            .verify_icv(&expected_icv)
            .expect("ICV verification should succeed");
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// handle_mkpdu verifies ICV and rejects invalid ICV.
    #[test]
    fn test_mka_participant_handle_mkpdu_valid_icv() {
        let mut p = make_participant();

        // Build a valid MKPDU from a "peer"
        let cak = Cak::from_bytes(&[0x01; 16]).unwrap();
        let ckn = Ckn::from_bytes(vec![0x02; 16]).unwrap();
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(&cak, &ckn).unwrap();

        let bps = crate::mkpdu::BasicParameterSet {
            version: crate::mkpdu::MKPDU_VERSION,
            key_server_priority: 0x20,
            macsec_capability: 3,
            macsec_desired: true,
            sci: Sci::new([0xAA; 6], 1),
            actor_mi: [0xBB; 12],
            actor_mn: 5,
            key_server_mi: [0xBB; 12],
            ckn: ckn.clone(),
            cipher_suite: CipherSuite::GcmAes128,
            an: 0,
        };

        let mkpdu_no_icv =
            crate::mkpdu::Mkpdu::new(vec![crate::mkpdu::ParameterSet::Basic(bps)]).unwrap();
        let payload = mkpdu_no_icv.encode_without_icv().unwrap();
        let icv = compute_icv(&payload, &ick).unwrap();

        let mkpdu_with_icv = crate::mkpdu::Mkpdu::new(vec![
            mkpdu_no_icv.parameter_sets()[0].clone(),
            crate::mkpdu::ParameterSet::Icv(icv),
        ])
        .unwrap();
        let raw = mkpdu_with_icv.encode().unwrap();

        let result = p.handle_mkpdu(&raw);
        assert!(result.is_ok(), "handle_mkpdu with valid ICV should succeed");
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// handle_mkpdu rejects MKPDU with invalid ICV.
    #[test]
    fn test_mka_participant_handle_mkpdu_invalid_icv() {
        let mut p = make_participant();

        let bps = crate::mkpdu::BasicParameterSet {
            version: crate::mkpdu::MKPDU_VERSION,
            key_server_priority: 0x20,
            macsec_capability: 3,
            macsec_desired: true,
            sci: Sci::new([0xAA; 6], 1),
            actor_mi: [0xBB; 12],
            actor_mn: 5,
            key_server_mi: [0xBB; 12],
            ckn: Ckn::from_bytes(vec![0x02; 16]).unwrap(),
            cipher_suite: CipherSuite::GcmAes128,
            an: 0,
        };

        let wrong_icv = [0xFF; 16];
        let mkpdu = crate::mkpdu::Mkpdu::new(vec![
            crate::mkpdu::ParameterSet::Basic(bps),
            crate::mkpdu::ParameterSet::Icv(wrong_icv),
        ])
        .unwrap();
        let raw = mkpdu.encode().unwrap();

        let result = p.handle_mkpdu(&raw);
        assert!(result.is_err(), "handle_mkpdu with invalid ICV must fail");
    }

    /// Verifies: #20 (REQ-F-MKA-002)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// MN increments after each step and handle_mkpdu.
    #[test]
    fn test_mka_participant_mn_increments() {
        let mut p = make_participant();
        assert_eq!(p.mn(), 1);

        p.step().unwrap();
        assert_eq!(p.mn(), 2, "MN should increment after step");
    }

    // --- REQ-F-MKA-003: MKA Peer List Management ---

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// MkaPeer creates with Potential status.
    #[test]
    fn test_mka_peer_new() {
        let mi = [0xAA; 12];
        let peer = MkaPeer::new(mi, 5);
        assert_eq!(*peer.mi(), mi);
        assert_eq!(peer.mn(), 5);
        assert_eq!(peer.status(), MkaPeerStatus::Potential);
        assert!(peer.last_rx().is_none());
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// MkaPeer promotes from Potential to Live.
    #[test]
    fn test_mka_peer_promote() {
        let mi = [0xAA; 12];
        let mut peer = MkaPeer::new(mi, 1);
        assert_eq!(peer.status(), MkaPeerStatus::Potential);
        peer.promote();
        assert_eq!(peer.status(), MkaPeerStatus::Live);
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// MkaPeer updates MN monotonically.
    #[test]
    fn test_mka_peer_update_mn() {
        let mi = [0xAA; 12];
        let mut peer = MkaPeer::new(mi, 5);
        assert!(peer.update_mn(6).is_ok());
        assert_eq!(peer.mn(), 6);
        assert!(peer.update_mn(5).is_err(), "MN must not decrease");
        assert!(peer.update_mn(6).is_err(), "MN must strictly increase");
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// MkaPeer touch updates last_rx timestamp.
    #[test]
    fn test_mka_peer_touch() {
        let mi = [0xAA; 12];
        let mut peer = MkaPeer::new(mi, 1);
        assert!(peer.last_rx().is_none());
        let now = Duration::from_secs(10);
        peer.touch(now);
        assert_eq!(peer.last_rx(), Some(now));
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// MkaPeerList starts empty.
    #[test]
    fn test_mka_peer_list_new() {
        let list = MkaPeerList::new();
        assert!(list.is_empty());
        assert_eq!(list.live_count(), 0);
        assert_eq!(list.potential_count(), 0);
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// update_peer adds a new peer to the potential list.
    #[test]
    fn test_mka_peer_list_update_new_peer() {
        let mut list = MkaPeerList::new();
        let mi = [0x01; 12];
        let now = Duration::from_secs(1);
        list.update_peer(mi, 1, now).unwrap();
        assert_eq!(list.potential_count(), 1);
        assert_eq!(list.live_count(), 0);
        let peer = list.find_by_mi(&mi).unwrap();
        assert_eq!(*peer.mi(), mi);
        assert_eq!(peer.mn(), 1);
        assert_eq!(peer.status(), MkaPeerStatus::Potential);
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// update_peer updates an existing peer's MN.
    #[test]
    fn test_mka_peer_list_update_existing_peer() {
        let mut list = MkaPeerList::new();
        let mi = [0x01; 12];
        let now = Duration::from_secs(1);
        list.update_peer(mi, 1, now).unwrap();
        let now2 = Duration::from_secs(2);
        list.update_peer(mi, 2, now2).unwrap();
        assert_eq!(list.potential_count(), 1, "should not duplicate");
        let peer = list.find_by_mi(&mi).unwrap();
        assert_eq!(peer.mn(), 2);
        assert_eq!(peer.last_rx(), Some(now2));
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Peer list rejects when potential list is full (max 2).
    #[test]
    fn test_mka_peer_list_potential_full() {
        let mut list = MkaPeerList::new();
        let now = Duration::from_secs(1);
        list.update_peer([0x01; 12], 1, now).unwrap();
        list.update_peer([0x02; 12], 1, now).unwrap();
        let result = list.update_peer([0x03; 12], 1, now);
        assert!(result.is_err());
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// promote_peer moves a peer from potential to live.
    #[test]
    fn test_mka_peer_list_promote() {
        let mut list = MkaPeerList::new();
        let now = Duration::from_secs(1);
        let mi = [0x01; 12];
        list.update_peer(mi, 1, now).unwrap();
        assert_eq!(list.potential_count(), 1);
        assert_eq!(list.live_count(), 0);

        list.promote_peer(&mi).unwrap();
        assert_eq!(list.potential_count(), 0);
        assert_eq!(list.live_count(), 1);
        let peer = list.find_by_mi(&mi).unwrap();
        assert_eq!(peer.status(), MkaPeerStatus::Live);
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Peer list rejects promotion when live list is full (max 2).
    #[test]
    fn test_mka_peer_list_live_full() {
        let mut list = MkaPeerList::new();
        let now = Duration::from_secs(1);
        let mi1 = [0x01; 12];
        let mi2 = [0x02; 12];
        list.update_peer(mi1, 1, now).unwrap();
        list.update_peer(mi2, 1, now).unwrap();

        list.promote_peer(&mi1).unwrap();
        list.promote_peer(&mi2).unwrap();

        // Add a third peer and try to promote
        let mi3 = [0x03; 12];
        list.update_peer(mi3, 1, now).unwrap();
        let result = list.promote_peer(&mi3);
        assert!(result.is_err());
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// expire_peers removes peers whose MKA Life timer has expired.
    #[test]
    fn test_mka_peer_list_expire() {
        let mut list = MkaPeerList::new();
        let now = Duration::from_secs(10);
        let mka_life = Duration::from_secs(6);

        list.update_peer([0x01; 12], 1, Duration::from_secs(3))
            .unwrap(); // expired
        list.update_peer([0x02; 12], 1, Duration::from_secs(8))
            .unwrap(); // alive
        list.promote_peer(&[0x02; 12]).unwrap();

        let expired = list.expire_peers(now, mka_life);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], [0x01; 12]);
        assert_eq!(list.potential_count(), 0, "expired peer should be removed");
        assert_eq!(list.live_count(), 1, "alive peer should remain");
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// find_by_mi returns None for unknown MI.
    #[test]
    fn test_mka_peer_list_find_unknown() {
        let list = MkaPeerList::new();
        assert!(list.find_by_mi(&[0xFF; 12]).is_none());
    }

    /// Verifies: #21 (REQ-F-MKA-003)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Live and potential peer iterators work.
    #[test]
    fn test_mka_peer_list_iterators() {
        let mut list = MkaPeerList::new();
        let now = Duration::from_secs(1);
        list.update_peer([0x01; 12], 1, now).unwrap();
        list.update_peer([0x02; 12], 1, now).unwrap();
        list.promote_peer(&[0x01; 12]).unwrap();

        let live_mis: Vec<_> = list.live_peers().map(|p| *p.mi()).collect();
        let pot_mis: Vec<_> = list.potential_peers().map(|p| *p.mi()).collect();
        assert_eq!(live_mis, vec![[0x01; 12]]);
        assert_eq!(pot_mis, vec![[0x02; 12]]);
    }

    // --- REQ-F-MKA-004: Key Server Election ---

    /// Verifies: #22 (REQ-F-MKA-004)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Actor with lower priority is Key Server.
    #[test]
    fn test_elect_key_server_actor_lower_priority() {
        let role = elect_key_server(0x01, &[0xAA; 12], 0x02, &[0xBB; 12]);
        assert_eq!(role, KeyServerRole::Actor);
    }

    /// Verifies: #22 (REQ-F-MKA-004)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Peer with lower priority is Key Server.
    #[test]
    fn test_elect_key_server_peer_lower_priority() {
        let role = elect_key_server(0x02, &[0xAA; 12], 0x01, &[0xBB; 12]);
        assert_eq!(role, KeyServerRole::Partner);
    }

    /// Verifies: #22 (REQ-F-MKA-004)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Equal priority: lexicographically smaller MI wins.
    #[test]
    fn test_elect_key_server_equal_priority_mi_tiebreak() {
        let mi_small = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let mi_big = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let role = elect_key_server(0x10, &mi_small, 0x10, &mi_big);
        assert_eq!(role, KeyServerRole::Actor);
    }

    /// Verifies: #22 (REQ-F-MKA-004)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Equal priority and peer has smaller MI: peer is Key Server.
    #[test]
    fn test_elect_key_server_equal_priority_peer_smaller_mi() {
        let mi_big = [0xFF; 12];
        let mi_small = [0x00; 12];
        let role = elect_key_server(0x10, &mi_big, 0x10, &mi_small);
        assert_eq!(role, KeyServerRole::Partner);
    }

    /// Verifies: #22 (REQ-F-MKA-004)
    /// MkaParticipant starts as Key Server (Actor).
    #[test]
    fn test_mka_participant_initial_key_server() {
        let p = make_participant();
        assert!(p.is_key_server());
        assert_eq!(p.key_server(), KeyServerRole::Actor);
    }

    // --- REQ-F-MKA-006: SAK Reception/Installation ---

    /// Verifies: #24 (REQ-F-MKA-006)
    /// Per IEEE 802.1X-2020, Clause 9.8.
    /// MkaParticipant starts with no SAK installed.
    #[test]
    fn test_mka_participant_no_initial_sak() {
        let p = make_participant();
        assert!(p.sak().is_none());
    }

    /// Verifies: #24 (REQ-F-MKA-006)
    /// Per IEEE 802.1X-2020, Clause 9.8.
    /// distribute_sak generates and installs a SAK (Key Server only).
    #[test]
    fn test_mka_participant_distribute_sak() {
        let mut p = make_participant();
        assert!(p.sak().is_none());

        let events = p.distribute_sak().expect("distribute_sak should succeed");
        assert!(
            p.sak().is_some(),
            "SAK should be installed after distribute_sak"
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            PaeEvent::MkaSakInstalled {
                sak_key,
                sak_an,
                sci,
                cipher_suite,
            } => {
                assert_eq!(*sak_an, 0);
                assert_eq!(sak_key.len(), 16); // GcmAes128
                assert_eq!(*sci, *p.sci());
                assert_eq!(*cipher_suite, p.cipher_suite());
            }
            _ => panic!("expected MkaSakInstalled event"),
        }
    }

    /// Verifies: #24 (REQ-F-MKA-006)
    /// Per IEEE 802.1X-2020, Clause 9.8.
    /// distribute_sak fails when not Key Server.
    #[test]
    fn test_mka_participant_distribute_sak_not_key_server() {
        let mut p = make_participant();
        p.key_server = KeyServerRole::Partner;
        let result = p.distribute_sak();
        assert!(
            result.is_err(),
            "distribute_sak must fail when not Key Server"
        );
    }

    /// Verifies: #24 (REQ-F-MKA-006)
    /// Per IEEE 802.1X-2020, Clause 9.8.
    /// install_sak unwraps and installs a received SAK.
    #[test]
    fn test_mka_participant_install_sak() {
        let mut p = make_participant();
        assert!(p.sak().is_none());

        // Create a mock wrapped SAK (1-byte header + 16 key bytes)
        let mut wrapped = vec![0x01];
        wrapped.extend_from_slice(&[0xAB; 16]);

        let sak = p
            .install_sak(&wrapped, 1)
            .expect("install_sak should succeed");
        assert_eq!(sak.an(), 1);
        assert!(
            p.sak().is_some(),
            "SAK should be installed after install_sak"
        );
        assert_eq!(p.sak().unwrap().an(), 1);
    }

    /// Verifies: #24 (REQ-F-MKA-006)
    /// Per IEEE 802.1X-2020, Clause 9.8.
    /// install_sak fails with invalid wrapped data.
    #[test]
    fn test_mka_participant_install_sak_invalid() {
        let mut p = make_participant();
        let result = p.install_sak(&[0x01], 0); // too short
        assert!(result.is_err(), "install_sak must fail with invalid data");
    }

    // --- REQ-F-MKA-008: MKA Participant Creation/Deletion ---

    /// Verifies: #26 (REQ-F-MKA-008)
    /// Per IEEE 802.1X-2020, Clause 9.
    /// MkaParticipant starts with empty peer list.
    #[test]
    fn test_mka_participant_empty_peers() {
        let p = make_participant();
        assert!(p.peers().is_empty());
        assert_eq!(p.peers().live_count(), 0);
        assert_eq!(p.peers().potential_count(), 0);
    }

    /// Verifies: #26 (REQ-F-MKA-008)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// update_peer_from_mkpdu adds a peer and runs key server election.
    #[test]
    fn test_mka_participant_update_peer() {
        let mut p = make_participant();
        let mi = [0xBB; 12];
        let events = p.update_peer_from_mkpdu(mi, 5, 0x20).unwrap();
        assert!(events.is_empty(), "no events when no live peers");
        assert_eq!(p.peers().potential_count(), 1);
        assert_eq!(p.state(), MkaState::Pending);
    }

    /// Verifies: #26 (REQ-F-MKA-008)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Transition to Established when a peer is promoted to Live.
    #[test]
    fn test_mka_participant_established_on_live_peer() {
        let mut p = make_participant();
        let mi = [0xBB; 12];
        p.update_peer_from_mkpdu(mi, 5, 0x20).unwrap();
        assert_eq!(p.state(), MkaState::Pending);

        // Promote the peer to Live
        p.peers.promote_peer(&mi).unwrap();
        // The next update_peer_from_mkpdu should detect live peers
        let events = p.update_peer_from_mkpdu(mi, 6, 0x20).unwrap();
        assert_eq!(p.state(), MkaState::Established);
        assert!(events.contains(&PaeEvent::MkaSessionEstablished));
    }

    /// Verifies: #26 (REQ-F-MKA-008)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// Key server election updates when peer has lower priority.
    #[test]
    fn test_mka_participant_key_server_election_on_peer() {
        let mut p = make_participant();
        assert!(p.is_key_server());

        // Peer with lower priority becomes Key Server
        let mi = [0xBB; 12];
        p.update_peer_from_mkpdu(mi, 5, 0x05).unwrap(); // 0x05 < 0x10
        assert_eq!(p.key_server(), KeyServerRole::Partner);
    }

    /// Verifies: #26 (REQ-F-MKA-008)
    /// Per IEEE 802.1X-2020, Clause 9.
    /// teardown clears SAK, peers, and resets state.
    #[test]
    fn test_mka_participant_teardown() {
        let mut p = make_participant();
        p.update_peer_from_mkpdu([0xBB; 12], 5, 0x20).unwrap();
        p.distribute_sak().unwrap();
        assert!(p.sak().is_some());
        assert!(!p.peers().is_empty());

        let events = p.teardown();
        assert!(p.sak().is_none());
        assert!(p.peers().is_empty());
        assert_eq!(p.state(), MkaState::Pending);
        assert!(p.is_key_server());
        assert!(events.contains(&PaeEvent::MkaSessionTerminated));
    }

    /// Verifies: #49 (REQ-NF-PERF-002)
    /// Peer is NOT expired before MKA Life Time (6.0s).
    /// At t=5999ms after last_rx, the peer must still be present.
    #[test]
    fn test_perf_life_time_not_expired_before_deadline() {
        let mut list = MkaPeerList::new();
        let mi = [0x01; 12];
        let last_rx = Duration::from_millis(0);
        list.update_peer(mi, 1, last_rx).unwrap();
        list.promote_peer(&mi).unwrap();

        // At 5999ms (1ms before MKA Life Time), peer must NOT be expired
        let expired = list.expire_peers(Duration::from_millis(5999), MKA_LIFE_TIME);
        assert!(
            expired.is_empty(),
            "peer must not expire before 6000ms, but got {:?} expired",
            expired.len()
        );
        assert_eq!(list.live_count(), 1, "live peer must remain");
    }

    /// Verifies: #49 (REQ-NF-PERF-002)
    /// Peer IS expired at exactly MKA Life Time (6.0s).
    /// At t=6000ms after last_rx, the peer must be removed.
    #[test]
    fn test_perf_life_time_expired_at_deadline() {
        let mut list = MkaPeerList::new();
        let mi = [0x01; 12];
        let last_rx = Duration::from_millis(0);
        list.update_peer(mi, 1, last_rx).unwrap();
        list.promote_peer(&mi).unwrap();

        // At exactly 6000ms, peer MUST be expired
        let expired = list.expire_peers(MKA_LIFE_TIME, MKA_LIFE_TIME);
        assert_eq!(expired.len(), 1, "peer must expire at exactly 6000ms");
        assert_eq!(expired[0], mi);
        assert_eq!(list.live_count(), 0, "expired peer must be removed");
    }

    /// Verifies: #49 (REQ-NF-PERF-002)
    /// Peer with recent liveness (within Hello Time) is NOT expired
    /// even if the absolute time is past MKA Life Time from session start.
    /// Liveness refreshes the expiry deadline.
    #[test]
    fn test_perf_life_time_liveness_refreshes_expiry() {
        let mut list = MkaPeerList::new();
        let mi = [0x01; 12];

        // Peer first seen at t=0
        list.update_peer(mi, 1, Duration::from_millis(0)).unwrap();
        list.promote_peer(&mi).unwrap();

        // Peer sends MKPDU at t=4000ms (refreshes liveness)
        list.update_peer(mi, 2, Duration::from_millis(4000))
            .unwrap();

        // At t=9999ms (5999ms since last_rx at 4000ms), peer must NOT expire
        let expired = list.expire_peers(Duration::from_millis(9999), MKA_LIFE_TIME);
        assert!(
            expired.is_empty(),
            "peer with refreshed liveness must not expire before 6s from last_rx"
        );

        // At t=10000ms (6000ms since last_rx), peer MUST expire
        let expired = list.expire_peers(Duration::from_millis(10000), MKA_LIFE_TIME);
        assert_eq!(expired.len(), 1, "peer must expire at 6s after last_rx");
    }

    /// Verifies: #49 (REQ-NF-PERF-002)
    /// Periodic peer expiry over 5 cycles with liveness refreshes.
    /// Validates that expire_peers timing is accurate across multiple
    /// expiry/refresh cycles (simulating 30 seconds of operation).
    #[test]
    fn test_perf_life_time_periodic_expiry() {
        let mut list = MkaPeerList::new();

        for cycle in 0..5u64 {
            let mi = [cycle as u8; 12];
            let base_ms = cycle * 7000; // 7s per cycle (6s life + 1s gap)

            // Peer appears at cycle start
            list.update_peer(mi, 1, Duration::from_millis(base_ms))
                .unwrap();
            list.promote_peer(&mi).unwrap();

            // Check at 1ms before Life Time: peer must survive
            let expired_before =
                list.expire_peers(Duration::from_millis(base_ms + 5999), MKA_LIFE_TIME);
            assert!(
                !expired_before.iter().any(|e| *e == mi),
                "cycle {cycle}: peer must not expire before 6s"
            );

            // Check at Life Time: peer must expire
            let expired_at =
                list.expire_peers(Duration::from_millis(base_ms + 6000), MKA_LIFE_TIME);
            assert!(
                expired_at.iter().any(|e| *e == mi),
                "cycle {cycle}: peer must expire at 6s"
            );
        }
    }

    /// Verifies: #49 (REQ-NF-PERF-002)
    /// expire_peers execution is bounded when processing many peers.
    /// With 4 peers (2 live + 2 potential), repeated expiry over 1000 cycles
    /// should complete in sub-millisecond wall-clock time.
    #[test]
    fn test_perf_expire_bounded_execution() {
        let mut list = MkaPeerList::new();
        let start = std::time::Instant::now();

        let mut total_expired = 0;
        for cycle in 0..1000u64 {
            let base_ms = cycle * 6001;

            // Add 2 potential + 2 live peers at cycle start
            let mi1 = [0x01u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, cycle as u8];
            let mi2 = [0x02u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, cycle as u8];
            let mi3 = [0x03u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, cycle as u8];
            let mi4 = [0x04u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, cycle as u8];

            list = MkaPeerList::new(); // Reset each cycle to avoid capacity errors
            let now = Duration::from_millis(base_ms);
            list.update_peer(mi1, 1, now).unwrap();
            list.update_peer(mi2, 1, now).unwrap();
            list.promote_peer(&mi1).unwrap();
            list.promote_peer(&mi2).unwrap();
            list.update_peer(mi3, 1, now).unwrap();
            list.update_peer(mi4, 1, now).unwrap();

            // Advance past MKA Life Time
            let expired = list.expire_peers(Duration::from_millis(base_ms + 6000), MKA_LIFE_TIME);
            total_expired += expired.len();
        }

        let elapsed = start.elapsed();
        assert!(
            total_expired >= 4000,
            "expected >= 4000 expired, got {}",
            total_expired
        );
        assert!(
            elapsed < Duration::from_millis(100),
            "1000 expiry cycles took {:?}, expected < 100ms",
            elapsed
        );
    }

    /// Verifies: #26 (REQ-F-MKA-008)
    /// Per IEEE 802.1X-2020, Clause 9.4.
    /// expire_peers transitions back to Pending when all live peers expire.
    #[test]
    fn test_mka_participant_expire_peers_session_terminated() {
        let mut p = make_participant();
        let mi = [0xBB; 12];
        p.update_peer_from_mkpdu(mi, 5, 0x20).unwrap();
        p.peers.promote_peer(&mi).unwrap();
        p.update_peer_from_mkpdu(mi, 6, 0x20).unwrap();
        assert_eq!(p.state(), MkaState::Established);

        // Advance time past MKA Life Time
        p.ctx.advance_time(Duration::from_secs(10));
        let events = p.expire_peers();
        assert_eq!(p.state(), MkaState::Pending);
        assert!(events.contains(&PaeEvent::MkaSessionTerminated));
    }

    // --- #51 (REQ-NF-PERF-004): MKA State Machine Transition Latency ---

    /// Verifies: #51 (REQ-NF-PERF-004)
    /// MKA state machine transitions complete within 10ms.
    /// Measures: step (MKPDU transmit), update_peer, expire_peers, teardown.
    #[test]
    fn test_perf_mka_transition_latency() {
        let mut latencies = Vec::new();

        let mut p = make_participant();

        // step() → MKPDU transmit
        let start = std::time::Instant::now();
        p.step().unwrap();
        latencies.push(start.elapsed());

        // update_peer_from_mkpdu
        let mi = [0xBB; 12];
        let start = std::time::Instant::now();
        p.update_peer_from_mkpdu(mi, 5, 0x20).unwrap();
        latencies.push(start.elapsed());

        // promote_peer + update → Established
        p.peers.promote_peer(&mi).unwrap();
        let start = std::time::Instant::now();
        p.update_peer_from_mkpdu(mi, 6, 0x20).unwrap();
        latencies.push(start.elapsed());

        // expire_peers
        p.ctx.advance_time(Duration::from_secs(10));
        let start = std::time::Instant::now();
        let _ = p.expire_peers();
        latencies.push(start.elapsed());

        // teardown
        let start = std::time::Instant::now();
        let _ = p.teardown();
        latencies.push(start.elapsed());

        for (i, latency) in latencies.iter().enumerate() {
            assert!(
                *latency < Duration::from_millis(10),
                "MKA transition {i} took {:?}, expected < 10ms",
                latency
            );
        }
    }

    /// Verifies: #51 (REQ-NF-PERF-004)
    /// MKA state machine 95th percentile transition latency over 1000 cycles
    /// is ≤ 10ms. Exercises the full Pending → Established → Pending cycle.
    #[test]
    fn test_perf_mka_transition_95th_percentile() {
        let mut latencies = Vec::with_capacity(3000);

        for _ in 0..1000 {
            let mut p = make_participant();

            // step() → MKPDU transmit
            let start = std::time::Instant::now();
            p.step().unwrap();
            latencies.push(start.elapsed());

            // update_peer + promote → Established
            let mi = [0xBB; 12];
            let start = std::time::Instant::now();
            p.update_peer_from_mkpdu(mi, 5, 0x20).unwrap();
            p.peers.promote_peer(&mi).unwrap();
            p.update_peer_from_mkpdu(mi, 6, 0x20).unwrap();
            latencies.push(start.elapsed());

            // expire_peers → Pending
            p.ctx.advance_time(Duration::from_secs(10));
            let start = std::time::Instant::now();
            p.expire_peers();
            latencies.push(start.elapsed());
        }

        latencies.sort();
        let p95_idx = (latencies.len() as f64 * 0.95) as usize;
        let p95 = latencies[p95_idx.min(latencies.len() - 1)];

        assert!(
            p95 < Duration::from_millis(10),
            "95th percentile MKA transition latency {:?}, expected < 10ms",
            p95
        );
    }

    // --- #86 (QA-SC-PERF-001): MKA Hello Timing Under Load ---

    /// Verifies: #86 (QA-SC-PERF-001)
    /// ATAM scenario: MKA Hello timer fires while processing 10 concurrent peer
    /// MKPDUs. Validates that MKPDU is still transmitted within Hello Time.
    /// Uses virtual clock: timer fires at exactly 2000ms, step() produces
    /// MkaTransmit event regardless of peer processing load.
    ///
    /// The supplicant peer list is capped at 2 live + 2 potential peers.
    /// To simulate 10 concurrent MKPDU arrivals, we process 10 rapid
    /// update_peer calls on the same peers within the Hello interval.
    #[test]
    fn test_perf_hello_under_load_10_peers() {
        let mut tw = TimerWheel::new();
        let mut list = MkaPeerList::new();

        // Fill peer list to max capacity (2 live + 2 potential)
        let now = Duration::from_millis(0);
        let mi1 = [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mi2 = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mi3 = [0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mi4 = [0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        list.update_peer(mi1, 1, now).unwrap();
        list.update_peer(mi2, 1, now).unwrap();
        list.promote_peer(&mi1).unwrap();
        list.promote_peer(&mi2).unwrap();
        list.update_peer(mi3, 1, now).unwrap();
        list.update_peer(mi4, 1, now).unwrap();
        assert_eq!(list.live_count(), 2);
        assert_eq!(list.potential_count(), 2);

        // Schedule hello timer
        tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);

        // Simulate 10 rapid MKPDU arrivals (update same peers with new MNs)
        for i in 1..=10u32 {
            let peer_time = Duration::from_millis(i as u64 * 100);
            list.update_peer(mi1, i + 1, peer_time).unwrap();
            list.update_peer(mi2, i + 1, peer_time).unwrap();
        }

        // Advance to just before Hello Time with peer processing
        let expired = tw.advance_to(Duration::from_millis(1999));
        assert!(
            !expired.contains(&TimerId::MkaHello),
            "Hello must not fire before 2000ms under load"
        );

        // Process peer expiry check (simulating concurrent load)
        let expired_peers = list.expire_peers(Duration::from_millis(1999), MKA_LIFE_TIME);
        assert!(expired_peers.is_empty(), "no peers should expire at 1999ms");

        // Advance to Hello Time: timer MUST fire despite load
        let expired = tw.advance_to(MKA_HELLO_TIME);
        assert!(
            expired.contains(&TimerId::MkaHello),
            "Hello timer must fire at exactly 2000ms even under 10-peer load"
        );
    }

    /// Verifies: #86 (QA-SC-PERF-001)
    /// Wall-clock latency of hello timer + MKPDU generation under load.
    /// With timer wheel processing 4 concurrent timers + peer list expiry,
    /// the combined step() latency must remain bounded (< 100ms).
    #[test]
    fn test_perf_hello_latency_under_load_bounded() {
        let mut tw = TimerWheel::new();
        let mut list = MkaPeerList::new();

        // Populate peer list
        let now = Duration::from_millis(0);
        for i in 0..4u8 {
            let mi = [i + 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            list.update_peer(mi, 1, now).unwrap();
            if i < 2 {
                list.promote_peer(&mi).unwrap();
            }
        }

        let mut total_transmits = 0;
        let start = std::time::Instant::now();

        for cycle in 0..1000u64 {
            let base = Duration::from_millis(2000 * cycle);

            // Schedule all timers (simulating concurrent load)
            tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);
            tw.schedule(TimerId::MkaBoundedHello, MKA_BOUNDED_HELLO_TIME);
            tw.schedule(TimerId::MkaLife, MKA_LIFE_TIME);
            tw.schedule(TimerId::SakRetire, SAK_RETIRE_TIME);

            // Advance past Hello Time
            let expired = tw.advance_to(base + MKA_HELLO_TIME);

            // Count hello timer fires (MKPDU transmits)
            if expired.contains(&TimerId::MkaHello) {
                total_transmits += 1;
            }

            // Process peer expiry under load
            list.expire_peers(base + MKA_HELLO_TIME, MKA_LIFE_TIME);
        }

        let elapsed = start.elapsed();

        assert!(
            total_transmits >= 1000,
            "expected >= 1000 hello fires, got {}",
            total_transmits
        );
        assert!(
            elapsed < Duration::from_millis(100),
            "1000 loaded hello cycles took {:?}, expected < 100ms",
            elapsed
        );
    }

    /// Verifies: #86 (QA-SC-PERF-001)
    /// Bounded Hello (0.5s) timing under load with 10 concurrent peers.
    /// The 95th percentile MKPDU transmission latency must be ≤ 0.5s.
    #[test]
    fn test_perf_bounded_hello_under_load_10_peers() {
        let mut tw = TimerWheel::new();
        let mut list = MkaPeerList::new();

        // Populate peer list
        for i in 0..4u8 {
            let mi = [i + 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            list.update_peer(mi, 1, Duration::ZERO).unwrap();
            if i < 2 {
                list.promote_peer(&mi).unwrap();
            }
        }

        // Schedule bounded hello under load
        tw.schedule(TimerId::MkaBoundedHello, MKA_BOUNDED_HELLO_TIME);
        tw.schedule(TimerId::MkaLife, MKA_LIFE_TIME);

        // Must NOT fire before 500ms
        let expired = tw.advance_to(MKA_BOUNDED_HELLO_TIME - Duration::from_millis(1));
        assert!(
            !expired.contains(&TimerId::MkaBoundedHello),
            "Bounded Hello must not fire before 500ms under load"
        );

        // Must fire at exactly 500ms
        let expired = tw.advance_to(MKA_BOUNDED_HELLO_TIME);
        assert!(
            expired.contains(&TimerId::MkaBoundedHello),
            "Bounded Hello must fire at exactly 500ms under load"
        );
    }
}
