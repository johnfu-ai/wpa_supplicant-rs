//! MKPDU format — encode and decode per IEEE 802.1X-2020, Clause 11.11.
//!
//! Implements: #47 (REQ-F-EAPOL-004: MKPDU Format)
//!
//! MKPDUs are carried in EAPOL-MKA frames and consist of parameter sets
//! in Type-Length-Value (TLV) format. Per Cl.11.11, the Basic Parameter Set
//! must be first, followed by optional parameter sets, and the ICV
//! parameter set must be last.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use crate::mka::{CipherSuite, Ckn, Sci};
use crate::PaeError;

/// MKPDU protocol version per Cl.11.11.
pub const MKPDU_VERSION: u8 = 3;

/// Parameter set type numbers per Cl.11.11.
pub mod param_type {
    /// Basic Parameter Set (always first).
    pub const BASIC: u8 = 1;
    /// Live Peer List.
    pub const LIVE_PEER_LIST: u8 = 2;
    /// Potential Peer List.
    pub const POTENTIAL_PEER_LIST: u8 = 3;
    /// MACsec SAK Use.
    pub const SAK_USE: u8 = 4;
    /// Distribute SAK.
    pub const DISTRIB_SAK: u8 = 5;
    /// ICV (Integrity Check Value) — always last.
    pub const ICV: u8 = 255;
}

/// MKPDU parameter set header size: type(1) + length(2) = 3 bytes.
/// Per Cl.11.11: the length field includes the header.
pub const PARAM_HEADER_SIZE: usize = 4;

/// ICV length (AES-CMAC-128 output).
pub const ICV_LEN: usize = 16;

/// Member Identifier — 12-byte unique ID per MKA participant.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
pub type Mi = [u8; 12];

/// Member Number — monotonically increasing counter per participant.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
pub type Mn = u32;

/// Basic Parameter Set — always the first parameter set in an MKPDU.
///
/// Per IEEE 802.1X-2020, Clause 11.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicParameterSet {
    /// MKA version.
    pub version: u8,
    /// Key Server priority (lower is preferred).
    pub key_server_priority: u8,
    /// MACsec capability: 0=not capable, 1=unspecified, 2=integrity, 3=confidentiality, 4=conf+offset.
    pub macsec_capability: u8,
    /// MACsec desired flag.
    pub macsec_desired: bool,
    /// Secure Channel Identifier.
    pub sci: Sci,
    /// Actor's Member Identifier.
    pub actor_mi: Mi,
    /// Actor's Member Number.
    pub actor_mn: Mn,
    /// Key Server's Member Identifier (for key server election).
    pub key_server_mi: Mi,
    /// CAK Name identifying the CA.
    pub ckn: Ckn,
    /// Cipher suite.
    pub cipher_suite: CipherSuite,
    /// Association Number (0-3) for the current SAK.
    pub an: u8,
}

impl BasicParameterSet {
    /// Encoded size of the fixed portion (before CKN).
    /// version(1) + priority(1) + macsec_cap(1) + macsec_desired(1) +
    /// SCI(8) + actor_mi(12) + actor_mn(4) + key_server_mi(12) + AN(1) + cipher_suite(4) = 45 bytes.
    const FIXED_SIZE: usize = 45;

    /// Encode the Basic Parameter Set to bytes (without TLV header).
    fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.ckn.len());
        buf.push(self.version);
        buf.push(self.key_server_priority);
        buf.push(self.macsec_capability);
        buf.push(if self.macsec_desired { 0x80 } else { 0x00 });
        // SCI: MAC(6) + port(2)
        buf.extend_from_slice(self.sci.mac());
        buf.extend_from_slice(&self.sci.port().to_be_bytes());
        // Actor MI + MN
        buf.extend_from_slice(&self.actor_mi);
        buf.extend_from_slice(&self.actor_mn.to_be_bytes());
        // Key Server MI
        buf.extend_from_slice(&self.key_server_mi);
        // AN (in lower 2 bits of a byte, rest reserved)
        buf.push(self.an & 0x03);
        // Cipher suite identifier
        buf.extend_from_slice(&cipher_suite_to_bytes(self.cipher_suite));
        // CKN
        buf.extend_from_slice(self.ckn.as_bytes());
        buf
    }

    /// Decode the Basic Parameter Set from body bytes.
    fn decode_body(bytes: &[u8]) -> Result<Self, PaeError> {
        // FIXED_SIZE(45) + minimum CKN(1) = 46
        if bytes.len() < Self::FIXED_SIZE + 1 {
            return Err(PaeError::InvalidMkpdu(format!(
                "BPS too short: {} < {}",
                bytes.len(),
                Self::FIXED_SIZE + 1
            )));
        }
        let version = bytes[0];
        if version > MKPDU_VERSION {
            return Err(PaeError::InvalidMkpdu(format!(
                "unsupported MKPDU version: {}",
                version
            )));
        }
        let key_server_priority = bytes[1];
        let macsec_capability = bytes[2];
        if macsec_capability > 4 {
            return Err(PaeError::InvalidMkpdu(format!(
                "invalid macsec_capability: {}",
                macsec_capability
            )));
        }
        let macsec_desired = (bytes[3] & 0x80) != 0;
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&bytes[4..10]);
        let port = u16::from_be_bytes([bytes[10], bytes[11]]);
        let sci = Sci::new(mac, port);
        let mut actor_mi = [0u8; 12];
        actor_mi.copy_from_slice(&bytes[12..24]);
        let actor_mn = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let mut key_server_mi = [0u8; 12];
        key_server_mi.copy_from_slice(&bytes[28..40]);
        let an = bytes[40] & 0x03;
        let cipher_suite = bytes_to_cipher_suite(&bytes[41..45])?;
        let ckn = Ckn::from_bytes(bytes[45..].to_vec())?;
        Ok(Self {
            version,
            key_server_priority,
            macsec_capability,
            macsec_desired,
            sci,
            actor_mi,
            actor_mn,
            key_server_mi,
            ckn,
            cipher_suite,
            an,
        })
    }
}

/// Peer list entry — MI + MN pair.
///
/// Per Cl.11.11: each peer in a Live or Potential Peer List is MI(12) + MN(4) = 16 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// Member Identifier.
    pub mi: Mi,
    /// Member Number.
    pub mn: Mn,
}

impl PeerEntry {
    /// Encoded size: MI(12) + MN(4) = 16 bytes.
    pub const ENCODED_SIZE: usize = 16;

    /// Encode to bytes.
    pub fn encode(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[..12].copy_from_slice(&self.mi);
        buf[12..16].copy_from_slice(&self.mn.to_be_bytes());
        buf
    }

    /// Decode from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PaeError> {
        if bytes.len() < Self::ENCODED_SIZE {
            return Err(PaeError::InvalidMkpdu(format!(
                "peer entry too short: {} < {}",
                bytes.len(),
                Self::ENCODED_SIZE
            )));
        }
        let mut mi = [0u8; 12];
        mi.copy_from_slice(&bytes[..12]);
        let mn = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        Ok(Self { mi, mn })
    }
}

/// SAK Use Parameter Set — indicates current SAK usage.
///
/// Per IEEE 802.1X-2020, Clause 11.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SakUseParameterSet {
    /// Latest key AN (0-3).
    pub latest_an: u8,
    /// Latest key TX flag.
    pub latest_tx: bool,
    /// Latest key RX flag.
    pub latest_rx: bool,
    /// Old key AN (0-3).
    pub old_an: u8,
    /// Old key TX flag.
    pub old_tx: bool,
    /// Old key RX flag.
    pub old_rx: bool,
    /// Plain TX flag.
    pub plain_tx: bool,
    /// Plain RX flag.
    pub plain_rx: bool,
}

impl SakUseParameterSet {
    /// Encoded body size: 8 bytes (per Cl.11.11).
    const BODY_SIZE: usize = 8;

    /// Encode body to bytes.
    fn encode_body(&self) -> [u8; Self::BODY_SIZE] {
        let mut buf = [0u8; Self::BODY_SIZE];
        // Byte 0: latest AN[1:0] | latest_tx | latest_rx | old AN[1:0] | old_tx | old_rx
        buf[0] = (self.latest_an & 0x03) << 6
            | (self.latest_tx as u8) << 5
            | (self.latest_rx as u8) << 4
            | (self.old_an & 0x03) << 2
            | (self.old_tx as u8) << 1
            | (self.old_rx as u8);
        // Byte 1: plain_tx | plain_rx | reserved
        buf[1] = (self.plain_tx as u8) << 7 | (self.plain_rx as u8) << 6;
        buf
    }

    /// Decode body from bytes.
    fn decode_body(bytes: &[u8]) -> Result<Self, PaeError> {
        if bytes.len() < Self::BODY_SIZE {
            return Err(PaeError::InvalidMkpdu(format!(
                "SAK Use body too short: {} < {}",
                bytes.len(),
                Self::BODY_SIZE
            )));
        }
        let latest_an = (bytes[0] >> 6) & 0x03;
        let latest_tx = (bytes[0] & 0x20) != 0;
        let latest_rx = (bytes[0] & 0x10) != 0;
        let old_an = (bytes[0] >> 2) & 0x03;
        let old_tx = (bytes[0] & 0x02) != 0;
        let old_rx = (bytes[0] & 0x01) != 0;
        let plain_tx = (bytes[1] & 0x80) != 0;
        let plain_rx = (bytes[1] & 0x40) != 0;
        Ok(Self {
            latest_an,
            latest_tx,
            latest_rx,
            old_an,
            old_tx,
            old_rx,
            plain_tx,
            plain_rx,
        })
    }
}

/// Distribute SAK Parameter Set — carries a wrapped SAK from Key Server.
///
/// Per IEEE 802.1X-2020, Clause 11.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistribSakParameterSet {
    /// Association Number (0-3) for the distributed SAK.
    pub an: u8,
    /// Whether to use the distributed SAK as the latest key.
    pub use_latest: bool,
    /// Cipher suite for the distributed SAK.
    pub cipher_suite: CipherSuite,
    /// Wrapped SAK data (AES Key Wrap per RFC 3394).
    pub wrapped_sak: Vec<u8>,
}

impl DistribSakParameterSet {
    /// Minimum body size: AN(1) + cipher_suite(4) = 5 bytes (without wrapped SAK).
    const MIN_BODY_SIZE: usize = 5;

    /// Encode body to bytes.
    fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::MIN_BODY_SIZE + self.wrapped_sak.len());
        buf.push((self.an & 0x03) | (self.use_latest as u8) << 2);
        buf.extend_from_slice(&cipher_suite_to_bytes(self.cipher_suite));
        buf.extend_from_slice(&self.wrapped_sak);
        buf
    }

    /// Decode body from bytes.
    fn decode_body(bytes: &[u8]) -> Result<Self, PaeError> {
        if bytes.len() < Self::MIN_BODY_SIZE {
            return Err(PaeError::InvalidMkpdu(format!(
                "DistribSAK body too short: {} < {}",
                bytes.len(),
                Self::MIN_BODY_SIZE
            )));
        }
        let an = bytes[0] & 0x03;
        let use_latest = (bytes[0] & 0x04) != 0;
        let cipher_suite = bytes_to_cipher_suite(&bytes[1..5])?;
        let wrapped_sak = bytes[5..].to_vec();
        Ok(Self {
            an,
            use_latest,
            cipher_suite,
            wrapped_sak,
        })
    }
}

/// A single MKPDU parameter set (TLV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterSet {
    /// Basic Parameter Set (always first).
    Basic(BasicParameterSet),
    /// Live Peer List.
    LivePeerList(Vec<PeerEntry>),
    /// Potential Peer List.
    PotentialPeerList(Vec<PeerEntry>),
    /// SAK Use.
    SakUse(SakUseParameterSet),
    /// Distribute SAK.
    DistribSak(DistribSakParameterSet),
    /// ICV (Integrity Check Value) — always last.
    Icv([u8; ICV_LEN]),
    /// Unknown parameter set (type, body).
    Unknown(u8, Vec<u8>),
}

impl ParameterSet {
    /// Get the parameter set type number.
    pub fn param_type(&self) -> u8 {
        match self {
            Self::Basic(_) => param_type::BASIC,
            Self::LivePeerList(_) => param_type::LIVE_PEER_LIST,
            Self::PotentialPeerList(_) => param_type::POTENTIAL_PEER_LIST,
            Self::SakUse(_) => param_type::SAK_USE,
            Self::DistribSak(_) => param_type::DISTRIB_SAK,
            Self::Icv(_) => param_type::ICV,
            Self::Unknown(t, _) => *t,
        }
    }

    /// Encode this parameter set to bytes (including TLV header).
    pub fn encode(&self) -> Result<Vec<u8>, PaeError> {
        let body = match self {
            Self::Basic(bps) => bps.encode_body(),
            Self::LivePeerList(peers) => {
                let mut buf = Vec::new();
                for peer in peers {
                    buf.extend_from_slice(&peer.encode());
                }
                buf
            }
            Self::PotentialPeerList(peers) => {
                let mut buf = Vec::new();
                for peer in peers {
                    buf.extend_from_slice(&peer.encode());
                }
                buf
            }
            Self::SakUse(su) => su.encode_body().to_vec(),
            Self::DistribSak(ds) => ds.encode_body(),
            Self::Icv(icv) => icv.to_vec(),
            Self::Unknown(_, body) => body.clone(),
        };
        // TLV header: type(1) + body_length(2) + body + padding to 4-byte boundary
        let body_len = body.len();
        let total_len = PARAM_HEADER_SIZE + body_len;
        let padded_len = (total_len + 3) & !3; // round up to 4-byte boundary
        let padding = padded_len - total_len;
        let length_field = u16::try_from(PARAM_HEADER_SIZE + body_len).map_err(|_| {
            PaeError::InvalidMkpdu("parameter set too large for u16 length field".into())
        })?;
        let mut buf = Vec::with_capacity(padded_len);
        buf.push(self.param_type());
        buf.extend_from_slice(&length_field.to_be_bytes());
        // 1 byte reserved (part of 4-byte header)
        buf.push(0);
        buf.extend_from_slice(&body);
        buf.extend(std::iter::repeat(0).take(padding));
        Ok(buf)
    }

    /// Decode a parameter set from bytes. Returns (ParameterSet, bytes_consumed).
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), PaeError> {
        if bytes.len() < PARAM_HEADER_SIZE {
            return Err(PaeError::InvalidMkpdu(format!(
                "param set header too short: {} < {}",
                bytes.len(),
                PARAM_HEADER_SIZE
            )));
        }
        let ptype = bytes[0];
        let length = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if length < PARAM_HEADER_SIZE {
            return Err(PaeError::InvalidMkpdu(format!(
                "param set length too small: {} < {}",
                length, PARAM_HEADER_SIZE
            )));
        }
        let body_len = length - PARAM_HEADER_SIZE;
        if bytes.len() < length {
            return Err(PaeError::InvalidMkpdu(format!(
                "param set truncated: have {}, need {}",
                bytes.len(),
                length
            )));
        }
        let body = &bytes[PARAM_HEADER_SIZE..length];
        // Total consumed: padded to 4-byte boundary
        let consumed = (length + 3) & !3;

        let ps = match ptype {
            param_type::BASIC => Self::Basic(BasicParameterSet::decode_body(body)?),
            param_type::LIVE_PEER_LIST => {
                let peers = decode_peer_list(body)?;
                Self::LivePeerList(peers)
            }
            param_type::POTENTIAL_PEER_LIST => {
                let peers = decode_peer_list(body)?;
                Self::PotentialPeerList(peers)
            }
            param_type::SAK_USE => Self::SakUse(SakUseParameterSet::decode_body(body)?),
            param_type::DISTRIB_SAK => Self::DistribSak(DistribSakParameterSet::decode_body(body)?),
            param_type::ICV => {
                if body_len < ICV_LEN {
                    return Err(PaeError::InvalidMkpdu(format!(
                        "ICV too short: {} < {}",
                        body_len, ICV_LEN
                    )));
                }
                let mut icv = [0u8; ICV_LEN];
                icv.copy_from_slice(&body[..ICV_LEN]);
                Self::Icv(icv)
            }
            _ => Self::Unknown(ptype, body.to_vec()),
        };
        Ok((ps, consumed))
    }
}

/// Decode a peer list from body bytes.
fn decode_peer_list(body: &[u8]) -> Result<Vec<PeerEntry>, PaeError> {
    if body.len() % PeerEntry::ENCODED_SIZE != 0 {
        return Err(PaeError::InvalidMkpdu(format!(
            "peer list body not multiple of {}: got {}",
            PeerEntry::ENCODED_SIZE,
            body.len()
        )));
    }
    let count = body.len() / PeerEntry::ENCODED_SIZE;
    let mut peers = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * PeerEntry::ENCODED_SIZE;
        peers.push(PeerEntry::decode(&body[offset..])?);
    }
    Ok(peers)
}

/// MKPDU — the complete MKA Protocol Data Unit.
///
/// Per IEEE 802.1X-2020, Clause 11.11.
/// An MKPDU consists of a Basic Parameter Set followed by zero or more
/// optional parameter sets, with an ICV parameter set at the end.
///
/// Implements: #47 (REQ-F-EAPOL-004: MKPDU Format)
#[derive(Debug, Clone)]
pub struct Mkpdu {
    /// Parameter sets in order. Basic is always first, ICV always last.
    parameter_sets: Vec<ParameterSet>,
}

impl Mkpdu {
    /// Create a new MKPDU from parameter sets.
    ///
    /// # Errors
    /// Returns `PaeError::InvalidMkpdu` if:
    /// - The first parameter set is not Basic
    /// - ICV is present but not the last parameter set
    /// - Duplicate parameter sets found (Basic, SAK Use, DistribSAK, ICV)
    pub fn new(parameter_sets: Vec<ParameterSet>) -> Result<Self, PaeError> {
        if parameter_sets.is_empty() {
            return Err(PaeError::InvalidMkpdu(
                "MKPDU must have at least a Basic Parameter Set".into(),
            ));
        }
        if parameter_sets[0].param_type() != param_type::BASIC {
            return Err(PaeError::InvalidMkpdu(
                "first parameter set must be Basic".into(),
            ));
        }
        // Per Cl.11.11: ICV must be the last parameter set
        let icv_positions: Vec<usize> = parameter_sets
            .iter()
            .enumerate()
            .filter(|(_, ps)| ps.param_type() == param_type::ICV)
            .map(|(i, _)| i)
            .collect();
        if !icv_positions.is_empty()
            && icv_positions[icv_positions.len() - 1] != parameter_sets.len() - 1
        {
            return Err(PaeError::InvalidMkpdu(
                "ICV must be the last parameter set".into(),
            ));
        }
        // Check for duplicates of singleton parameter sets
        let mut seen = std::collections::HashSet::new();
        let singletons = [
            param_type::BASIC,
            param_type::SAK_USE,
            param_type::DISTRIB_SAK,
            param_type::ICV,
        ];
        for ps in &parameter_sets {
            let pt = ps.param_type();
            if singletons.contains(&pt) && !seen.insert(pt) {
                return Err(PaeError::InvalidMkpdu(format!(
                    "duplicate parameter set type: {}",
                    pt
                )));
            }
        }
        Ok(Self { parameter_sets })
    }

    /// Get the Basic Parameter Set.
    ///
    /// # Panics
    /// Never panics in practice — enforced by `Mkpdu::new()`.
    pub fn basic(&self) -> &BasicParameterSet {
        match &self.parameter_sets[0] {
            ParameterSet::Basic(bps) => bps,
            // SAFETY: Mkpdu::new() enforces first parameter set is Basic
            _ => unreachable!(),
        }
    }

    /// Get the ICV if present.
    pub fn icv(&self) -> Option<&[u8; ICV_LEN]> {
        self.parameter_sets.iter().find_map(|ps| match ps {
            ParameterSet::Icv(icv) => Some(icv),
            _ => None,
        })
    }

    /// Verify the ICV against a computed value.
    ///
    /// Per Cl.11.11: the ICV covers all parameter sets except the ICV itself.
    /// The caller must compute the expected ICV using the ICK and pass it here.
    /// Uses constant-time comparison to prevent timing side-channel attacks.
    ///
    /// # Errors
    /// Returns `PaeError::IcvFailed` if the MKPDU has no ICV or verification fails.
    pub fn verify_icv(&self, expected_icv: &[u8; ICV_LEN]) -> Result<(), PaeError> {
        match self.icv() {
            Some(received) => {
                // Constant-time comparison to prevent timing attacks
                let mut diff = 0u8;
                for (a, b) in received.iter().zip(expected_icv.iter()) {
                    diff |= a ^ b;
                }
                if diff == 0 {
                    Ok(())
                } else {
                    Err(PaeError::IcvFailed)
                }
            }
            None => Err(PaeError::InvalidMkpdu("MKPDU has no ICV".into())),
        }
    }

    /// Encode all parameter sets except the ICV (for ICV computation).
    ///
    /// The caller uses this to compute the AES-CMAC over the MKPDU content,
    /// then passes the result to `verify_icv()`.
    pub fn encode_without_icv(&self) -> Result<Vec<u8>, PaeError> {
        let mut buf = Vec::new();
        for ps in &self.parameter_sets {
            if ps.param_type() == param_type::ICV {
                continue;
            }
            buf.extend_from_slice(&ps.encode()?);
        }
        Ok(buf)
    }

    /// Get all parameter sets.
    pub fn parameter_sets(&self) -> &[ParameterSet] {
        &self.parameter_sets
    }

    /// Encode the MKPDU to bytes for transmission in an EAPOL-MKA frame.
    pub fn encode(&self) -> Result<Vec<u8>, PaeError> {
        let mut buf = Vec::new();
        for ps in &self.parameter_sets {
            buf.extend_from_slice(&ps.encode()?);
        }
        Ok(buf)
    }

    /// Decode an MKPDU from bytes (the body of an EAPOL-MKA frame).
    pub fn decode(bytes: &[u8]) -> Result<Self, PaeError> {
        if bytes.is_empty() {
            return Err(PaeError::InvalidMkpdu("empty MKPDU".into()));
        }
        let mut parameter_sets = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let (ps, consumed) = ParameterSet::decode(&bytes[offset..])?;
            parameter_sets.push(ps);
            offset += consumed;
        }
        Self::new(parameter_sets)
    }
}

/// Convert CipherSuite to 4-byte identifier per Cl.11.11.
fn cipher_suite_to_bytes(suite: CipherSuite) -> [u8; 4] {
    match suite {
        // Standard MACsec cipher suite OUI-based identifiers
        CipherSuite::GcmAes128 => [0x00, 0x80, 0x02, 0x01],
        CipherSuite::GcmAes256 => [0x00, 0x80, 0x02, 0x02],
        CipherSuite::GcmAesXpn256 => [0x00, 0x80, 0x02, 0x03],
        CipherSuite::Null => [0x00, 0x00, 0x00, 0x00],
    }
}

/// Convert 4-byte identifier to CipherSuite per Cl.11.11.
fn bytes_to_cipher_suite(bytes: &[u8]) -> Result<CipherSuite, PaeError> {
    if bytes.len() < 4 {
        return Err(PaeError::InvalidMkpdu(format!(
            "cipher suite too short: {} < 4",
            bytes.len()
        )));
    }
    match bytes {
        [0x00, 0x80, 0x02, 0x01] => Ok(CipherSuite::GcmAes128),
        [0x00, 0x80, 0x02, 0x02] => Ok(CipherSuite::GcmAes256),
        [0x00, 0x80, 0x02, 0x03] => Ok(CipherSuite::GcmAesXpn256),
        [0x00, 0x00, 0x00, 0x00] => Ok(CipherSuite::Null),
        _ => Err(PaeError::InvalidMkpdu(format!(
            "unknown cipher suite: {:02x?}",
            &bytes[..4]
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sci() -> Sci {
        Sci::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 1)
    }

    fn test_mi() -> Mi {
        [0xAA; 12]
    }

    fn test_ckn() -> Ckn {
        Ckn::from_bytes(vec![0x0B; 16]).unwrap()
    }

    fn test_bps() -> BasicParameterSet {
        BasicParameterSet {
            version: MKPDU_VERSION,
            key_server_priority: 0x10,
            macsec_capability: 3,
            macsec_desired: true,
            sci: test_sci(),
            actor_mi: test_mi(),
            actor_mn: 42,
            key_server_mi: test_mi(),
            ckn: test_ckn(),
            cipher_suite: CipherSuite::GcmAes128,
            an: 0,
        }
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// Basic Parameter Set encode/decode round-trip.
    #[test]
    fn test_bps_round_trip() {
        let bps = test_bps();
        let body = bps.encode_body();
        let decoded = BasicParameterSet::decode_body(&body).unwrap();
        assert_eq!(decoded.version, bps.version);
        assert_eq!(decoded.key_server_priority, bps.key_server_priority);
        assert_eq!(decoded.macsec_capability, bps.macsec_capability);
        assert_eq!(decoded.macsec_desired, bps.macsec_desired);
        assert_eq!(decoded.sci, bps.sci);
        assert_eq!(decoded.actor_mi, bps.actor_mi);
        assert_eq!(decoded.actor_mn, bps.actor_mn);
        assert_eq!(decoded.key_server_mi, bps.key_server_mi);
        assert_eq!(decoded.ckn.as_bytes(), bps.ckn.as_bytes());
        assert_eq!(decoded.cipher_suite, bps.cipher_suite);
        assert_eq!(decoded.an, bps.an);
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// Peer entry encode/decode round-trip.
    #[test]
    fn test_peer_entry_round_trip() {
        let entry = PeerEntry {
            mi: [0xBB; 12],
            mn: 100,
        };
        let encoded = entry.encode();
        let decoded = PeerEntry::decode(&encoded).unwrap();
        assert_eq!(decoded.mi, entry.mi);
        assert_eq!(decoded.mn, entry.mn);
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// Peer list encode/decode.
    #[test]
    fn test_peer_list_decode() {
        let mut body = Vec::new();
        let peer1 = PeerEntry {
            mi: [0x01; 12],
            mn: 1,
        };
        let peer2 = PeerEntry {
            mi: [0x02; 12],
            mn: 2,
        };
        body.extend_from_slice(&peer1.encode());
        body.extend_from_slice(&peer2.encode());
        let peers = decode_peer_list(&body).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].mi, [0x01; 12]);
        assert_eq!(peers[0].mn, 1);
        assert_eq!(peers[1].mi, [0x02; 12]);
        assert_eq!(peers[1].mn, 2);
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// SAK Use parameter set encode/decode round-trip.
    #[test]
    fn test_sak_use_round_trip() {
        let su = SakUseParameterSet {
            latest_an: 1,
            latest_tx: true,
            latest_rx: true,
            old_an: 0,
            old_tx: false,
            old_rx: true,
            plain_tx: false,
            plain_rx: false,
        };
        let body = su.encode_body();
        let decoded = SakUseParameterSet::decode_body(&body).unwrap();
        assert_eq!(decoded.latest_an, su.latest_an);
        assert_eq!(decoded.latest_tx, su.latest_tx);
        assert_eq!(decoded.latest_rx, su.latest_rx);
        assert_eq!(decoded.old_an, su.old_an);
        assert_eq!(decoded.old_tx, su.old_tx);
        assert_eq!(decoded.old_rx, su.old_rx);
        assert_eq!(decoded.plain_tx, su.plain_tx);
        assert_eq!(decoded.plain_rx, su.plain_rx);
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// DistribSAK parameter set encode/decode round-trip.
    #[test]
    fn test_distrib_sak_round_trip() {
        let ds = DistribSakParameterSet {
            an: 2,
            use_latest: true,
            cipher_suite: CipherSuite::GcmAes256,
            wrapped_sak: vec![0xCC; 24],
        };
        let body = ds.encode_body();
        let decoded = DistribSakParameterSet::decode_body(&body).unwrap();
        assert_eq!(decoded.an, ds.an);
        assert_eq!(decoded.use_latest, ds.use_latest);
        assert_eq!(decoded.cipher_suite, ds.cipher_suite);
        assert_eq!(decoded.wrapped_sak, ds.wrapped_sak);
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// Cipher suite to/from bytes round-trip.
    #[test]
    fn test_cipher_suite_bytes_round_trip() {
        for suite in [
            CipherSuite::GcmAes128,
            CipherSuite::GcmAes256,
            CipherSuite::GcmAesXpn256,
            CipherSuite::Null,
        ] {
            let bytes = cipher_suite_to_bytes(suite);
            let decoded = bytes_to_cipher_suite(&bytes).unwrap();
            assert_eq!(decoded, suite);
        }
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// Unknown cipher suite bytes returns error.
    #[test]
    fn test_unknown_cipher_suite_error() {
        let result = bytes_to_cipher_suite(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// ParameterSet encode/decode round-trip for Basic.
    #[test]
    fn test_param_set_basic_round_trip() {
        let bps = test_bps();
        let ps = ParameterSet::Basic(bps.clone());
        let encoded = ps.encode().unwrap();
        let (decoded, consumed) = ParameterSet::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.param_type(), param_type::BASIC);
        if let ParameterSet::Basic(d) = decoded {
            assert_eq!(d.version, bps.version);
            assert_eq!(d.key_server_priority, bps.key_server_priority);
            assert_eq!(d.ckn.as_bytes(), bps.ckn.as_bytes());
        } else {
            panic!("expected Basic");
        }
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// ParameterSet encode/decode for Live Peer List.
    #[test]
    fn test_param_set_live_peer_list_round_trip() {
        let peers = vec![
            PeerEntry {
                mi: [0x01; 12],
                mn: 1,
            },
            PeerEntry {
                mi: [0x02; 12],
                mn: 2,
            },
        ];
        let ps = ParameterSet::LivePeerList(peers.clone());
        let encoded = ps.encode().unwrap();
        let (decoded, _) = ParameterSet::decode(&encoded).unwrap();
        if let ParameterSet::LivePeerList(d) = decoded {
            assert_eq!(d.len(), 2);
            assert_eq!(d[0].mi, peers[0].mi);
            assert_eq!(d[0].mn, peers[0].mn);
        } else {
            panic!("expected LivePeerList");
        }
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// ParameterSet encode/decode for ICV.
    #[test]
    fn test_param_set_icv_round_trip() {
        let icv = [0xDD; ICV_LEN];
        let ps = ParameterSet::Icv(icv);
        let encoded = ps.encode().unwrap();
        let (decoded, _) = ParameterSet::decode(&encoded).unwrap();
        if let ParameterSet::Icv(d) = decoded {
            assert_eq!(d, icv);
        } else {
            panic!("expected Icv");
        }
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// Full MKPDU encode/decode round-trip.
    #[test]
    fn test_mkpdu_round_trip() {
        let bps = test_bps();
        let peers = vec![PeerEntry {
            mi: [0x01; 12],
            mn: 1,
        }];
        let icv = [0xEE; ICV_LEN];
        let mkpdu = Mkpdu::new(vec![
            ParameterSet::Basic(bps),
            ParameterSet::LivePeerList(peers),
            ParameterSet::Icv(icv),
        ])
        .unwrap();

        let encoded = mkpdu.encode().unwrap();
        let decoded = Mkpdu::decode(&encoded).unwrap();

        assert_eq!(decoded.basic().version, MKPDU_VERSION);
        assert_eq!(decoded.basic().key_server_priority, 0x10);
        assert_eq!(decoded.basic().ckn.as_bytes(), test_ckn().as_bytes());
        assert_eq!(decoded.parameter_sets().len(), 3);
        assert_eq!(decoded.icv(), Some(&[0xEE; ICV_LEN]));
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// MKPDU with all parameter set types.
    #[test]
    fn test_mkpdu_all_param_types() {
        let bps = test_bps();
        let live = vec![PeerEntry {
            mi: [0x01; 12],
            mn: 1,
        }];
        let potential = vec![PeerEntry {
            mi: [0x02; 12],
            mn: 2,
        }];
        let sak_use = SakUseParameterSet {
            latest_an: 0,
            latest_tx: true,
            latest_rx: true,
            old_an: 0,
            old_tx: false,
            old_rx: false,
            plain_tx: false,
            plain_rx: false,
        };
        let distrib = DistribSakParameterSet {
            an: 1,
            use_latest: false,
            cipher_suite: CipherSuite::GcmAes128,
            wrapped_sak: vec![0xAB; 24],
        };
        let icv = [0xFF; ICV_LEN];

        let mkpdu = Mkpdu::new(vec![
            ParameterSet::Basic(bps),
            ParameterSet::LivePeerList(live),
            ParameterSet::PotentialPeerList(potential),
            ParameterSet::SakUse(sak_use),
            ParameterSet::DistribSak(distrib),
            ParameterSet::Icv(icv),
        ])
        .unwrap();

        let encoded = mkpdu.encode().unwrap();
        let decoded = Mkpdu::decode(&encoded).unwrap();
        assert_eq!(decoded.parameter_sets().len(), 6);
        assert_eq!(decoded.parameter_sets()[0].param_type(), param_type::BASIC);
        assert_eq!(
            decoded.parameter_sets()[1].param_type(),
            param_type::LIVE_PEER_LIST
        );
        assert_eq!(
            decoded.parameter_sets()[2].param_type(),
            param_type::POTENTIAL_PEER_LIST
        );
        assert_eq!(
            decoded.parameter_sets()[3].param_type(),
            param_type::SAK_USE
        );
        assert_eq!(
            decoded.parameter_sets()[4].param_type(),
            param_type::DISTRIB_SAK
        );
        assert_eq!(decoded.parameter_sets()[5].param_type(), param_type::ICV);
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// MKPDU rejects empty parameter sets.
    #[test]
    fn test_mkpdu_rejects_empty() {
        let result = Mkpdu::new(vec![]);
        assert!(result.is_err());
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// MKPDU rejects parameter sets where first is not Basic.
    #[test]
    fn test_mkpdu_rejects_non_basic_first() {
        let icv = [0x00; ICV_LEN];
        let result = Mkpdu::new(vec![ParameterSet::Icv(icv)]);
        assert!(result.is_err());
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// MKPDU decode rejects empty bytes.
    #[test]
    fn test_mkpdu_decode_empty() {
        let result = Mkpdu::decode(&[]);
        assert!(result.is_err());
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// BPS decode rejects too-short body.
    #[test]
    fn test_bps_decode_too_short() {
        let result = BasicParameterSet::decode_body(&[0x00; 10]);
        assert!(result.is_err());
    }

    /// Verifies: #47 (REQ-F-EAPOL-004)
    /// ParameterSet decode rejects truncated header.
    #[test]
    fn test_param_set_decode_truncated_header() {
        let result = ParameterSet::decode(&[0x01, 0x00]);
        assert!(result.is_err());
    }
}
