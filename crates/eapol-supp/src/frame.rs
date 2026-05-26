//! EAPOL frame types and parsing per IEEE 802.1X-2020, Clause 11.
//!
//! Implements: #44 (REQ-F-EAPOL-001: EAPOL Frame Encoding and Decoding)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use crate::EapolError;

/// EAPOL protocol version.
///
/// Per IEEE 802.1X-2020, Clause 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolVersion {
    /// 802.1X-2001 (version 1).
    V1 = 1,
    /// 802.1X-2004 (version 2).
    V2 = 2,
    /// 802.1X-2010 (version 3).
    V3 = 3,
}

impl EapolVersion {
    /// Convert to u8.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// EAPOL packet type.
///
/// Per IEEE 802.1X-2020, Clause 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolPacketType {
    /// EAP Packet (0x00).
    EapPacket,
    /// EAPOL-Start (0x01).
    EapolStart,
    /// EAPOL-Logoff (0x02).
    EapolLogoff,
    /// EAPOL-Key (0x03).
    EapolKey,
    /// EAPOL-Encapsulated-ASF-Alert (0x04).
    AsfAlert,
    /// EAPOL-MKA (0x05).
    EapolMka,
    /// EAPOL-Announcement (0x06).
    EapolAnnouncement,
    /// EAPOL-Announcement-Req (0x07).
    EapolAnnouncementReq,
}

impl EapolPacketType {
    /// Convert to u8.
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::EapPacket => 0x00,
            Self::EapolStart => 0x01,
            Self::EapolLogoff => 0x02,
            Self::EapolKey => 0x03,
            Self::AsfAlert => 0x04,
            Self::EapolMka => 0x05,
            Self::EapolAnnouncement => 0x06,
            Self::EapolAnnouncementReq => 0x07,
        }
    }

    /// Create from u8 value.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidFrame` for unknown packet type values.
    pub fn from_u8(value: u8) -> Result<Self, EapolError> {
        match value {
            0x00 => Ok(Self::EapPacket),
            0x01 => Ok(Self::EapolStart),
            0x02 => Ok(Self::EapolLogoff),
            0x03 => Ok(Self::EapolKey),
            0x04 => Ok(Self::AsfAlert),
            0x05 => Ok(Self::EapolMka),
            0x06 => Ok(Self::EapolAnnouncement),
            0x07 => Ok(Self::EapolAnnouncementReq),
            _ => Err(EapolError::InvalidFrame(format!(
                "unknown EAPOL packet type: 0x{:02x}",
                value
            ))),
        }
    }
}

/// EAPOL frame — Value Object for frame encoding/decoding.
///
/// Per IEEE 802.1X-2020, Clause 11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolFrame {
    /// Protocol version.
    pub version: EapolVersion,
    /// Packet type.
    pub packet_type: EapolPacketType,
    /// Frame body (payload after EAPOL header).
    pub body: Vec<u8>,
}

impl EapolFrame {
    /// EAPOL header size: version(1) + type(1) + length(2) = 4 bytes.
    pub const HEADER_SIZE: usize = 4;

    /// Maximum EAPOL frame body size per Cl.11.
    pub const MAX_BODY_SIZE: usize = 1500;

    /// Default EAPOL version for 802.1X-2020.
    pub const DEFAULT_VERSION: EapolVersion = EapolVersion::V3;

    /// Encode the frame to bytes for transmission. Per Cl.11.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidFrame` if body exceeds MAX_BODY_SIZE.
    pub fn encode(&self) -> Result<Vec<u8>, EapolError> {
        if self.body.len() > Self::MAX_BODY_SIZE {
            return Err(EapolError::InvalidFrame(format!(
                "body too large: {} > {}",
                self.body.len(),
                Self::MAX_BODY_SIZE
            )));
        }
        let body_len = self.body.len() as u16;
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.body.len());
        buf.push(self.version.as_u8());
        buf.push(self.packet_type.as_u8());
        buf.extend_from_slice(&body_len.to_be_bytes());
        buf.extend_from_slice(&self.body);
        Ok(buf)
    }

    /// Decode a frame from raw bytes. Per Cl.11.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidFrame` on malformed input.
    pub fn decode(bytes: &[u8]) -> Result<Self, EapolError> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(EapolError::InvalidFrame(format!(
                "frame too short: {} < {}",
                bytes.len(),
                Self::HEADER_SIZE
            )));
        }
        let version = match bytes[0] {
            1 => EapolVersion::V1,
            2 => EapolVersion::V2,
            3 => EapolVersion::V3,
            v => {
                return Err(EapolError::InvalidFrame(format!(
                    "unknown EAPOL version: {}",
                    v
                )))
            }
        };
        let packet_type = EapolPacketType::from_u8(bytes[1])?;
        let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if body_len > Self::MAX_BODY_SIZE {
            return Err(EapolError::InvalidFrame(format!(
                "body too large: {} > {}",
                body_len,
                Self::MAX_BODY_SIZE
            )));
        }
        let expected_len = Self::HEADER_SIZE + body_len;
        if bytes.len() < expected_len {
            return Err(EapolError::InvalidFrame(format!(
                "frame truncated: have {} bytes, need {}",
                bytes.len(),
                expected_len
            )));
        }
        let body = bytes[Self::HEADER_SIZE..expected_len].to_vec();
        Ok(Self {
            version,
            packet_type,
            body,
        })
    }

    /// Create an EAPOL-Start frame. Per Cl.11.
    pub fn start() -> Self {
        Self {
            version: Self::DEFAULT_VERSION,
            packet_type: EapolPacketType::EapolStart,
            body: Vec::new(),
        }
    }

    /// Create an EAPOL-Start frame with NID TLV. Per Cl.11.6 and Cl.10.16.
    ///
    /// Implements: #36 (REQ-F-LOGON-004)
    /// The NID TLV contains the selected Network Identifier so the
    /// authenticator knows which network the supplicant wants.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidFrame` if the NID is too long.
    pub fn start_with_nid(nid: &[u8]) -> Result<Self, EapolError> {
        // NID TLV format: type(1) + length(2) + nid_bytes
        if nid.len() > 255 {
            return Err(EapolError::InvalidFrame(format!(
                "NID too long for TLV: {} > 255",
                nid.len()
            )));
        }
        let mut body = Vec::with_capacity(3 + nid.len());
        body.push(0x01); // TLV type: NID Set
        body.extend_from_slice(&(nid.len() as u16).to_be_bytes());
        body.extend_from_slice(nid);
        Ok(Self {
            version: Self::DEFAULT_VERSION,
            packet_type: EapolPacketType::EapolStart,
            body,
        })
    }

    /// Create an EAPOL-Logoff frame. Per Cl.11.
    pub fn logoff() -> Self {
        Self {
            version: Self::DEFAULT_VERSION,
            packet_type: EapolPacketType::EapolLogoff,
            body: Vec::new(),
        }
    }

    /// Create an EAP Packet frame. Per Cl.11.
    pub fn eap_packet(eap_data: Vec<u8>) -> Self {
        Self {
            version: Self::DEFAULT_VERSION,
            packet_type: EapolPacketType::EapPacket,
            body: eap_data,
        }
    }

    /// Create an EAPOL-MKA frame. Per Cl.11.
    pub fn mka(mkpdu: Vec<u8>) -> Self {
        Self {
            version: Self::DEFAULT_VERSION,
            packet_type: EapolPacketType::EapolMka,
            body: mkpdu,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: EAPOL-Start frame encodes correctly.
    #[test]
    fn test_eapol_start_encode() {
        let frame = EapolFrame::start();
        let encoded = frame.encode().unwrap();
        assert_eq!(encoded.len(), EapolFrame::HEADER_SIZE);
        assert_eq!(encoded[0], 3); // version 3
        assert_eq!(encoded[1], 0x01); // EAPOL-Start
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 0); // body length = 0
    }

    /// Verifies: #36 (REQ-F-LOGON-004)
    /// EAPOL-Start with NID TLV encodes the NID in the body.
    #[test]
    fn test_eapol_start_with_nid() {
        let nid = b"test-nid";
        let frame = EapolFrame::start_with_nid(nid).unwrap();
        assert_eq!(frame.packet_type, EapolPacketType::EapolStart);

        // Body should contain: type(1) + length(2) + nid
        assert_eq!(frame.body[0], 0x01); // TLV type: NID Set
        assert_eq!(
            u16::from_be_bytes([frame.body[1], frame.body[2]]),
            8 // "test-nid" length
        );
        assert_eq!(&frame.body[3..], nid);

        // Verify round-trip through encode/decode
        let encoded = frame.encode().unwrap();
        let decoded = EapolFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.packet_type, EapolPacketType::EapolStart);
        assert_eq!(decoded.body, frame.body);
    }

    /// Verifies: #36 (REQ-F-LOGON-004)
    /// EAPOL-Start with NID rejects too-long NID.
    #[test]
    fn test_eapol_start_nid_too_long() {
        let nid = vec![0xAA; 256];
        let result = EapolFrame::start_with_nid(&nid);
        assert!(result.is_err());
    }

    /// Verifies: EAPOL-Logoff frame encodes correctly.
    #[test]
    fn test_eapol_logoff_encode() {
        let frame = EapolFrame::logoff();
        let encoded = frame.encode().unwrap();
        assert_eq!(encoded[1], 0x02); // EAPOL-Logoff
    }

    /// Verifies: EAP Packet frame encodes with body.
    #[test]
    fn test_eap_packet_encode() {
        let data = vec![0x01, 0x00, 0x00, 0x04]; // minimal EAP
        let frame = EapolFrame::eap_packet(data.clone());
        let encoded = frame.encode().unwrap();
        assert_eq!(encoded[1], 0x00); // EAP Packet
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 4);
        assert_eq!(&encoded[4..], &data);
    }

    /// Verifies: Round-trip encode/decode preserves frame.
    #[test]
    fn test_eapol_round_trip() {
        let original = EapolFrame::eap_packet(vec![0xAA, 0xBB]);
        let encoded = original.encode().unwrap();
        let decoded = EapolFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.packet_type, original.packet_type);
        assert_eq!(decoded.body, original.body);
    }

    /// Verifies: Decode rejects too-short frames.
    #[test]
    fn test_eapol_decode_too_short() {
        let result = EapolFrame::decode(&[0x03, 0x01]);
        assert!(result.is_err());
    }

    /// Verifies: Decode rejects unknown packet type.
    #[test]
    fn test_eapol_decode_unknown_type() {
        let result = EapolFrame::decode(&[0x03, 0xFF, 0x00, 0x00]);
        assert!(result.is_err());
    }

    /// Verifies: Packet type from_u8 round-trip.
    #[test]
    fn test_packet_type_from_u8() {
        assert_eq!(
            EapolPacketType::from_u8(0x00).unwrap(),
            EapolPacketType::EapPacket
        );
        assert_eq!(
            EapolPacketType::from_u8(0x05).unwrap(),
            EapolPacketType::EapolMka
        );
        assert!(EapolPacketType::from_u8(0xFF).is_err());
    }
}
