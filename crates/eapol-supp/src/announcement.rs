//! EAPOL-Announcement parsing per IEEE 802.1X-2020, Clauses 10.3 and 11.12.
//!
//! Implements: #35 (REQ-F-LOGON-003: EAPOL-Announcement Reception)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use crate::EapolError;

/// Access status advertised in an EAPOL-Announcement.
///
/// Per IEEE 802.1X-2020, Clause 10.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessStatus {
    /// Authenticator requires authentication.
    AuthenticationRequired,
    /// Authentication in progress.
    Authenticating,
    /// Authentication succeeded.
    Authenticated,
    /// Authentication failed.
    AuthenticationFailed,
    /// Unknown status value.
    Unknown(u8),
}

impl AccessStatus {
    /// Create from u8 value.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::AuthenticationRequired,
            1 => Self::Authenticating,
            2 => Self::Authenticated,
            3 => Self::AuthenticationFailed,
            _ => Self::Unknown(value),
        }
    }
}

/// A single NID advertised in an EAPOL-Announcement NID Set TLV.
///
/// Per IEEE 802.1X-2020, Clause 10.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementNidEntry {
    /// NID identifier bytes.
    pub id: Vec<u8>,
    /// Whether PSK is supported for this NID.
    pub supports_psk: bool,
}

/// EAPOL-Announcement — parsed from frame body.
///
/// Per IEEE 802.1X-2020, Clauses 10.3 and 11.12.
/// Contains NID Set TLVs and access status information.
#[derive(Debug, Clone)]
pub struct EapolAnnouncement {
    /// Access status from the announcement.
    pub access_status: AccessStatus,
    /// NID entries from NID Set TLVs.
    pub nids: Vec<AnnouncementNidEntry>,
}

impl EapolAnnouncement {
    /// Minimum announcement body size: access_status(1).
    const MIN_BODY_SIZE: usize = 1;

    /// NID Set TLV type identifier.
    const NID_SET_TLV_TYPE: u8 = 1;

    /// Parse an EAPOL-Announcement from the raw frame body.
    ///
    /// Per IEEE 802.1X-2020, Clauses 10.3 and 11.12.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidFrame` if the body is malformed.
    pub fn parse(body: &[u8]) -> Result<Self, EapolError> {
        if body.len() < Self::MIN_BODY_SIZE {
            return Err(EapolError::InvalidFrame(format!(
                "announcement body too short: {} < {}",
                body.len(),
                Self::MIN_BODY_SIZE
            )));
        }

        let access_status = AccessStatus::from_u8(body[0]);

        // Parse TLVs starting at offset 1
        let mut nids = Vec::new();
        let mut offset = 1;
        while offset + 3 <= body.len() {
            let tlv_type = body[offset];
            let tlv_length = u16::from_be_bytes([body[offset + 1], body[offset + 2]]) as usize;
            offset += 3;

            if offset + tlv_length > body.len() {
                return Err(EapolError::InvalidFrame(format!(
                    "TLV at offset {} overflows body (len {})",
                    offset - 3,
                    body.len()
                )));
            }

            if tlv_type == Self::NID_SET_TLV_TYPE {
                let tlv_data = &body[offset..offset + tlv_length];
                Self::parse_nid_set(tlv_data, &mut nids)?;
            }

            offset += tlv_length;
        }

        Ok(Self {
            access_status,
            nids,
        })
    }

    /// Parse a NID Set TLV payload into NID entries.
    ///
    /// Each NID entry: length(1) + id(length bytes) + capabilities(1).
    fn parse_nid_set(
        data: &[u8],
        nids: &mut Vec<AnnouncementNidEntry>,
    ) -> Result<(), EapolError> {
        let mut offset = 0;
        while offset < data.len() {
            if offset + 1 > data.len() {
                break;
            }
            let nid_len = data[offset] as usize;
            offset += 1;

            if offset + nid_len + 1 > data.len() {
                return Err(EapolError::InvalidFrame(format!(
                    "NID entry at offset {} overflows TLV (len {})",
                    offset - 1,
                    data.len()
                )));
            }

            let id = data[offset..offset + nid_len].to_vec();
            offset += nid_len;

            let capabilities = data[offset];
            offset += 1;

            nids.push(AnnouncementNidEntry {
                id,
                supports_psk: (capabilities & 0x01) != 0,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// AC1: NID Set TLVs parsed and access capabilities extracted.
    #[test]
    fn test_parse_announcement_with_nid_set() {
        // access_status=0 (AuthenticationRequired)
        // TLV: type=1 (NID Set), length=4
        //   NID entry: len=2, id=0xAA 0xBB, capabilities=0x01 (PSK)
        let body = vec![
            0x00, // access_status
            0x01, 0x00, 0x04, // TLV type=1, length=4
            0x02, 0xAA, 0xBB, 0x01, // NID: len=2, id=0xAABB, caps=PSK
        ];
        let ann = EapolAnnouncement::parse(&body).unwrap();
        assert_eq!(ann.access_status, AccessStatus::AuthenticationRequired);
        assert_eq!(ann.nids.len(), 1);
        assert_eq!(ann.nids[0].id, vec![0xAA, 0xBB]);
        assert!(ann.nids[0].supports_psk);
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// Multiple NID entries in a single TLV.
    #[test]
    fn test_parse_announcement_multiple_nids() {
        let body = vec![
            0x02, // access_status = Authenticated
            0x01, 0x00, 0x07, // TLV type=1, length=7
            0x02, 0x11, 0x22, 0x00, // NID: len=2, id=0x1122, caps=0
            0x01, 0x33, 0x01, // NID: len=1, id=0x33, caps=PSK
        ];
        let ann = EapolAnnouncement::parse(&body).unwrap();
        assert_eq!(ann.nids.len(), 2);
        assert_eq!(ann.nids[0].id, vec![0x11, 0x22]);
        assert!(!ann.nids[0].supports_psk);
        assert_eq!(ann.nids[1].id, vec![0x33]);
        assert!(ann.nids[1].supports_psk);
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// Announcement with no NID Set TLV.
    #[test]
    fn test_parse_announcement_no_nids() {
        let body = vec![0x01]; // access_status = Authenticating
        let ann = EapolAnnouncement::parse(&body).unwrap();
        assert_eq!(ann.access_status, AccessStatus::Authenticating);
        assert!(ann.nids.is_empty());
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// Truncated body returns error.
    #[test]
    fn test_parse_announcement_too_short() {
        let result = EapolAnnouncement::parse(&[]);
        assert!(result.is_err());
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// TLV overflow returns error.
    #[test]
    fn test_parse_announcement_tlv_overflow() {
        let body = vec![
            0x00,
            0x01, 0x00, 0xFF, // TLV claims length 255 but body is short
        ];
        let result = EapolAnnouncement::parse(&body);
        assert!(result.is_err());
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// Unknown TLV type is skipped gracefully.
    #[test]
    fn test_parse_announcement_unknown_tlv_skipped() {
        let body = vec![
            0x00,
            0x99, 0x00, 0x02, 0xDE, 0xAD, // unknown TLV type=0x99, length=2
            0x01, 0x00, 0x03, // NID Set TLV, length=3
            0x01, 0xCC, 0x00, // NID: len=1, id=0xCC, caps=0
        ];
        let ann = EapolAnnouncement::parse(&body).unwrap();
        assert_eq!(ann.nids.len(), 1);
        assert_eq!(ann.nids[0].id, vec![0xCC]);
    }
}
