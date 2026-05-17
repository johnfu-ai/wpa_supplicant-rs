//! EAPOL frame transmission on the Uncontrolled Port.
//!
//! Implements: #45 (REQ-F-EAPOL-002: EAPOL Frame Transmission)
//!
//! Per IEEE 802.1X-2020, Clause 11.1 and Clause 12.7.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use crate::frame::EapolFrame;
use crate::EapolError;

/// PAE group MAC address per IEEE 802.1X-2020, Clause 12.7.
///
/// All EAPOL frames are transmitted to this destination on the Uncontrolled Port.
pub const PAE_GROUP_MAC: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

/// L2 frame sender abstraction — Repository trait for network I/O.
///
/// Per ADR-SM-002 (#74). Enables mock injection for unit testing.
pub trait FrameSender: Send + Sync {
    /// Send raw EAPOL bytes to the given destination MAC.
    fn send(&self, dest: &[u8; 6], frame_bytes: &[u8]) -> Result<(), EapolError>;

    /// Check if the link is up.
    fn link_up(&self) -> bool;
}

/// EAPOL frame transmitter — Domain Service for Uncontrolled Port transmission.
///
/// Per IEEE 802.1X-2020, Clause 11.1 and Clause 12.7.
/// Encodes EAPOL frames and transmits them to the PAE group MAC address
/// on the Uncontrolled Port, only when the link is up.
///
/// Implements: #45 (REQ-F-EAPOL-002: EAPOL Frame Transmission)
pub struct EapolTransmitter<S: FrameSender> {
    sender: S,
}

impl<S: FrameSender> EapolTransmitter<S> {
    /// Create a new transmitter with the given L2 sender.
    pub fn new(sender: S) -> Self {
        Self { sender }
    }

    /// Transmit an EAPOL frame on the Uncontrolled Port.
    ///
    /// Per Cl.11.1 and Cl.12.7: frames are sent to the PAE group MAC address.
    ///
    /// # Errors
    /// Returns `EapolError::SendFailed` if the link is down or encoding/transmission fails.
    pub fn transmit(&self, frame: &EapolFrame) -> Result<(), EapolError> {
        if !self.sender.link_up() {
            return Err(EapolError::SendFailed("link is down".into()));
        }
        let bytes = frame.encode()?;
        self.sender.send(&PAE_GROUP_MAC, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::EapolPacketType;
    use std::sync::{Arc, Mutex};

    /// Mock FrameSender for testing.
    struct MockSender {
        sent: Mutex<Vec<([u8; 6], Vec<u8>)>>,
        link_up: bool,
    }

    impl MockSender {
        fn new(link_up: bool) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                link_up,
            }
        }

        fn sent_frames(&self) -> Vec<([u8; 6], Vec<u8>)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl FrameSender for MockSender {
        fn send(&self, dest: &[u8; 6], frame_bytes: &[u8]) -> Result<(), EapolError> {
            self.sent
                .lock()
                .unwrap()
                .push((*dest, frame_bytes.to_vec()));
            Ok(())
        }

        fn link_up(&self) -> bool {
            self.link_up
        }
    }

    impl FrameSender for Arc<MockSender> {
        fn send(&self, dest: &[u8; 6], frame_bytes: &[u8]) -> Result<(), EapolError> {
            (**self).send(dest, frame_bytes)
        }

        fn link_up(&self) -> bool {
            (**self).link_up()
        }
    }

    /// Verifies: #45 (REQ-F-EAPOL-002)
    /// Per Cl.11.1, Cl.12.7: EAPOL-Start transmitted to PAE group MAC.
    #[test]
    fn test_transmit_start_to_pae_group_mac() {
        let sender = Arc::new(MockSender::new(true));
        let tx = EapolTransmitter::new(sender.clone());
        let frame = EapolFrame::start();
        tx.transmit(&frame).unwrap();
        let sent = sender.sent_frames();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, PAE_GROUP_MAC);
    }

    /// Verifies: #45 (REQ-F-EAPOL-002)
    /// Per Cl.11.1: frame is encoded correctly before transmission.
    #[test]
    fn test_transmit_encodes_frame_correctly() {
        let sender = Arc::new(MockSender::new(true));
        let tx = EapolTransmitter::new(sender.clone());
        let frame = EapolFrame::eap_packet(vec![0x01, 0x02]);
        let expected_bytes = frame.encode().unwrap();
        tx.transmit(&frame).unwrap();
        let sent = sender.sent_frames();
        assert_eq!(sent[0].1, expected_bytes);
    }

    /// Verifies: #45 (REQ-F-EAPOL-002)
    /// Per Cl.11.1: transmission fails when link is down.
    #[test]
    fn test_transmit_link_down() {
        let sender = Arc::new(MockSender::new(false));
        let tx = EapolTransmitter::new(sender);
        let frame = EapolFrame::start();
        let result = tx.transmit(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("link is down"));
    }

    /// Verifies: #45 (REQ-F-EAPOL-002)
    /// Per Cl.11.1, Cl.12.7: EAPOL-Logoff transmitted to PAE group MAC.
    #[test]
    fn test_transmit_logoff() {
        let sender = Arc::new(MockSender::new(true));
        let tx = EapolTransmitter::new(sender.clone());
        let frame = EapolFrame::logoff();
        tx.transmit(&frame).unwrap();
        let sent = sender.sent_frames();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, PAE_GROUP_MAC);
        // Verify it's actually a logoff frame
        let decoded = EapolFrame::decode(&sent[0].1).unwrap();
        assert_eq!(decoded.packet_type, EapolPacketType::EapolLogoff);
    }

    /// Verifies: #45 (REQ-F-EAPOL-002)
    /// Per Cl.11.1, Cl.12.7: EAPOL-MKA transmitted to PAE group MAC.
    #[test]
    fn test_transmit_mka() {
        let sender = Arc::new(MockSender::new(true));
        let tx = EapolTransmitter::new(sender.clone());
        let frame = EapolFrame::mka(vec![0xAA, 0xBB, 0xCC]);
        tx.transmit(&frame).unwrap();
        let sent = sender.sent_frames();
        assert_eq!(sent[0].0, PAE_GROUP_MAC);
        let decoded = EapolFrame::decode(&sent[0].1).unwrap();
        assert_eq!(decoded.packet_type, EapolPacketType::EapolMka);
    }

    /// Verifies: #45 (REQ-F-EAPOL-002)
    /// PAE group MAC constant matches Clause 12.7.
    #[test]
    fn test_pae_group_mac_value() {
        assert_eq!(PAE_GROUP_MAC, [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03]);
    }
}
