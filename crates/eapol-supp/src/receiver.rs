//! EAPOL frame reception and dispatch on the Uncontrolled Port.
//!
//! Implements: #46 (REQ-F-EAPOL-003: EAPOL Frame Reception)
//!
//! Per IEEE 802.1X-2020, Clause 11.1.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use crate::frame::{EapolFrame, EapolPacketType};
use crate::EapolError;

/// L2 frame receiver abstraction — Repository trait for network I/O.
///
/// Per ADR-SM-002 (#74). Enables mock injection for unit testing.
pub trait FrameReceiver: Send + Sync {
    /// Receive a raw EAPOL frame (non-blocking).
    ///
    /// Returns `Ok(Some(bytes))` if a frame is available, `Ok(None)` if none pending.
    fn recv(&self) -> Result<Option<Vec<u8>>, EapolError>;
}

/// EAP handler — dispatch target for EAPOL-EAP frames.
///
/// Per Cl.11.1: EAP packets are delivered to the EAP higher layer.
pub trait EapHandler: Send + Sync {
    /// Handle a received EAP packet.
    fn handle_eap(&self, eap_data: &[u8]) -> Result<(), EapolError>;
}

/// MKA handler — dispatch target for EAPOL-MKA frames.
///
/// Per Cl.11.1: MKA frames are delivered to the KaY (Key Agreement Entity).
pub trait MkaHandler: Send + Sync {
    /// Handle a received MKPDU.
    fn handle_mka(&self, mkpdu: &[u8]) -> Result<(), EapolError>;
}

/// Announcement handler — dispatch target for EAPOL-Announcement frames.
///
/// Per Cl.11.1: Announcement frames are delivered to the Logon Process.
pub trait AnnouncementHandler: Send + Sync {
    /// Handle a received EAPOL-Announcement.
    fn handle_announcement(&self, body: &[u8]) -> Result<(), EapolError>;
}

/// EAPOL frame receiver and dispatcher — Domain Service.
///
/// Per IEEE 802.1X-2020, Clause 11.1.
/// Receives EAPOL frames on the Uncontrolled Port, decodes them,
/// and dispatches to the appropriate handler based on Packet Type.
///
/// Implements: #46 (REQ-F-EAPOL-003: EAPOL Frame Reception)
pub struct EapolReceiver<R, E, M, A>
where
    R: FrameReceiver,
    E: EapHandler,
    M: MkaHandler,
    A: AnnouncementHandler,
{
    receiver: R,
    eap_handler: E,
    mka_handler: M,
    announcement_handler: A,
}

/// Result of dispatching a received EAPOL frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResult {
    /// Frame dispatched to EAP handler.
    EapPacket,
    /// Frame dispatched to MKA handler.
    MkaPacket,
    /// Frame dispatched to Announcement handler.
    Announcement,
    /// EAPOL-Start received (no dispatch needed, handled by PAE).
    Start,
    /// EAPOL-Logoff received (no dispatch needed, handled by PAE).
    Logoff,
    /// EAPOL-Key received (handled by key management).
    Key,
    /// No frame available.
    NoFrame,
}

impl<R, E, M, A> EapolReceiver<R, E, M, A>
where
    R: FrameReceiver,
    E: EapHandler,
    M: MkaHandler,
    A: AnnouncementHandler,
{
    /// Create a new receiver with the given L2 receiver and dispatch handlers.
    pub fn new(receiver: R, eap_handler: E, mka_handler: M, announcement_handler: A) -> Self {
        Self {
            receiver,
            eap_handler,
            mka_handler,
            announcement_handler,
        }
    }

    /// Receive and dispatch a single EAPOL frame.
    ///
    /// Per Cl.11.1: decodes the frame and dispatches based on Packet Type.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidFrame` if the frame cannot be decoded.
    pub fn receive(&self) -> Result<DispatchResult, EapolError> {
        let bytes = match self.receiver.recv()? {
            Some(b) => b,
            None => return Ok(DispatchResult::NoFrame),
        };
        let frame = EapolFrame::decode(&bytes)?;
        self.dispatch(&frame)
    }

    /// Dispatch a decoded EAPOL frame to the appropriate handler.
    fn dispatch(&self, frame: &EapolFrame) -> Result<DispatchResult, EapolError> {
        match frame.packet_type {
            EapolPacketType::EapPacket => {
                self.eap_handler.handle_eap(&frame.body)?;
                Ok(DispatchResult::EapPacket)
            }
            EapolPacketType::EapolMka => {
                self.mka_handler.handle_mka(&frame.body)?;
                Ok(DispatchResult::MkaPacket)
            }
            EapolPacketType::EapolAnnouncement => {
                self.announcement_handler.handle_announcement(&frame.body)?;
                Ok(DispatchResult::Announcement)
            }
            EapolPacketType::EapolStart => Ok(DispatchResult::Start),
            EapolPacketType::EapolLogoff => Ok(DispatchResult::Logoff),
            EapolPacketType::EapolKey => Ok(DispatchResult::Key),
            // ASF Alert and Announcement-Req not dispatched from supplicant
            _ => Ok(DispatchResult::NoFrame),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock FrameReceiver.
    struct MockReceiver {
        frames: Mutex<Vec<Vec<u8>>>,
    }

    impl MockReceiver {
        fn new(frames: Vec<Vec<u8>>) -> Self {
            Self {
                frames: Mutex::new(frames),
            }
        }
    }

    impl FrameReceiver for MockReceiver {
        fn recv(&self) -> Result<Option<Vec<u8>>, EapolError> {
            Ok(self.frames.lock().unwrap().pop())
        }
    }

    /// Mock EapHandler.
    struct MockEapHandler {
        received: Mutex<Vec<Vec<u8>>>,
    }

    impl MockEapHandler {
        fn new() -> Self {
            Self {
                received: Mutex::new(Vec::new()),
            }
        }

        fn received(&self) -> Vec<Vec<u8>> {
            self.received.lock().unwrap().clone()
        }
    }

    impl EapHandler for MockEapHandler {
        fn handle_eap(&self, eap_data: &[u8]) -> Result<(), EapolError> {
            self.received.lock().unwrap().push(eap_data.to_vec());
            Ok(())
        }
    }

    /// Mock MkaHandler.
    struct MockMkaHandler {
        received: Mutex<Vec<Vec<u8>>>,
    }

    impl MockMkaHandler {
        fn new() -> Self {
            Self {
                received: Mutex::new(Vec::new()),
            }
        }

        fn received(&self) -> Vec<Vec<u8>> {
            self.received.lock().unwrap().clone()
        }
    }

    impl MkaHandler for MockMkaHandler {
        fn handle_mka(&self, mkpdu: &[u8]) -> Result<(), EapolError> {
            self.received.lock().unwrap().push(mkpdu.to_vec());
            Ok(())
        }
    }

    /// Mock AnnouncementHandler.
    struct MockAnnouncementHandler {
        received: Mutex<Vec<Vec<u8>>>,
    }

    impl MockAnnouncementHandler {
        fn new() -> Self {
            Self {
                received: Mutex::new(Vec::new()),
            }
        }

        fn received(&self) -> Vec<Vec<u8>> {
            self.received.lock().unwrap().clone()
        }
    }

    impl AnnouncementHandler for MockAnnouncementHandler {
        fn handle_announcement(&self, body: &[u8]) -> Result<(), EapolError> {
            self.received.lock().unwrap().push(body.to_vec());
            Ok(())
        }
    }

    // Arc wrapper impls for sharing mocks
    impl FrameReceiver for Arc<MockReceiver> {
        fn recv(&self) -> Result<Option<Vec<u8>>, EapolError> {
            (**self).recv()
        }
    }

    impl EapHandler for Arc<MockEapHandler> {
        fn handle_eap(&self, eap_data: &[u8]) -> Result<(), EapolError> {
            (**self).handle_eap(eap_data)
        }
    }

    impl MkaHandler for Arc<MockMkaHandler> {
        fn handle_mka(&self, mkpdu: &[u8]) -> Result<(), EapolError> {
            (**self).handle_mka(mkpdu)
        }
    }

    impl AnnouncementHandler for Arc<MockAnnouncementHandler> {
        fn handle_announcement(&self, body: &[u8]) -> Result<(), EapolError> {
            (**self).handle_announcement(body)
        }
    }

    /// Helper: create receiver with mock handlers.
    fn create_receiver(
        frames: Vec<Vec<u8>>,
    ) -> (
        EapolReceiver<
            Arc<MockReceiver>,
            Arc<MockEapHandler>,
            Arc<MockMkaHandler>,
            Arc<MockAnnouncementHandler>,
        >,
        Arc<MockEapHandler>,
        Arc<MockMkaHandler>,
        Arc<MockAnnouncementHandler>,
    ) {
        // MockReceiver pops from end, so reverse to get FIFO
        let receiver = Arc::new(MockReceiver::new(frames.into_iter().rev().collect()));
        let eap = Arc::new(MockEapHandler::new());
        let mka = Arc::new(MockMkaHandler::new());
        let ann = Arc::new(MockAnnouncementHandler::new());
        let rx = EapolReceiver::new(receiver, eap.clone(), mka.clone(), ann.clone());
        (rx, eap, mka, ann)
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// Per Cl.11.1: EAPOL-EAP frame dispatched to EAP handler.
    #[test]
    fn test_dispatch_eap_packet() {
        let eap_data = vec![0x01, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        let frame = EapolFrame::eap_packet(eap_data.clone());
        let (rx, eap, mka, ann) = create_receiver(vec![frame.encode().unwrap()]);
        let result = rx.receive().unwrap();
        assert_eq!(result, DispatchResult::EapPacket);
        assert_eq!(eap.received().len(), 1);
        assert_eq!(eap.received()[0], eap_data);
        assert!(mka.received().is_empty());
        assert!(ann.received().is_empty());
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// Per Cl.11.1: EAPOL-MKA frame dispatched to MKA handler.
    #[test]
    fn test_dispatch_mka() {
        let mkpdu = vec![0xAA, 0xBB, 0xCC];
        let frame = EapolFrame::mka(mkpdu.clone());
        let (rx, eap, mka, ann) = create_receiver(vec![frame.encode().unwrap()]);
        let result = rx.receive().unwrap();
        assert_eq!(result, DispatchResult::MkaPacket);
        assert_eq!(mka.received().len(), 1);
        assert_eq!(mka.received()[0], mkpdu);
        assert!(eap.received().is_empty());
        assert!(ann.received().is_empty());
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// Per Cl.11.1: EAPOL-Announcement frame dispatched to Announcement handler.
    #[test]
    fn test_dispatch_announcement() {
        let body = vec![0x01, 0x02];
        let frame = EapolFrame {
            version: crate::frame::EapolVersion::V3,
            packet_type: EapolPacketType::EapolAnnouncement,
            body: body.clone(),
        };
        let (rx, eap, mka, ann) = create_receiver(vec![frame.encode().unwrap()]);
        let result = rx.receive().unwrap();
        assert_eq!(result, DispatchResult::Announcement);
        assert_eq!(ann.received().len(), 1);
        assert_eq!(ann.received()[0], body);
        assert!(eap.received().is_empty());
        assert!(mka.received().is_empty());
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// EAPOL-Start is recognized but not dispatched to handlers.
    #[test]
    fn test_dispatch_start() {
        let frame = EapolFrame::start();
        let (rx, eap, mka, ann) = create_receiver(vec![frame.encode().unwrap()]);
        let result = rx.receive().unwrap();
        assert_eq!(result, DispatchResult::Start);
        assert!(eap.received().is_empty());
        assert!(mka.received().is_empty());
        assert!(ann.received().is_empty());
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// EAPOL-Logoff is recognized but not dispatched to handlers.
    #[test]
    fn test_dispatch_logoff() {
        let frame = EapolFrame::logoff();
        let (rx, eap, mka, ann) = create_receiver(vec![frame.encode().unwrap()]);
        let result = rx.receive().unwrap();
        assert_eq!(result, DispatchResult::Logoff);
        assert!(eap.received().is_empty());
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// EAPOL-Key is recognized but not dispatched to handlers.
    #[test]
    fn test_dispatch_key() {
        let frame = EapolFrame {
            version: crate::frame::EapolVersion::V3,
            packet_type: EapolPacketType::EapolKey,
            body: vec![0x00; 16],
        };
        let (rx, eap, mka, ann) = create_receiver(vec![frame.encode().unwrap()]);
        let result = rx.receive().unwrap();
        assert_eq!(result, DispatchResult::Key);
        assert!(eap.received().is_empty());
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// No frame available returns NoFrame.
    #[test]
    fn test_no_frame_available() {
        let (rx, _, _, _) = create_receiver(vec![]);
        let result = rx.receive().unwrap();
        assert_eq!(result, DispatchResult::NoFrame);
    }

    /// Verifies: #46 (REQ-F-EAPOL-003)
    /// Malformed frame returns error.
    #[test]
    fn test_malformed_frame_error() {
        let (rx, _, _, _) = create_receiver(vec![vec![0x03]]); // too short
        let result = rx.receive();
        assert!(result.is_err());
    }
}
