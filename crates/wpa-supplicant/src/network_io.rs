//! Network I/O abstraction for the supplicant.
//!
//! Per ADR-SM-002 (#74).
//! Enables testability without real network interfaces.

use anyhow::Result;

/// Network I/O abstraction — abstracts L2 packet socket.
///
/// Per ADR-SM-002 (#74).
/// Enables testability without real network interfaces.
pub trait NetworkIo: Send + Sync {
    /// Send an EAPOL frame on the Uncontrolled Port.
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<()>;

    /// Receive an EAPOL frame (non-blocking).
    ///
    /// Returns `Ok(None)` if no frame is available.
    fn recv_eapol(&self) -> Result<Option<Vec<u8>>>;

    /// Get the MAC address of the interface.
    fn mac_address(&self) -> [u8; 6];

    /// Check if the link is up.
    fn link_up(&self) -> bool;
}

/// Mock network I/O for testing.
#[cfg(test)]
pub struct MockNetworkIo {
    mac: [u8; 6],
    link: bool,
    sent: std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    inbox: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[cfg(test)]
impl MockNetworkIo {
    /// Create a mock with default MAC and link up.
    pub fn new() -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            link: true,
            sent: std::sync::Mutex::new(Vec::new()),
            inbox: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get all sent frames (dest, frame).
    pub fn sent_frames(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.sent.lock().unwrap().clone()
    }

    /// Queue a frame for reception.
    pub fn enqueue(&self, frame: Vec<u8>) {
        self.inbox.lock().unwrap().push(frame);
    }
}

#[cfg(test)]
impl NetworkIo for MockNetworkIo {
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((dest.to_vec(), frame.to_vec()));
        Ok(())
    }

    fn recv_eapol(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.inbox.lock().unwrap().pop())
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        self.link
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-SM-002 (#74)
    /// MockNetworkIo sends and receives frames.
    #[test]
    fn test_mock_network_io() {
        let net = MockNetworkIo::new();
        assert!(net.link_up());
        assert_eq!(net.mac_address(), [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

        // No frames initially
        assert!(net.recv_eapol().unwrap().is_none());

        // Send a frame
        net.send_eapol([0xFF; 6], &[1, 2, 3]).unwrap();
        let sent = net.sent_frames();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, vec![1, 2, 3]);

        // Enqueue and receive
        net.enqueue(vec![4, 5, 6]);
        let received = net.recv_eapol().unwrap().unwrap();
        assert_eq!(received, vec![4, 5, 6]);
    }
}
