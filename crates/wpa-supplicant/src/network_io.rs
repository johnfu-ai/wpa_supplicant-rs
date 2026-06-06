//! Network I/O abstraction for the supplicant.
//!
//! Per ADR-SM-002 (#74).
//! Enables testability without real network interfaces.

use std::sync::Arc;

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

/// Blanket forwarding impl so an `Arc<N>` can be passed wherever a `NetworkIo`
/// is required. Used by `Supplicant` to share a single network handle between
/// itself and the `SupplicantPae` adapter (INT-002 / #110).
impl<T: NetworkIo + ?Sized> NetworkIo for Arc<T> {
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<()> {
        (**self).send_eapol(dest, frame)
    }

    fn recv_eapol(&self) -> Result<Option<Vec<u8>>> {
        (**self).recv_eapol()
    }

    fn mac_address(&self) -> [u8; 6] {
        (**self).mac_address()
    }

    fn link_up(&self) -> bool {
        (**self).link_up()
    }
}

/// No-op `NetworkIo` placeholder.
///
/// Per INT-001 (#109): a minimal stand-in that the binary entry point
/// can construct so the daemon assembles and runs end-to-end without
/// the L2 raw-socket binding (which is intentionally out of scope for
/// INT-001 and tracked as a follow-up — see the issue body).
///
/// Behaviour:
/// - `send_eapol` logs at `debug` and discards the frame.
/// - `recv_eapol` always returns `None` (nothing arrives on the wire).
/// - `mac_address` returns a fixed locally-administered MAC.
/// - `link_up` reflects the value passed to [`NoopNetworkIo::new`].
///
/// **Do not use in production.** The eventual `RawSocketNetworkIo`
/// (planned as a Phase-06 follow-up) replaces this with a real
/// `AF_PACKET` socket bound to the configured interface.
pub struct NoopNetworkIo {
    mac: [u8; 6],
    link_up: bool,
}

impl NoopNetworkIo {
    /// Construct a `NoopNetworkIo` with the given MAC and link state.
    ///
    /// The binary entry point uses the locally-administered placeholder
    /// MAC `02:00:00:00:00:00` until the raw-socket binding lands.
    pub fn new(mac: [u8; 6], link_up: bool) -> Self {
        Self { mac, link_up }
    }
}

impl NetworkIo for NoopNetworkIo {
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<()> {
        tracing::debug!(
            ?dest,
            len = frame.len(),
            "NoopNetworkIo: dropping EAPOL frame (INT-001 stub)"
        );
        Ok(())
    }

    fn recv_eapol(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        self.link_up
    }
}

/// Mock network I/O for testing.
///
/// Per ADR-SM-002 (#74).
/// Supports dynamic link state changes for link flap testing per REQ-NF-REL-003 (#59).
#[cfg(test)]
pub struct MockNetworkIo {
    mac: [u8; 6],
    link: std::sync::Mutex<bool>,
    sent: std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    inbox: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[cfg(test)]
impl Default for MockNetworkIo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl MockNetworkIo {
    /// Create a mock with default MAC and link up.
    pub fn new() -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            link: std::sync::Mutex::new(true),
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

    /// Set link state. Per REQ-NF-REL-003 (#59): simulates link flap.
    pub fn set_link(&self, up: bool) {
        *self.link.lock().unwrap() = up;
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
        *self.link.lock().unwrap()
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
