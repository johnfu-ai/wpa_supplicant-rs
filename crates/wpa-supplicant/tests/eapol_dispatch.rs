//! Integration test for INT-002 — inbound EAPOL frames are parsed and
//! dispatched into the Supplicant PAE state machine.
//!
//! Verifies: INT-002 (#110)
//! Per IEEE 802.1X-2020 Clause 8.3 (Supplicant PACP frame ingestion).
//! Architecture: ADR-SM-002 (#74), ADR-EVT-007 (#79).
//!
//! Scope boundary: this test covers only the receive-path wiring — bytes
//! arriving on `NetworkIo::recv_eapol` reach `SupplicantPae::handle_eapol`.
//! Advancing the PAE through `step()` and the EAP exchange itself is
//! covered by INT-003 (#111) and follow-on issues.

use std::sync::Mutex;

use anyhow::Result;
use eapol_supp::frame::{EapolFrame, EapolPacketType, EapolVersion};
use eapol_supp::PaeState;
use wpa_supplicant::{Config, NetworkIo, Supplicant};

/// Test double — in-test implementation of `NetworkIo`.
///
/// Lives in the integration test because the production `MockNetworkIo`
/// in `crates/wpa-supplicant/src/network_io.rs` is `#[cfg(test)]`-gated
/// and not visible to integration tests by design.
struct TestNet {
    mac: [u8; 6],
    link: Mutex<bool>,
    sent: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    inbox: Mutex<Vec<Vec<u8>>>,
}

impl TestNet {
    fn new() -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            link: Mutex::new(true),
            sent: Mutex::new(Vec::new()),
            inbox: Mutex::new(Vec::new()),
        }
    }

    fn enqueue(&self, frame: Vec<u8>) {
        self.inbox.lock().unwrap().push(frame);
    }
}

impl NetworkIo for TestNet {
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

fn make_config() -> Config {
    Config::from_toml(
        r#"
interface = "eth0"

[eap]
identity = "test@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#,
    )
    .unwrap()
}

/// Verifies: INT-002 (#110)
/// Per IEEE 802.1X-2020 Clause 8.3.
///
/// A well-formed inbound EAPOL frame is parsed by the supplicant and
/// reaches the Supplicant PAE state machine — observed via the
/// `eapol_frames_rx` counter incrementing per `PaeCounters` (Cl.8.8).
#[test]
fn test_inbound_eapol_frame_reaches_supplicant_pae() {
    let config = make_config();
    let net = TestNet::new();
    // Enqueue a well-formed EAPOL EAP-Packet before constructing the
    // supplicant; the queue will be drained by the first `tick()`.
    let frame = EapolFrame {
        version: EapolVersion::V3,
        packet_type: EapolPacketType::EapPacket,
        // A minimal EAP body (Request/Identity-shaped); the Supplicant PAE
        // at this layer inspects only the EAPOL packet type.
        body: vec![0x01, 0x00, 0x00, 0x05, 0x01],
    };
    net.enqueue(frame.encode().unwrap());

    let mut supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    // Pre-condition: counter is zero before any tick.
    assert_eq!(supp.pae_counters().eapol_frames_rx, 0);

    supp.tick().unwrap();

    // Post-condition: the frame was dispatched into the PAE — counter
    // incremented and last_eapol_version reflects what we sent.
    assert_eq!(
        supp.pae_counters().eapol_frames_rx,
        1,
        "expected handle_eapol() to have been called exactly once"
    );
    assert_eq!(
        supp.pae_counters().last_eapol_version,
        EapolVersion::V3.as_u8(),
        "last_eapol_version should reflect the frame the PAE consumed"
    );
}

/// Verifies: INT-002 (#110)
/// Per IEEE 802.1X-2020 Clause 8.3.
///
/// Malformed inbound bytes do not crash the event loop; the frame is
/// dropped and the PAE state and counters remain untouched.
#[test]
fn test_malformed_eapol_is_dropped_without_panic() {
    let config = make_config();
    let net = TestNet::new();
    // Enqueue a few different shapes of garbage that cannot be a valid
    // EAPOL frame: too short, empty, and unknown packet type byte.
    net.enqueue(vec![0xFF]);
    net.enqueue(vec![]);
    net.enqueue(vec![0x03, 0xEE, 0x00, 0x00]);

    let mut supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    // Each tick drains one queued frame; run enough ticks to drain all.
    for _ in 0..4 {
        let result = supp.tick();
        assert!(result.is_ok(), "tick() returned: {:?}", result);
    }

    // No malformed frame should have reached the PAE.
    assert_eq!(
        supp.pae_counters().eapol_frames_rx,
        0,
        "malformed frames must be dropped before reaching the Supplicant PAE"
    );
    // PAE state stays at the initial Disconnected.
    assert_eq!(supp.pae_state(), PaeState::Disconnected);
}
