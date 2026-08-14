//! Integration test for INT-004 (#112) — link-down resets the
//! Supplicant PAE; link-up notifies it so authentication restarts.
//!
//! Verifies: INT-004 (#112)
//! Per IEEE 802.1X-2020 Clause 8.3 (Supplicant PAE link transitions)
//! and REQ-NF-REL-003 (#59) reconnection-after-link-flap.
//! Architecture: ADR-EVT-007 (#79), ARC-C-WPA-005 (#85).
//!
//! Scope boundary: covers the PAE half of the teardown / restoration
//! path. The MKA half (dropping `MkaParticipant`, zeroizing SAK/KEK/ICK)
//! lands when INT-005 (#113) constructs the participant on `Supplicant`.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use eapol_supp::frame::{EapolFrame, EapolPacketType, EapolVersion};
use eapol_supp::PaeState;
use wpa_supplicant::{Config, NetworkIo, Supplicant};

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
    fn set_link(&self, up: bool) {
        *self.link.lock().unwrap() = up;
    }
    fn enqueue(&self, frame: Vec<u8>) {
        self.inbox.lock().unwrap().push(frame);
    }
    fn sent_frames(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.sent.lock().unwrap().clone()
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

/// Verifies: INT-004 (#112)
/// Per IEEE 802.1X-2020 Clause 8.3 and REQ-NF-REL-003 (#59).
///
/// When the link goes down after the PAE has reached `Connecting`
/// (or any non-Disconnected state), `tick()` must observe the link
/// transition and reset the PAE to `Disconnected` via
/// `SupplicantPae::link_changed(false)`.
#[test]
fn test_link_down_resets_supplicant_pae() {
    let config = make_config();
    let net = Arc::new(TestNet::new());
    let mut supp = Supplicant::with_eap_methods(config, Arc::clone(&net), Vec::new()).unwrap();

    // Drive PAE to Connecting via tick() (INT-003).
    supp.pae_set_authenticate(true);
    supp.tick().unwrap();
    assert_eq!(supp.pae_state(), PaeState::Connecting);

    // Link goes down.
    net.set_link(false);
    supp.tick().unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Disconnected,
        "link-down must reset PAE to Disconnected per Cl.8.3 + INT-004"
    );
}

/// Verifies: INT-004 (#112)
/// Per IEEE 802.1X-2020 Clause 8.3 and REQ-NF-REL-003 (#59).
///
/// After a link-down -> link-up cycle, the PAE rejoins the network:
/// because `authenticate=true` persists across the flap, `link_changed(true)`
/// returns the PAE to `Connecting` and emits a fresh EAPOL-Start.
#[test]
fn test_link_up_after_down_restarts_authentication() {
    let config = make_config();
    let net = Arc::new(TestNet::new());
    let mut supp = Supplicant::with_eap_methods(config, Arc::clone(&net), Vec::new()).unwrap();

    supp.pae_set_authenticate(true);
    supp.tick().unwrap();
    let starts_before = net
        .sent_frames()
        .iter()
        .filter(|(_, b)| b.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .count();
    assert_eq!(starts_before, 1);

    // Flap the link.
    net.set_link(false);
    supp.tick().unwrap();
    assert_eq!(supp.pae_state(), PaeState::Disconnected);

    net.set_link(true);
    supp.tick().unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "link-up with persistent authenticate flag should drive PAE back to Connecting per Cl.8.3"
    );
    let starts_after = net
        .sent_frames()
        .iter()
        .filter(|(_, b)| b.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .count();
    assert!(
        starts_after > starts_before,
        "link-up must re-emit EAPOL-Start (before={}, after={})",
        starts_before,
        starts_after
    );
}

/// Verifies: INT-004 (#112)
/// Per IEEE 802.1X-2020 Clause 8.3.
///
/// Link-down from `Authenticating` also resets the PAE — covers the
/// case where the link drops mid-EAP-exchange.
#[test]
fn test_link_down_from_authenticating_resets_pae() {
    let config = make_config();
    let net = Arc::new(TestNet::new());
    let mut supp = Supplicant::with_eap_methods(config, Arc::clone(&net), Vec::new()).unwrap();

    supp.pae_set_authenticate(true);
    supp.tick().unwrap();

    // Drive Connecting -> Authenticating via an inbound EAP-Packet.
    let req = EapolFrame {
        version: EapolVersion::V3,
        packet_type: EapolPacketType::EapPacket,
        body: vec![0x01, 0x00, 0x00, 0x05, 0x01],
    };
    net.enqueue(req.encode().unwrap());
    supp.tick().unwrap();
    assert_eq!(supp.pae_state(), PaeState::Authenticating);

    // Link drops.
    net.set_link(false);
    supp.tick().unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Disconnected,
        "link-down from Authenticating must reset PAE to Disconnected per Cl.8.3"
    );
}
