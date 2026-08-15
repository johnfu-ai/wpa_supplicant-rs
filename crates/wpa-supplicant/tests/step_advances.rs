//! Integration test for INT-003 (#111) — the supplicant's `tick()`
//! drives `SupplicantPae::step()` so timer-driven state transitions
//! advance without callers having to step the PAE by hand.
//!
//! Verifies: INT-003 (#111)
//! Per IEEE 802.1X-2020 Clause 8.3 (Supplicant PACP timer-driven
//! transitions) and Clause 9 (MKA Hello timer bounds).
//! Architecture: ADR-EVT-007 (#79), ADR-SM-002 (#74).

use std::sync::Mutex;

use anyhow::Result;
use eapol_supp::{EapolPacketType, PaeState};
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

/// Verifies: INT-003 (#111)
/// Per IEEE 802.1X-2020 Clause 8.3.
///
/// Since #170 / F-INT-1 (REQ-F-PAE-001) the daemon auto-starts
/// authentication at construction when the link is up: the PAE boots
/// straight into Connecting and puts EAPOL-Start on the wire before
/// any tick. The tick loop (INT-003) must keep the PAE advancing
/// without re-emitting EAPOL-Start — callers never invoke the PAE
/// step by hand.
#[test]
fn test_tick_advances_pae_to_connecting_and_emits_eapol_start() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp =
        Supplicant::with_eap_methods(config, std::sync::Arc::clone(&net), Vec::new()).unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "construction must auto-start authentication (Cl.8.4) when the link is up"
    );

    let starts_before: Vec<_> = net
        .sent_frames()
        .into_iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .collect();
    assert_eq!(
        starts_before.len(),
        1,
        "exactly one EAPOL-Start must be on the wire from the auto-start boot path"
    );

    supp.tick().unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "tick() must drive pae.step() and hold the Connecting state per Cl.8.3"
    );
    let starts_after = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .count();
    assert_eq!(
        starts_after, 1,
        "a tick after boot must not re-emit EAPOL-Start (startWhen timer governs retry)"
    );
}

/// Verifies: INT-003 (#111)
/// Per IEEE 802.1X-2020 Clause 8.3.
///
/// `tick()` is idempotent once PAE is steady — repeated calls with no
/// new input do not re-emit EAPOL-Start (the startWhen timer governs
/// retry, not the tick cadence).
#[test]
fn test_tick_does_not_double_emit_eapol_start() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp =
        Supplicant::with_eap_methods(config, std::sync::Arc::clone(&net), Vec::new()).unwrap();

    // No manual `pae_set_authenticate` shim: since #187 the boot path
    // itself starts authentication when the link is up.
    for _ in 0..5 {
        supp.tick().unwrap();
    }

    let starts = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .count();
    assert_eq!(
        starts, 1,
        "five ticks must not re-emit EAPOL-Start (startWhen timer is 30s default per Cl.8.3)"
    );
}

/// Verifies: INT-003 (#111)
/// Per ADR-EVT-007 (#79).
///
/// `tick()` returns `Ok` and an empty event vector on a quiet PAE.
/// Since #170 / F-INT-1 the PAE has already auto-started (Connecting,
/// EAPOL-Start sent) at construction when the link is up; a tick with
/// no inbound frames and no link change must produce no events and
/// leave that state untouched.
#[test]
fn test_tick_returns_ok_on_quiet_supplicant() {
    let config = make_config();
    let net = TestNet::new();
    let mut supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    // No inbound frames, no link change — the boot already fired.
    let events = supp.tick().unwrap();
    assert!(
        events.is_empty(),
        "no events should be produced on a quiet tick"
    );
    assert_eq!(supp.pae_state(), PaeState::Connecting);
}
