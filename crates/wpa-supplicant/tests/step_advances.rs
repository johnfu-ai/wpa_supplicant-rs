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
/// After `pae_set_authenticate(true)`, a single `tick()` call must
/// advance the Supplicant PAE from Disconnected to Connecting and
/// emit an EAPOL-Start on the network. Pre-INT-003, callers had to
/// invoke `pae_step()` directly; INT-003 makes the tick loop do that.
#[test]
fn test_tick_advances_pae_to_connecting_and_emits_eapol_start() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp =
        Supplicant::with_eap_methods(config, std::sync::Arc::clone(&net), Vec::new()).unwrap();

    assert_eq!(supp.pae_state(), PaeState::Disconnected);

    supp.pae_set_authenticate(true);
    supp.tick().unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "tick() must drive pae.step() — PAE should advance to Connecting per Cl.8.3"
    );

    let starts: Vec<_> = net
        .sent_frames()
        .into_iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .collect();
    assert_eq!(
        starts.len(),
        1,
        "tick() must send exactly one EAPOL-Start when authenticate is set"
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

    supp.pae_set_authenticate(true);
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
/// `tick()` returns `Ok` and an event vector even when the PAE rejects
/// a step (e.g. inconsistent flags). The current `SupplicantPae::step`
/// is total over its inputs, but the event loop must remain robust.
#[test]
fn test_tick_returns_ok_on_quiet_supplicant() {
    let config = make_config();
    let net = TestNet::new();
    let mut supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    // No authenticate flag, no inbound frames, no link change.
    let events = supp.tick().unwrap();
    assert!(
        events.is_empty(),
        "no events should be produced on a quiet tick"
    );
    assert_eq!(supp.pae_state(), PaeState::Disconnected);
}
