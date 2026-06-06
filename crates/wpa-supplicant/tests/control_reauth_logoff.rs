//! Integration tests for INT-007 (#115) and INT-008 (#116) — the
//! control-socket `reauthenticate` and `logoff` commands wire into the
//! Supplicant PAE.
//!
//! Verifies: INT-007 (#115), INT-008 (#116)
//! Per IEEE 802.1X-2020 Clause 8.3 (reauthentication) and Clause 8.5
//! (EAPOL-Logoff transmission, MACsec-secured suppression).
//! Architecture: ADR-EVT-007 (#79), ARC-C-WPA-005 (#85).

use std::sync::Mutex;

use anyhow::Result;
use eapol_supp::frame::{EapolFrame, EapolPacketType, EapolVersion};
use eapol_supp::PaeState;
use wpa_supplicant::{Config, ControlCommand, NetworkIo, Supplicant};

/// Test double — in-test implementation of `NetworkIo`. Mirrors the
/// `TestNet` in `eapol_dispatch.rs`; kept local because the production
/// `MockNetworkIo` is `#[cfg(test)]`-gated.
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

/// Drive the supplicant's PAE through Disconnected → Connecting →
/// Authenticating → Authenticated.
///
/// Uses only the public `Supplicant` API (the thin PAE pass-through
/// accessors `pae_set_authenticate`, `pae_step`, `pae_eap_success`).
/// In the eventual EAP-peer wiring (a future INT-NNN), `eap_success`
/// will be driven by the real EAP exchange; today the test exercises
/// the same signal directly.
fn drive_to_authenticated<N: NetworkIo>(supp: &mut Supplicant<N>, net: &TestNet) -> Result<()> {
    supp.pae_set_authenticate(true);
    // step() advances Disconnected -> Connecting and sends EAPOL-Start.
    supp.pae_step()?;
    assert_eq!(supp.pae_state(), PaeState::Connecting);

    // A received EAP-Packet drives Connecting -> Authenticating.
    let req = EapolFrame {
        version: EapolVersion::V3,
        packet_type: EapolPacketType::EapPacket,
        body: vec![0x01, 0x00, 0x00, 0x05, 0x01],
    };
    net.enqueue(req.encode().unwrap());
    supp.tick()?;
    assert_eq!(supp.pae_state(), PaeState::Authenticating);

    // EAP Success drives Authenticating -> Authenticated.
    supp.pae_eap_success()?;
    assert_eq!(supp.pae_state(), PaeState::Authenticated);
    Ok(())
}

// --- INT-007 (#115): reauthenticate command ---

/// Verifies: INT-007 (#115)
/// Per IEEE 802.1X-2020 Clause 8.3.
///
/// `ControlCommand::Reauthenticate` issued while the PAE is in the
/// Authenticated state transitions it back to Connecting and emits
/// an EAPOL-Start on the network.
#[test]
fn test_reauthenticate_from_authenticated() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = Supplicant::new(config, std::sync::Arc::clone(&net)).unwrap();

    drive_to_authenticated(&mut supp, &net).unwrap();

    // Snapshot the EAPOL-Start count from the priming exchange; the
    // reauth must add at least one more.
    let starts_before = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .count();

    supp.handle_command(ControlCommand::Reauthenticate).unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "Reauthenticate must move PAE Authenticated -> Connecting per Cl.8.3"
    );

    let starts_after = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolStart.as_u8()))
        .count();
    assert!(
        starts_after > starts_before,
        "Reauthenticate must trigger an EAPOL-Start (before={}, after={})",
        starts_before,
        starts_after
    );
}

/// Verifies: INT-007 (#115)
/// Per IEEE 802.1X-2020 Clause 8.3 and ADR-EVT-007 (#79).
///
/// `ControlCommand::Reauthenticate` issued from an invalid state (e.g.
/// Disconnected) returns `Ok(())` — control commands must never crash
/// the daemon — and the PAE state is unchanged.
#[test]
fn test_reauthenticate_from_invalid_state_is_noop() {
    let config = make_config();
    let net = TestNet::new();
    let mut supp = Supplicant::new(config, net).unwrap();

    // PAE starts in Disconnected; reauth is not valid here.
    assert_eq!(supp.pae_state(), PaeState::Disconnected);

    let result = supp.handle_command(ControlCommand::Reauthenticate);
    assert!(
        result.is_ok(),
        "reauthenticate in Disconnected must not error the daemon (got {:?})",
        result
    );
    assert_eq!(
        supp.pae_state(),
        PaeState::Disconnected,
        "PAE state must be unchanged after an invalid reauthenticate"
    );
}

// --- INT-008 (#116): logoff command ---

/// Verifies: INT-008 (#116)
/// Per IEEE 802.1X-2020 Clause 8.5.
///
/// `ControlCommand::Logoff` issued while the PAE is Authenticated emits
/// EAPOL-Logoff (since the link is not MACsec-secured in this test) and
/// transitions the PAE into the Logoff state.
#[test]
fn test_logoff_from_authenticated_sends_eapol_logoff() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = Supplicant::new(config, std::sync::Arc::clone(&net)).unwrap();

    drive_to_authenticated(&mut supp, &net).unwrap();

    let logoffs_before = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolLogoff.as_u8()))
        .count();
    assert_eq!(
        logoffs_before, 0,
        "no EAPOL-Logoff should have been sent during priming"
    );

    supp.handle_command(ControlCommand::Logoff).unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Logoff,
        "Logoff must move PAE -> Logoff per Cl.8.5"
    );

    let logoffs_after = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolLogoff.as_u8()))
        .count();
    assert_eq!(
        logoffs_after, 1,
        "Logoff must emit exactly one EAPOL-Logoff when not MACsec-secured per Cl.8.5"
    );
}

/// Verifies: INT-008 (#116)
/// Per IEEE 802.1X-2020 Clause 8.5 and ADR-EVT-007 (#79).
///
/// `ControlCommand::Logoff` issued from an invalid state returns
/// `Ok(())` without modifying PAE state — the daemon must never crash
/// on a control-socket command.
#[test]
fn test_logoff_from_invalid_state_is_noop() {
    let config = make_config();
    let net = TestNet::new();
    let mut supp = Supplicant::new(config, net).unwrap();

    assert_eq!(supp.pae_state(), PaeState::Disconnected);

    let result = supp.handle_command(ControlCommand::Logoff);
    assert!(
        result.is_ok(),
        "logoff in Disconnected must not error the daemon (got {:?})",
        result
    );
    assert_eq!(supp.pae_state(), PaeState::Disconnected);
}
