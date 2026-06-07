//! Integration tests for #129 — `MkaParticipant` construction on
//! `Supplicant` + populating the MKA fields of `state()`.
//!
//! Verifies: #129
//! Per IEEE 802.1X-2020 Cl.6.2.2 (CAK from MSK), Cl.9 (MKA),
//! Cl.9.3 (CKN).
//! Architecture: ARC-C-PAE-001 (#81), ARC-C-WPA-005 (#85),
//! ADR-SEC-004 (#76 secret zeroization).

use std::sync::Mutex;

use anyhow::Result;
use eapol_supp::frame::{EapolFrame, EapolPacketType, EapolVersion};
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

    fn enqueue(&self, frame: Vec<u8>) {
        self.inbox.lock().unwrap().push(frame);
    }

    fn sent_frames(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.sent.lock().unwrap().clone()
    }

    fn set_link(&self, up: bool) {
        *self.link.lock().unwrap() = up;
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
identity = "alice@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#,
    )
    .unwrap()
}

fn eapol_wrap_eap(body: Vec<u8>) -> Vec<u8> {
    EapolFrame {
        version: EapolVersion::V3,
        packet_type: EapolPacketType::EapPacket,
        body,
    }
    .encode()
    .unwrap()
}

/// Drive the supplicant through a synthetic EAP exchange that yields
/// a 64-byte MSK from a mock EAP method. The bridge (#130) stashes
/// the MSK on the supplicant; this test then drives `tick()` to let
/// #129 construct the `MkaParticipant`.
fn drive_to_msk_available<N: NetworkIo>(supp: &mut Supplicant<N>, net: &TestNet) -> Result<()> {
    supp.pae_set_authenticate(true);
    supp.tick()?; // Disconnected -> Connecting + EAPOL-Start

    // EAP-Request/TLS (type=13) routes through the mock method which
    // yields Success+MSK.
    net.enqueue(eapol_wrap_eap(vec![
        0x01, // code: Request
        0x07, // id
        0x00, 0x06, // length = 6
        0x0D, // type: EAP-TLS (13)
        0x00, // empty TLS data
    ]));
    supp.tick()?;

    // EAP-Success advances the PAE.
    net.enqueue(eapol_wrap_eap(vec![0x03, 0x08, 0x00, 0x04]));
    supp.tick()?;
    Ok(())
}

/// Build a Supplicant with a single mock EAP method that yields a
/// deterministic 64-byte MSK on first request.
fn build_supp_with_mock_msk(
    config: Config,
    net: std::sync::Arc<TestNet>,
) -> Supplicant<std::sync::Arc<TestNet>> {
    use eap_peer::peer::{EapContext, EapMethod, EapMethodOutput, EapType};

    struct MockTlsMethod {
        complete: bool,
    }
    impl EapMethod for MockTlsMethod {
        fn method_type(&self) -> EapType {
            EapType::Tls
        }
        fn handle_request(
            &mut self,
            _id: u8,
            _data: &[u8],
            _ctx: &dyn EapContext,
        ) -> std::result::Result<EapMethodOutput, eap_peer::EapError> {
            self.complete = true;
            Ok(EapMethodOutput::Success {
                msk: pae::Msk::from_bytes(vec![0x42; 64]).unwrap(),
                session_id: vec![13],
            })
        }
        fn reset(&mut self) {
            self.complete = false;
        }
        fn is_complete(&self) -> bool {
            self.complete
        }
        fn take_msk(&mut self) -> Option<pae::Msk> {
            None
        }
        fn supports_mutual_authentication(&self) -> bool {
            true
        }
    }

    Supplicant::with_eap_methods(
        config,
        net,
        vec![Box::new(MockTlsMethod { complete: false })],
    )
    .unwrap()
}

/// Verifies: #129
/// After a successful EAP exchange yields an MSK, the next `tick()`
/// constructs an `MkaParticipant` on the Supplicant. `mka_is_some()`
/// flips from false to true.
#[test]
fn test_mka_participant_constructed_after_eap_success() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = build_supp_with_mock_msk(config, std::sync::Arc::clone(&net));

    assert!(
        !supp.mka_is_some(),
        "no MKA participant before EAP completes"
    );

    drive_to_msk_available(&mut supp, &net).unwrap();
    // One more tick to let the construction hook run.
    supp.tick().unwrap();

    assert!(
        supp.mka_is_some(),
        "MKA participant must be constructed once the MSK is available per Cl.6.2.2"
    );
}

/// Verifies: #129
/// `Supplicant::state()` exposes the live MKA participant state and
/// peer count. Before construction the fields read default
/// (`mka_established=false`, `mka_live_peers=0`). After construction
/// they reflect the participant's `Pending` state and empty peer
/// list (we haven't injected a peer MKPDU in this test).
#[test]
fn test_state_reflects_live_mka_fields() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = build_supp_with_mock_msk(config, std::sync::Arc::clone(&net));

    // Initial snapshot — no MKA participant yet.
    let before = supp.state();
    assert!(!before.mka_established);
    assert_eq!(before.mka_live_peers, 0);

    drive_to_msk_available(&mut supp, &net).unwrap();
    supp.tick().unwrap();

    // After construction the participant is in `Pending` (no peers
    // discovered yet), so `mka_established` is still false but the
    // field reads from the participant's actual state — exercise the
    // accessor wiring.
    let after = supp.state();
    assert!(
        !after.mka_established,
        "Participant is Pending until at least one peer is live per Cl.9"
    );
    assert_eq!(after.mka_live_peers, 0);
}

/// Verifies: #129
/// On link-down the MKA participant is dropped (zeroizing the CAK /
/// ICK / KEK per ADR-SEC-004 #76). `mka_is_some()` returns to false.
#[test]
fn test_mka_participant_dropped_on_link_down() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = build_supp_with_mock_msk(config, std::sync::Arc::clone(&net));

    drive_to_msk_available(&mut supp, &net).unwrap();
    supp.tick().unwrap();
    assert!(supp.mka_is_some());

    // Simulate link loss.
    net.set_link(false);
    supp.tick().unwrap();

    assert!(
        !supp.mka_is_some(),
        "MKA participant must be dropped on link-down per Cl.6.2.2 (stale SAK)"
    );
}

/// Verifies: #129
/// Once the MKA participant is constructed, the next `tick()` calls
/// `mka.step()` which (per Cl.9.5 / Cl.9.7) emits an MKPDU wrapped
/// in an EAPOL-MKA frame on the wire.
///
/// This test pins the contract that `MkaParticipant::step()` emits
/// its *initial* MKPDU on the first call rather than waiting for
/// `MKA_HELLO_TIME` (2000 ms) to elapse — two synchronous ticks
/// elapse only microseconds, well under the Hello interval. If a
/// future refactor delays the first MKPDU until the first Hello
/// expiry, this test should be rewritten to drive time via a mock
/// `Clock` (tracked alongside the `Clock`-trait extraction follow-up
/// surfaced by the `mka-timing-auditor` on #129).
#[test]
fn test_mka_participant_emits_mkpdu_after_construction() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = build_supp_with_mock_msk(config, std::sync::Arc::clone(&net));

    drive_to_msk_available(&mut supp, &net).unwrap();
    // One tick to construct, another to let step() emit.
    supp.tick().unwrap();
    supp.tick().unwrap();

    let mkpdus_sent = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapolMka.as_u8()))
        .count();
    assert!(
        mkpdus_sent >= 1,
        "MKA participant must emit at least one EAPOL-MKA frame per Cl.9.5 (got {})",
        mkpdus_sent
    );
}
