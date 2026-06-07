//! Integration tests for #130 — eap-peer → Supplicant PAE bridge.
//!
//! Verifies that an inbound EAP packet on the wire drives the
//! `eap-peer` `EapPeer` conversation, and that EAP-Success / EAP-Failure
//! reach `SupplicantPae::eap_success / eap_failure` without the test
//! needing the legacy `pae_eap_success` shim removed in this issue.
//!
//! On EAP-Success, the bridge also takes the MSK and stashes it on the
//! Supplicant so the eventual MKA participant construction (#129) can
//! pick it up.
//!
//! Verifies: #130
//! Per IEEE 802.1X-2020 Cl.8.3, RFC 3748 §4, RFC 5247.
//! Architecture: ADR-EVT-007 (#79), ARC-C-EAP-003 (#83), ARC-C-WPA-005 (#85).

use std::sync::Mutex;

use anyhow::Result;
use eap_peer::peer::EapPacket;
use eapol_supp::frame::{EapolFrame, EapolPacketType, EapolVersion};
use eapol_supp::PaeState;
use wpa_supplicant::{Config, NetworkIo, Supplicant};

/// Local `NetworkIo` double — mirrors the production `MockNetworkIo`
/// but is reachable from integration tests (the workspace mock is
/// `#[cfg(test)]`-gated and not exported).
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

/// Wrap raw EAP-packet bytes in an EAPOL `EapPacket` frame.
fn eapol_wrap_eap(eap_bytes: Vec<u8>) -> Vec<u8> {
    EapolFrame {
        version: EapolVersion::V3,
        packet_type: EapolPacketType::EapPacket,
        body: eap_bytes,
    }
    .encode()
    .unwrap()
}

/// Drive PAE Disconnected -> Connecting -> Authenticating via the
/// public surface, without using the removed `pae_eap_success` shim.
fn drive_to_authenticating<N: NetworkIo>(supp: &mut Supplicant<N>, net: &TestNet) -> Result<()> {
    supp.pae_set_authenticate(true);
    supp.tick()?; // Disconnected -> Connecting + EAPOL-Start
    assert_eq!(supp.pae_state(), PaeState::Connecting);

    // An EAP-Request/Identity drives Connecting -> Authenticating.
    let req = EapPacket::response(0x00, eap_peer::peer::EapType::Identity, Vec::new());
    // Reusing `response` shape for simplicity; the EAPOL-level decode
    // only cares the body is a Request — re-build raw bytes to make it
    // a request (code=01) explicitly.
    let mut raw = req.encode().unwrap();
    raw[0] = 0x01; // EAP-Request
    net.enqueue(eapol_wrap_eap(raw));
    supp.tick()?;
    assert_eq!(supp.pae_state(), PaeState::Authenticating);
    Ok(())
}

/// Verifies: #130
/// An inbound EAP-Success (after the priming Identity exchange)
/// drives the bridge, which in turn calls `SupplicantPae::eap_success`
/// and moves PAE Authenticating -> Authenticated. No test code touches
/// the removed `pae_eap_success` shim.
#[test]
fn test_eap_success_drives_pae_via_bridge() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = Supplicant::new(config, std::sync::Arc::clone(&net)).unwrap();

    drive_to_authenticating(&mut supp, &net).unwrap();

    // EAP-Success: code=03, id=00, length=0004 — 4-byte payload, no
    // method type / data.
    let eap_success: Vec<u8> = vec![0x03, 0x00, 0x00, 0x04];
    net.enqueue(eapol_wrap_eap(eap_success));
    supp.tick().unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Authenticated,
        "EAP-Success on the wire must drive PAE -> Authenticated via the bridge per Cl.8.3"
    );
}

/// Verifies: #130
/// An inbound EAP-Failure (after the priming Identity exchange)
/// drives the bridge, which calls `SupplicantPae::eap_failure` and
/// moves PAE out of Authenticating. Per Cl.8.3 the exact next state
/// depends on the retry count — Connecting on retry, Held when
/// exhausted — so this test asserts the PAE simply left
/// Authenticating and the failure counter incremented, rather than
/// pinning a specific subsequent state.
#[test]
fn test_eap_failure_drives_pae_via_bridge() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = Supplicant::new(config, std::sync::Arc::clone(&net)).unwrap();

    drive_to_authenticating(&mut supp, &net).unwrap();
    let fails_before = supp.pae_counters().auth_fail_while_authenticating;

    // EAP-Failure: code=04, id=00, length=0004.
    let eap_failure: Vec<u8> = vec![0x04, 0x00, 0x00, 0x04];
    net.enqueue(eapol_wrap_eap(eap_failure));
    supp.tick().unwrap();

    assert_ne!(
        supp.pae_state(),
        PaeState::Authenticating,
        "EAP-Failure must move PAE out of Authenticating per Cl.8.3"
    );
    let fails_after = supp.pae_counters().auth_fail_while_authenticating;
    assert!(
        fails_after > fails_before,
        "auth_fail_while_authenticating counter must increment on EAP-Failure (before={}, after={})",
        fails_before,
        fails_after,
    );
}

/// Verifies: #130
/// An inbound EAP-Request/Identity is consumed by the bridge and an
/// EAP-Response/Identity is emitted on the wire wrapped in an EAPOL
/// EAP-Packet frame. This proves the bridge is actually invoking
/// `EapPeer::handle_packet` end-to-end rather than just routing the
/// success/failure terminal codes.
#[test]
fn test_eap_request_identity_emits_eap_response() {
    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = Supplicant::new(config, std::sync::Arc::clone(&net)).unwrap();
    supp.pae_set_authenticate(true);
    supp.tick().unwrap(); // -> Connecting + EAPOL-Start

    // Snapshot count of outbound EAPOL `EapPacket` frames before the
    // bridge runs.
    let resps_before = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapPacket.as_u8()))
        .count();

    // Build a real EAP-Request/Identity (code=01, id=42, len=0005, type=01)
    let eap_req: Vec<u8> = vec![0x01, 42, 0x00, 0x05, 0x01];
    net.enqueue(eapol_wrap_eap(eap_req));
    supp.tick().unwrap();

    let resps_after = net
        .sent_frames()
        .iter()
        .filter(|(_, body)| body.get(1) == Some(&EapolPacketType::EapPacket.as_u8()))
        .count();
    assert!(
        resps_after > resps_before,
        "bridge must emit an EAP-Response/Identity (before={}, after={})",
        resps_before,
        resps_after
    );

    // The outbound frame should contain an EAP-Response (code=2) with
    // the configured identity bytes.
    let last_eap = net
        .sent_frames()
        .into_iter()
        .rfind(|(_, body)| body.get(1) == Some(&EapolPacketType::EapPacket.as_u8()))
        .expect("at least one outbound EAP packet");
    // EAPOL header is 4 bytes (version, type, length-hi, length-lo).
    let eap_body = &last_eap.1[4..];
    assert_eq!(eap_body[0], 0x02, "outbound EAP code must be Response");
    assert_eq!(eap_body[1], 42, "outbound EAP identifier must echo request");
    assert_eq!(eap_body[4], 0x01, "outbound EAP type must be Identity");
    // Identity payload follows the type byte.
    assert_eq!(&eap_body[5..], b"alice@example.com");
}

/// Verifies: #130
/// After a successful EAP exchange via the bridge, the MSK produced
/// by the configured EAP method is queued on the supplicant for the
/// downstream MKA participant construction (#129).
///
/// This test injects a mock EAP method that produces a deterministic
/// 64-byte MSK; it then drives the bridge through the method and
/// confirms that the MSK reached the supplicant's hand-off path —
/// either observable directly via `take_msk()` (if the MKA participant
/// has not yet claimed it) or indirectly via `mka_is_some()` (once
/// #129's construction hook consumed it). Either witness proves the
/// bridge stashed the MSK; the test does not pin which path runs
/// first because the construction hook is timing-sensitive to the
/// tick-loop ordering.
#[test]
fn test_msk_exposed_after_method_success() {
    use eap_peer::peer::{EapContext, EapMethod, EapMethodOutput, EapType};

    /// Mock method that yields a fixed MSK on first request.
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
                msk: pae::Msk::from_bytes(vec![0xCD; 64]).unwrap(),
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

    let config = make_config();
    let net = std::sync::Arc::new(TestNet::new());
    let mut supp = Supplicant::with_eap_methods(
        config,
        std::sync::Arc::clone(&net),
        vec![Box::new(MockTlsMethod { complete: false })],
    )
    .unwrap();
    supp.pae_set_authenticate(true);
    supp.tick().unwrap(); // -> Connecting

    // EAP-Request/TLS (type=13). The bridge dispatches to the mock,
    // which yields Success with MSK.
    let eap_req: Vec<u8> = vec![
        0x01, // code: Request
        0x07, // id
        0x00, 0x06, // length = 6
        0x0D, // type: EAP-TLS (13)
        0x00, // empty TLS data
    ];
    net.enqueue(eapol_wrap_eap(eap_req));
    supp.tick().unwrap();

    // Then send EAP-Success on the wire to advance the PAE.
    let eap_success: Vec<u8> = vec![0x03, 0x08, 0x00, 0x04];
    net.enqueue(eapol_wrap_eap(eap_success));
    supp.tick().unwrap();

    assert_eq!(supp.pae_state(), PaeState::Authenticated);

    // The MSK either still lives on the supplicant (no MKA construction
    // run yet) or has already been consumed by #129's construction
    // hook. Either witness proves the bridge stashed it.
    let msk_visible = supp.take_msk().is_some();
    let mka_constructed = supp.mka_is_some();
    assert!(
        msk_visible || mka_constructed,
        "bridge must surface the MSK either directly (take_msk) or indirectly (mka_is_some)"
    );
}
