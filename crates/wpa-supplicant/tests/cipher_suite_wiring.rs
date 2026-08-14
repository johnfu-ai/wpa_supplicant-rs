//! Integration tests for #176 / F-EAP-3 — `config.macsec.cipher_suite`
//! → `pae::CipherSuite` mapping at MKA construction.
//!
//! Verifies: #176 (REQ-F-CP-004 #32 / REQ-F-MKA-005 #23)
//! Per IEEE 802.1X-2020 Cl.9.7 (cipher suites), Cl.6.2.2 (CAK from MSK).
//! Architecture: ADR-SM-002 (#74).

use std::sync::{Arc, Mutex};

use anyhow::Result;
use eap_peer::peer::{EapContext, EapMethod, EapMethodOutput, EapType};
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

/// Mock EAP method that yields a deterministic 64-byte MSK on request.
struct MockTlsMethod;
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
        Ok(EapMethodOutput::Success {
            msk: pae::Msk::from_bytes(vec![0x42; 64]).unwrap(),
            session_id: vec![13],
        })
    }
    fn reset(&mut self) {}
    fn is_complete(&self) -> bool {
        true
    }
    fn take_msk(&mut self) -> Option<pae::Msk> {
        None
    }
    fn supports_mutual_authentication(&self) -> bool {
        true
    }
}

fn make_config(cipher_suite: &str) -> Config {
    Config::from_toml(&format!(
        r#"
interface = "eth0"

[eap]
identity = "alice@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"

[macsec]
cipher_suite = "{cipher_suite}"
"#
    ))
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

/// Build a Supplicant with the mock MSK-yielding method (#130 bridge
/// pattern from `tests/mka_participant.rs`).
fn build_supp(config: Config, net: Arc<TestNet>) -> Supplicant<Arc<TestNet>> {
    Supplicant::with_eap_methods(config, net, vec![Box::new(MockTlsMethod)]).unwrap()
}

/// Drive a synthetic EAP exchange to EAP-Success, then one more tick
/// so the MKA-construction hook (#129) runs.
fn drive_to_mka(supp: &mut Supplicant<Arc<TestNet>>, net: &TestNet) -> Result<()> {
    supp.pae_set_authenticate(true);
    supp.tick()?;

    net.enqueue(eapol_wrap_eap(vec![0x01, 0x07, 0x00, 0x06, 0x0D, 0x00]));
    supp.tick()?;

    net.enqueue(eapol_wrap_eap(vec![0x03, 0x08, 0x00, 0x04]));
    supp.tick()?;
    supp.tick()?;
    Ok(())
}

/// Verifies: #176 (REQ-F-CP-004 #32 / REQ-F-MKA-005 #23)
/// `cipher_suite = "gcm-aes-256"` in the config TOML must produce an
/// MKA participant constructed with `GcmAes256` per Cl.9.7 — not be
/// silently ignored in favor of the GcmAes128 default.
#[test]
fn test_mka_cipher_suite_256_from_config() {
    let config = make_config("gcm-aes-256");
    let net = Arc::new(TestNet::new());
    let mut supp = build_supp(config, Arc::clone(&net));

    drive_to_mka(&mut supp, &net).unwrap();

    assert!(supp.mka_is_some(), "MKA participant must be constructed");
    assert_eq!(
        supp.mka_cipher_suite(),
        Some(pae::CipherSuite::GcmAes256),
        "config cipher_suite=gcm-aes-256 must flow into the MKA participant per #176"
    );
}

/// Verifies: #176 (REQ-F-CP-004 #32 / REQ-F-MKA-005 #23)
/// The default (`gcm-aes-128`) still maps to `GcmAes128`.
#[test]
fn test_mka_cipher_suite_default_128() {
    let config = make_config("gcm-aes-128");
    let net = Arc::new(TestNet::new());
    let mut supp = build_supp(config, Arc::clone(&net));

    drive_to_mka(&mut supp, &net).unwrap();

    assert_eq!(
        supp.mka_cipher_suite(),
        Some(pae::CipherSuite::GcmAes128),
        "default cipher_suite=gcm-aes-128 maps to GcmAes128"
    );
}
