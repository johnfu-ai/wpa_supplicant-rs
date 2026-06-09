//! Integration test for #135 — AES Key Wrap (RFC 3394) in MKA SAK unwrap.
//!
//! Validates two aspects:
//! 1. The `pae::aes_key_wrap` / `pae::aes_key_unwrap` primitives work
//!    correctly for MKA SAK-sized keys (16 and 32 bytes).
//! 2. The end-to-end dispatch path `MkaSakInstalled → CpEvent::SakAvailable
//!    → CP Secured` functions with SAK key bytes that were extracted by a
//!    real AES Key Unwrap operation.
//!
//! Verifies: #135, #24 (REQ-F-MKA-006)
//! Per IEEE 802.1X-2020 Cl.9.8 (SAK Distribution), Cl.9.13 (SAK Install),
//! Cl.10 (CP state machine).
//! Architecture: ARC-C-PAE-001 (#81), ARC-C-WPA-005 (#85),
//! ADR-SEC-004 (#76 — secret zeroization).

use std::sync::{Arc, Mutex};

use anyhow::Result;
use pae::{aes_key_unwrap, aes_key_wrap, CipherSuite, CpState, PaeEvent, Sci};
use wpa_supplicant::{Config, NetworkIo, Supplicant};

struct TestNet {
    mac: [u8; 6],
    link: Mutex<bool>,
    sent: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl TestNet {
    fn new(link_up: bool) -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            link: Mutex::new(link_up),
            sent: Mutex::new(Vec::new()),
        }
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
        Ok(None)
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

/// Verifies: #135
/// AES Key Wrap round-trip for MKA-relevant key sizes: 16-byte SAK with
/// 16-byte KEK (GcmAes128) and 32-byte SAK with 32-byte KEK (GcmAes256).
#[test]
fn test_aes_key_wrap_unwrap_mka_sak_sizes() {
    // AES-128 SAK with AES-128 KEK
    let kek128 = [0x42_u8; 16];
    let sak128 = [0xAB_u8; 16];
    let wrapped = aes_key_wrap(&sak128, &kek128).expect("wrap 128 should succeed");
    assert_eq!(wrapped.len(), 24, "128-bit SAK wrapped = 16 + 8 bytes");
    let unwrapped = aes_key_unwrap(&wrapped, &kek128).expect("unwrap 128 should succeed");
    assert_eq!(unwrapped.as_slice(), sak128);

    // AES-256 SAK with AES-256 KEK
    let kek256 = [0x37_u8; 32];
    let sak256 = [0xCD_u8; 32];
    let wrapped = aes_key_wrap(&sak256, &kek256).expect("wrap 256 should succeed");
    assert_eq!(wrapped.len(), 40, "256-bit SAK wrapped = 32 + 8 bytes");
    let unwrapped = aes_key_unwrap(&wrapped, &kek256).expect("unwrap 256 should succeed");
    assert_eq!(unwrapped.as_slice(), sak256);
}

/// Verifies: #135
/// Wrong KEK during unwrap produces `CryptoError` (IV check failure)
/// rather than silently returning garbage. Per ADR-SEC-004 (#76).
#[test]
fn test_aes_key_unwrap_wrong_kek_fails() {
    let kek1 = [0x42_u8; 16];
    let kek2 = [0xFF_u8; 16];
    let sak_bytes = [0xAB_u8; 16];

    let wrapped = aes_key_wrap(&sak_bytes, &kek1).expect("wrap should succeed");
    let result = aes_key_unwrap(&wrapped, &kek2);
    assert!(result.is_err(), "unwrap with wrong KEK must fail");
}

/// Verifies: #135
/// End-to-end: simulate a SAK that was unwrapped via AES Key Unwrap,
/// then dispatch it through the supplicant's event dispatch path, and
/// verify CP transitions to Secured per Cl.10.
///
/// This mirrors `test_mka_sak_installed_drives_cp_to_secured` in
/// `sak_install_secures_cp.rs` (INT-005 #113) but validates the SAK
/// bytes came from a real RFC 3394 unwrap operation.
#[test]
fn test_unwrapped_sak_dispatches_to_cp_secured() {
    let config = make_config();
    // Start with link down so CP is Disabled; then bring it up to
    // drive CP through EnableUnsecured per Cl.10.
    let net = Arc::new(TestNet::new(false));
    let mut supp = Supplicant::new(config, Arc::clone(&net)).unwrap();
    assert_eq!(supp.cp_state(), CpState::Disabled);

    // Drive CP Disabled -> Unsecured via link-up tick.
    *net.link.lock().unwrap() = true;
    supp.tick().unwrap();
    assert_eq!(supp.cp_state(), CpState::Unsecured);

    // Simulate a SAK that was AES-Key-Wrapped by the Authenticator's
    // Key Server and then unwrapped by the Supplicant's
    // `MkaParticipantAdapter::unwrap_sak`. In production the MKA
    // participant calls `unwrap_sak` on receiving a DistribSAK MKPDU,
    // then emits `MkaSakInstalled`. Here we produce the same key bytes
    // that the unwrap would yield.
    let kek = [0x42_u8; 16];
    let sak_plaintext = [0xAB_u8; 16];
    let wrapped_sak = aes_key_wrap(&sak_plaintext, &kek).expect("wrap should succeed");
    let unwrapped_sak = aes_key_unwrap(&wrapped_sak, &kek).expect("unwrap should succeed");
    assert_eq!(unwrapped_sak.as_slice(), sak_plaintext);

    let sci = Sci::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 1);
    let event = PaeEvent::MkaSakInstalled {
        sak_key: unwrapped_sak,
        sak_an: 0,
        sci,
        cipher_suite: CipherSuite::GcmAes128,
    };

    supp.dispatch_pae_event(event).unwrap();

    assert_eq!(
        supp.cp_state(),
        CpState::Secured,
        "CP must transition to Secured after SAK install per Cl.10 (got {:?})",
        supp.cp_state()
    );
}
