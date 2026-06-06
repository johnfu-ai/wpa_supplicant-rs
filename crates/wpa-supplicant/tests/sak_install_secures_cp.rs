//! Integration test for INT-005 (#113) — MKA-derived SAK install
//! events are forwarded to the CP state machine so the Controlled Port
//! transitions to Secured.
//!
//! Verifies: INT-005 (#113)
//! Per IEEE 802.1X-2020 Clauses 9.13 (SAK install) and 10 (CP
//! transitions). Architecture: ARC-C-WPA-005 (#85), ARC-C-PAE-001 (#81),
//! ADR-EVT-007 (#79).

use std::sync::{Arc, Mutex};

use anyhow::Result;
use pae::{CipherSuite, CpState, PaeEvent, Sci};
use wpa_supplicant::{Config, NetworkIo, Supplicant};

/// Test double with a toggleable link so the test can drive the CP
/// through `Disabled -> Unsecured` via the supplicant's
/// `handle_link_change` path.
struct TestNet {
    mac: [u8; 6],
    link: Mutex<bool>,
}

impl TestNet {
    fn new(link_up: bool) -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            link: Mutex::new(link_up),
        }
    }
    fn set_link(&self, up: bool) {
        *self.link.lock().unwrap() = up;
    }
}

impl NetworkIo for TestNet {
    fn send_eapol(&self, _dest: [u8; 6], _frame: &[u8]) -> Result<()> {
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

/// Verifies: INT-005 (#113)
/// Per IEEE 802.1X-2020 Clauses 9.13 + 10 and ARC-C-WPA-005 (#85).
///
/// When the supplicant's event dispatch path receives
/// `PaeEvent::MkaSakInstalled`, it reconstructs the SAK from the
/// `sak_key` + `sak_an` payload and forwards it to the CP state machine
/// as `CpEvent::SakAvailable`. With CP in `Unsecured`, the result is a
/// transition to `Secured` per Cl.10.
#[test]
fn test_mka_sak_installed_drives_cp_to_secured() {
    let config = make_config();
    // Start with link down so the construction-time state is
    // Disabled / LinkDown; then bring the link up via tick() to
    // drive CP through EnableUnsecured.
    let net = Arc::new(TestNet::new(false));
    let mut supp = Supplicant::new(config, Arc::clone(&net)).unwrap();
    assert_eq!(supp.cp_state(), CpState::Disabled);

    net.set_link(true);
    supp.tick().unwrap();
    assert_eq!(
        supp.cp_state(),
        CpState::Unsecured,
        "link-up must drive CP Disabled -> Unsecured per Cl.10 (handle_link_change)"
    );

    // Now dispatch a SAK install event — Cl.10 must drive CP -> Secured.
    let sci = Sci::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 1);
    let event = PaeEvent::MkaSakInstalled {
        sak_key: vec![0x42; 16],
        sak_an: 0,
        sci,
        cipher_suite: CipherSuite::GcmAes128,
    };

    supp.dispatch_pae_event(event).unwrap();

    assert_eq!(
        supp.cp_state(),
        CpState::Secured,
        "MkaSakInstalled must drive CP Unsecured -> Secured per Cl.10 + INT-005"
    );
}

/// Verifies: INT-005 (#113)
/// Per IEEE 802.1X-2020 Clause 10 and ADR-EVT-007 (#79).
///
/// `PaeEvent::MkaSakInstalled` dispatched while CP is `Disabled` (the
/// initial state, before any `EnableUnsecured`) does not crash the
/// daemon — it logs at `warn` and the CP state is unchanged.
#[test]
fn test_mka_sak_installed_from_disabled_is_warn_not_crash() {
    let config = make_config();
    let net = TestNet::new(true);
    let mut supp = Supplicant::new(config, net).unwrap();

    assert_eq!(
        supp.cp_state(),
        CpState::Disabled,
        "CP must start Disabled — INT-005 dispatch must not crash from this state"
    );

    let sci = Sci::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x03], 1);
    let event = PaeEvent::MkaSakInstalled {
        sak_key: vec![0xAA; 16],
        sak_an: 0,
        sci,
        cipher_suite: CipherSuite::GcmAes128,
    };

    let result = supp.dispatch_pae_event(event);
    assert!(result.is_ok(), "dispatch must not propagate CP errors");
    assert_eq!(
        supp.cp_state(),
        CpState::Disabled,
        "CP state must be unchanged when dispatch hits a wrong-state CP"
    );
}

/// Verifies: INT-005 (#113)
/// Per IEEE 802.1X-2020 Clause 10 and ADR-EVT-007 (#79).
///
/// A malformed SAK payload (e.g. wrong length for the cipher suite)
/// does not crash the dispatcher — the SAK reconstruction failure
/// downgrades to `warn`.
#[test]
fn test_mka_sak_installed_with_invalid_key_does_not_crash() {
    let config = make_config();
    let net = TestNet::new(true);
    let mut supp = Supplicant::new(config, net).unwrap();

    let sci = Sci::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x04], 1);
    // 7-byte key — Sak::from_bytes will reject; INT-005 dispatch must
    // catch the error and continue.
    let event = PaeEvent::MkaSakInstalled {
        sak_key: vec![0xCC; 7],
        sak_an: 0,
        sci,
        cipher_suite: CipherSuite::GcmAes128,
    };

    let result = supp.dispatch_pae_event(event);
    assert!(
        result.is_ok(),
        "dispatch must not propagate SAK-reconstruction errors"
    );
}

/// Verifies: INT-005 (#113)
/// Per IEEE 802.1X-2020 Clause 9 and ADR-EVT-007 (#79).
///
/// The remaining `PaeEvent` variants (`MkaSessionEstablished`,
/// `MkaSessionTerminated`, `MkaTransmit`) all dispatch without error
/// — `MkaTransmit` ends up on the network, the other two log only.
#[test]
fn test_other_pae_events_dispatch_cleanly() {
    let config = make_config();
    let net = TestNet::new(true);
    let mut supp = Supplicant::new(config, net).unwrap();

    assert!(supp
        .dispatch_pae_event(PaeEvent::MkaSessionEstablished)
        .is_ok());
    assert!(supp
        .dispatch_pae_event(PaeEvent::MkaSessionTerminated)
        .is_ok());
    assert!(supp
        .dispatch_pae_event(PaeEvent::MkaTransmit {
            mkpdu: vec![0x03, 0x05, 0x00, 0x00],
        })
        .is_ok());
}
