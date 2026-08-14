//! Integration test for INT-006 (#114) — the control-socket
//! `GetState` response surfaces the supplicant's live PAE / CP / Logon
//! / MKA state instead of hardcoded defaults.
//!
//! Verifies: INT-006 (#114)
//! Per IEEE 802.1X-2020 Clauses 8.3 (Supplicant PAE state) and 10
//! (Controlled Port state). Architecture: ARC-C-WPA-005 (#85),
//! ADR-EVT-007 (#79).

use std::sync::Mutex;

use anyhow::Result;
use wpa_supplicant::{Config, NetworkIo, Supplicant, SupplicantState};

struct TestNet {
    mac: [u8; 6],
    link: Mutex<bool>,
}

impl TestNet {
    fn new() -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            link: Mutex::new(true),
        }
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

/// Verifies: INT-006 (#114)
/// Per ARC-C-WPA-005 (#85).
///
/// `Supplicant::state()` returns a `SupplicantState` that round-trips
/// through `serde_json::to_string` cleanly with every field present and
/// schema-stable for control-socket consumers.
#[test]
fn test_state_json_round_trip_schema_stable() {
    let config = make_config();
    let net = TestNet::new();
    let supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    let state = supp.state();
    let json = serde_json::to_string(&state).expect("state must serialize");

    // Every field in `SupplicantState` must appear in the JSON so
    // control-socket consumers (and the eventual NETCONF / YANG surface
    // tracked under P5.3) have a stable schema.
    for field in &[
        "pae_state",
        "cp_state",
        "logon_state",
        "selected_nid",
        "mka_established",
        "mka_live_peers",
    ] {
        assert!(
            json.contains(field),
            "field {} missing from state JSON: {}",
            field,
            json
        );
    }
}

/// Verifies: INT-006 (#114)
/// Per IEEE 802.1X-2020 Clause 8.3 and INT-002 (#110).
///
/// The `pae_state` field in `Supplicant::state()` reflects the live
/// Supplicant PAE state — not a hardcoded default. After a
/// `pae_set_authenticate(true) + tick()` sequence the PAE moves to
/// `Connecting` per Cl.8.3 (the tick loop drives `pae.step()` per
/// INT-003 / #111), and the JSON must record that.
#[test]
fn test_state_pae_field_is_live() {
    let config = make_config();
    let net = TestNet::new();
    let mut supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    // Before stepping, the PAE is Disconnected.
    let json_before = serde_json::to_string(&supp.state()).unwrap();
    assert!(
        json_before.contains(r#""pae_state":"disconnected""#),
        "expected disconnected in {}",
        json_before
    );

    // Drive PAE: Disconnected -> Connecting via tick() per INT-003.
    supp.pae_set_authenticate(true);
    supp.tick().unwrap();

    let json_after = serde_json::to_string(&supp.state()).unwrap();
    assert!(
        json_after.contains(r#""pae_state":"connecting""#),
        "expected connecting in {}",
        json_after
    );
}

/// Verifies: INT-006 (#114)
/// Per ARC-C-WPA-005 (#85).
///
/// When no `LogonProcess` is wired (today's default — `LogonProcess`
/// construction lands with INT-001 / #109), `logon_state` and
/// `selected_nid` are `null` in JSON.
#[test]
fn test_state_logon_fields_default_null_when_unwired() {
    let config = make_config();
    let net = TestNet::new();
    let supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    let state: SupplicantState = supp.state();
    assert_eq!(
        state.logon_state, None,
        "logon_state must be None until LogonProcess is wired (INT-001 / #109)"
    );
    assert_eq!(
        state.selected_nid, None,
        "selected_nid must be None until LogonProcess is wired (INT-001 / #109)"
    );

    let json = serde_json::to_string(&state).unwrap();
    assert!(
        json.contains(r#""logon_state":null"#),
        "expected null in {}",
        json
    );
    assert!(
        json.contains(r#""selected_nid":null"#),
        "expected null in {}",
        json
    );
}

/// Verifies: INT-006 (#114)
/// Per IEEE 802.1X-2020 Clause 9 (MKA) and ARC-C-WPA-005 (#85).
///
/// When no `MkaParticipant` is wired (today's default — MKA
/// construction lands with INT-005 / #113), `mka_established` is
/// `false` and `mka_live_peers` is `0`.
#[test]
fn test_state_mka_fields_default_when_unwired() {
    let config = make_config();
    let net = TestNet::new();
    let supp = Supplicant::with_eap_methods(config, net, Vec::new()).unwrap();

    let state = supp.state();
    assert!(
        !state.mka_established,
        "mka_established must be false until MkaParticipant is wired (INT-005 / #113)"
    );
    assert_eq!(
        state.mka_live_peers, 0,
        "mka_live_peers must be 0 until MkaParticipant is wired (INT-005 / #113)"
    );
}
