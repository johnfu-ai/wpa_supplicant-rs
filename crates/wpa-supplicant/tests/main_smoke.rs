//! Smoke test for INT-001 (#109) — the binary entry point's
//! config-load → Supplicant construction → tick() path works end-to-end
//! against a temp-file configuration.
//!
//! Verifies: INT-001 (#109)
//! Per REQ-NF-DEPLOY-003 (#70) — Configuration File Support.
//! Architecture: ARC-C-WPA-005 (#85), ADR-EVT-007 (#79).

use std::io::Write;
use std::sync::Mutex;

use anyhow::Result;
use wpa_supplicant::{Config, NetworkIo, Supplicant};

/// In-test stub `NetworkIo` — drops sends, has nothing to receive,
/// reports link-up so the supplicant constructs in the `Idle`
/// reconnection state.
struct StubNet {
    mac: [u8; 6],
    link: Mutex<bool>,
}

impl StubNet {
    fn new() -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x10],
            link: Mutex::new(true),
        }
    }
}

impl NetworkIo for StubNet {
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

/// Verifies: INT-001 (#109)
/// Per REQ-NF-DEPLOY-003 (#70).
///
/// `Config::load(&Path)` round-trips a TOML file from disk, and the
/// loaded `Config` can construct a `Supplicant` whose `tick()` returns
/// `Ok`. This is the smoke test the binary entry point relies on.
#[test]
fn test_config_load_then_supplicant_tick() {
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile create");
    write!(
        tmp,
        r#"
interface = "eth0"

[eap]
identity = "smoke@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#
    )
    .expect("tempfile write");
    tmp.flush().expect("tempfile flush");

    let config = Config::load(tmp.path()).expect("Config::load must accept the temp file");
    assert_eq!(config.interface, "eth0");
    assert_eq!(config.eap.identity, "smoke@example.com");

    let net = StubNet::new();
    let mut supp = Supplicant::new(config, net).expect("Supplicant must construct");

    // tick() must return Ok on a freshly-constructed supplicant with
    // nothing on the wire — the binary entry point invokes tick in
    // a loop.
    let events = supp.tick().expect("tick() must succeed");
    assert!(events.is_empty(), "no events expected on a quiet tick");
}

/// Verifies: INT-001 (#109)
/// Per REQ-NF-DEPLOY-003 (#70).
///
/// `Config::load` returns an error (rather than panicking) when the
/// path does not exist — the binary's entry point relies on this for
/// a clean non-zero exit with a tracing `error!`.
#[test]
fn test_config_load_missing_file_returns_error() {
    let path = std::path::Path::new("/nonexistent/wpa_supplicant-rs-int001-smoke.toml");
    let result = Config::load(path);
    assert!(
        result.is_err(),
        "Config::load on a missing path must return Err (got {:?})",
        result.map(|_| "Ok").err()
    );
}

/// Verifies: INT-001 (#109)
/// Per REQ-NF-DEPLOY-003 (#70).
///
/// `Config::load` rejects malformed TOML — the binary maps this to a
/// non-zero exit instead of panicking inside `expect`.
#[test]
fn test_config_load_malformed_toml_returns_error() {
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile create");
    writeln!(tmp, "interface = \"eth0\"").unwrap();
    writeln!(tmp, "this is not valid TOML at all === ???").unwrap();
    tmp.flush().unwrap();

    let result = Config::load(tmp.path());
    assert!(
        result.is_err(),
        "malformed TOML must yield Err from Config::load"
    );
}
