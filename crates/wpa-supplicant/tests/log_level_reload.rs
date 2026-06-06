//! Integration test for INT-009 (#117) — runtime log-level reload via
//! `tracing-subscriber` on `ControlCommand::SetLogLevel`.
//!
//! Verifies: INT-009 (#117)
//! Per REQ-NF-DEPLOY-001 (#68) acceptance criterion (runtime level
//! changes without restart) and ADR-EVT-007 (#79) control-interface
//! dispatch.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use wpa_supplicant::{Config, ControlCommand, Logging, NetworkIo, Supplicant};

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

/// Test stand-in for `Logging::set_level` — tracks every level requested
/// so the test can assert the supplicant's control-command path actually
/// invoked the reload. Avoids depending on a real `tracing-subscriber`
/// registry (which can only be initialized once per process).
fn make_recording_logging() -> (Logging, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let log_clone = Arc::clone(&log);
    let logging = Logging::from_test_handle(Arc::new(move |level: &str| {
        log_clone.lock().unwrap().push(level.to_string());
        Ok(())
    }));
    (logging, log)
}

/// Verifies: INT-009 (#117)
/// Per REQ-NF-DEPLOY-001 (#68) and ADR-EVT-007 (#79).
///
/// `ControlCommand::SetLogLevel { level }` routes through the supplicant
/// into `Logging::set_level()` — observable via the recording handle.
#[test]
fn test_set_log_level_invokes_logging_reload() {
    let config = make_config();
    let net = TestNet::new();
    let (logging, log) = make_recording_logging();
    let mut supp = Supplicant::with_logging(config, net, logging).unwrap();

    supp.handle_command(ControlCommand::SetLogLevel {
        level: "debug".to_string(),
    })
    .unwrap();

    let recorded = log.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["debug".to_string()],
        "set_log_level must call Logging::set_level exactly once with the requested level"
    );
}

/// Verifies: INT-009 (#117)
/// Per REQ-NF-DEPLOY-001 (#68).
///
/// Multiple SetLogLevel commands accumulate; each call is independent
/// and the supplicant never panics on a reload error.
#[test]
fn test_multiple_set_log_levels_routed() {
    let config = make_config();
    let net = TestNet::new();
    let (logging, log) = make_recording_logging();
    let mut supp = Supplicant::with_logging(config, net, logging).unwrap();

    for level in &["trace", "wpa_supplicant=debug", "info", "warn"] {
        supp.handle_command(ControlCommand::SetLogLevel {
            level: (*level).to_string(),
        })
        .unwrap();
    }

    let recorded = log.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![
            "trace".to_string(),
            "wpa_supplicant=debug".to_string(),
            "info".to_string(),
            "warn".to_string(),
        ]
    );
}

/// Verifies: INT-009 (#117)
/// Per ADR-EVT-007 (#79).
///
/// If the reload handle returns an error (e.g. an unparseable filter
/// directive), the control command still returns `Ok(())` — the daemon
/// must never crash on a control-socket request.
#[test]
fn test_set_log_level_reload_error_does_not_crash_daemon() {
    let config = make_config();
    let net = TestNet::new();
    let logging = Logging::from_test_handle(Arc::new(|_level: &str| {
        Err(anyhow::anyhow!("simulated reload failure"))
    }));
    let mut supp = Supplicant::with_logging(config, net, logging).unwrap();

    let result = supp.handle_command(ControlCommand::SetLogLevel {
        level: "garbage===filter".to_string(),
    });

    assert!(
        result.is_ok(),
        "reload failures must not propagate to the control-command return"
    );
}
