//! Integration tests for #133 — EAP method factory with PEM loading.
//!
//! Verifies that the factory converts `EapMethodConfig` into real EAP
//! method objects with TLS engines configured from PEM files, that the
//! `Supplicant` constructors wire the factory in, and that bad PEM
//! paths fail fast at construction.
//!
//! Verifies: #133 (REQ-F-EAP-002/003/004)
//! Per IEEE 802.1X-2020, RFC 5216. Architecture: ADR-FF-006 (#78).

#![cfg(feature = "eap-tls-rustls")]

use std::sync::{Arc, Mutex};

use eap_peer::EapTls;
use wpa_supplicant::method_factory;
use wpa_supplicant::method_factory::RustlsTlsEngine;
use wpa_supplicant::{Config, NoopNetworkIo, Supplicant};

/// Generate a throwaway self-signed cert + key pair for testing.
/// Returns (cert_pem, key_pem).
fn generate_test_cert() -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "wpa_supplicant-rs interop");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test.example.com");
    let cert = params.self_signed(&key).unwrap();
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

/// Verifies: #133 (REQ-F-EAP-002)
/// Factory produces an EapTls method from EapMethodConfig::Tls and a
/// TLS config carrying the loaded PEM material.
#[test]
fn test_factory_builds_eap_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = generate_test_cert();
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    std::fs::write(&ca_path, &cert_pem).unwrap(); // self-signed: cert is CA

    let toml = format!(
        r#"
interface = "eth0"
[eap]
identity = "test@example.com"
[eap.method]
type = "tls"
cert = "{}"
key = "{}"
ca = "{}"
"#,
        cert_path.display(),
        key_path.display(),
        ca_path.display()
    );

    let config = Config::from_toml(&toml).unwrap();
    let output = method_factory::build_methods(&config.eap.method).unwrap();
    assert_eq!(output.methods.len(), 1);
    assert_eq!(output.tls_config.cert_chain.len(), 1);
    // verify_server defaults to true for production EAP-TLS per RFC 5216.
    assert!(output.tls_config.verify_server);
}

/// Verifies: #133
/// The factory validates PEM existence at construction (the correct
/// fail-fast layer — not config parsing). A missing file yields an
/// error naming the path, so the daemon never starts with a bad config.
#[test]
fn test_factory_rejects_missing_pem() {
    let dir = tempfile::tempdir().unwrap();
    // cert/key present, ca missing.
    let (cert_pem, key_pem) = generate_test_cert();
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();

    let toml = format!(
        r#"
interface = "eth0"
[eap]
identity = "test@example.com"
[eap.method]
type = "tls"
cert = "{}"
key = "{}"
ca = "{dir}/missing-ca.pem"
"#,
        cert_path.display(),
        key_path.display(),
        dir = dir.path().display()
    );

    let config = Config::from_toml(&toml).unwrap();
    let err = match method_factory::build_methods(&config.eap.method) {
        Ok(_) => panic!("missing PEM must fail the factory"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("missing-ca.pem"),
        "error should name the missing path; got: {err}"
    );

    // And Supplicant::new must propagate the same failure.
    let net = NoopNetworkIo::new([0x02; 6], true);
    let supp = Supplicant::new(config, net);
    assert!(supp.is_err(), "Supplicant::new must fail on missing PEM");
}

/// Verifies: #133 (REQ-F-EAP-003)
/// Factory builds PEAP with a recursive inner TLS method.
#[cfg(feature = "eap-peap-rustls")]
#[test]
fn test_factory_builds_peap_with_inner_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, _key_pem) = generate_test_cert();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &cert_pem).unwrap();

    let toml = format!(
        r#"
interface = "eth0"
[eap]
identity = "test@example.com"
[eap.method]
type = "peap"
ca = "{ca}"
[eap.method.inner]
type = "tls"
cert = "{ca}"
key = "{ca}"
ca = "{ca}"
"#,
        ca = ca_path.display()
    );

    let config = Config::from_toml(&toml).unwrap();
    let output = method_factory::build_methods(&config.eap.method).unwrap();
    assert_eq!(output.methods.len(), 1, "PEAP produces exactly 1 method");
}

/// Verifies: #133 (REQ-F-EAP-004)
/// Factory builds TEAP with optional (absent) client cert/key.
#[cfg(feature = "eap-teap-rustls")]
#[test]
fn test_factory_builds_teap_machine_only() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, _key_pem) = generate_test_cert();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &cert_pem).unwrap();

    let toml = format!(
        r#"
interface = "eth0"
[eap]
identity = "host.example.com"
[eap.method]
type = "teap"
ca = "{ca}"
"#,
        ca = ca_path.display()
    );

    let config = Config::from_toml(&toml).unwrap();
    let output = method_factory::build_methods(&config.eap.method).unwrap();
    assert_eq!(output.methods.len(), 1, "TEAP produces exactly 1 method");
}

/// Verifies: #133
/// `Supplicant::new` wires the factory: with valid PEM config it
/// constructs cleanly and a tick runs without panic. With the feature
/// off this path returns no methods; with it on, real EAP-TLS is built.
#[test]
fn test_supplicant_new_loads_factory_methods() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = generate_test_cert();
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, &key_pem).unwrap();
    std::fs::write(&ca_path, &cert_pem).unwrap();

    let toml = format!(
        r#"
interface = "eth0"
[eap]
identity = "test@example.com"
[eap.method]
type = "tls"
cert = "{cert}"
key = "{key}"
ca = "{ca}"
"#,
        cert = cert_path.display(),
        key = key_path.display(),
        ca = ca_path.display()
    );

    let config = Config::from_toml(&toml).unwrap();
    let net = NoopNetworkIo::new([0x02; 6], true);
    let mut supp = Supplicant::new(config, net).expect("factory-wired Supplicant builds");
    // A tick must not panic even though no real authenticator is present.
    let _ = supp.tick();
}

/// Verifies: #133
/// `with_eap_methods` is the explicit test-injection path — it always
/// bypasses the factory, so a placeholder config with bogus PEM paths
/// still builds (the injected method list wins).
#[test]
fn test_with_eap_methods_bypasses_factory() {
    let toml = r#"
interface = "eth0"
[eap]
identity = "test@example.com"
[eap.method]
type = "tls"
cert = "/nonexistent/cert.pem"
key = "/nonexistent/key.pem"
ca = "/nonexistent/ca.pem"
"#;
    let config = Config::from_toml(toml).unwrap();
    let net = NoopNetworkIo::new([0x02; 6], true);
    // Inject one real EapTls method — the factory must not run, so the
    // nonexistent PEM paths never get read.
    let engine = Arc::new(Mutex::new(RustlsTlsEngine::new()));
    let methods: Vec<Box<dyn eap_peer::EapMethod>> = vec![Box::new(EapTls::new(engine))];
    let supp = Supplicant::with_eap_methods(config, net, methods);
    assert!(supp.is_ok(), "explicit injection bypasses PEM loading");
}
