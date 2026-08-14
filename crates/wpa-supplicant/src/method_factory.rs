//! EAP method factory — converts [`EapMethodConfig`] into runtime EAP methods.
//!
//! Implements: #133 — reads PEM certificates from disk, constructs
//! [`RustlsTlsEngine`] instances, and wires them into [`EapTls`],
//! [`EapPeap`], or [`EapTeap`] method objects per the TOML config.
//!
//! Per ADR-FF-006 (#78): all EAP method construction is feature-gated
//! here. When no `eap-tls-rustls` feature is enabled, the legacy
//! no-methods path is used.
//!
//! IMPORTANT: This implementation is based on understanding of
//! IEEE 802.1X-2020 and RFC 5216. No copyrighted content from those
//! documents is reproduced.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use eap_peer::peer::TlsClientConfig;

use crate::config::EapMethodConfig;

// Re-export the production TLS engine so embedders (and integration
// tests) can construct `EapTls` / `EapPeap` / `EapTeap` methods
// directly with a rustls-backed engine, mirroring what `build_methods`
// does internally. Also satisfies this module's internal references.
pub use crate::rustls_engine::RustlsTlsEngine;

/// Output of the method factory: constructed methods + TLS config.
///
/// Per #133 (REQ-F-EAP-002 / 003 / 004).
pub struct MethodFactoryOutput {
    /// EAP methods to pass to [`EapSession::new`].
    pub methods: Vec<Box<dyn eap_peer::EapMethod>>,
    /// TLS client config built from the loaded PEM data.
    pub tls_config: TlsClientConfig,
}

/// Build EAP methods from [`EapMethodConfig`].
///
/// Per #133: reads PEM files from disk, constructs [`RustlsTlsEngine`]
/// instances, and wires them into the appropriate EAP method structs.
///
/// # Errors
/// Returns `Err` if any PEM file cannot be read or parsed.
pub fn build_methods(config: &EapMethodConfig) -> Result<MethodFactoryOutput> {
    match config {
        EapMethodConfig::Tls { cert, key, ca } => build_tls(cert, key, ca),
        #[cfg(feature = "eap-peap-rustls")]
        EapMethodConfig::Peap { ca, inner } => build_peap(ca, inner),
        #[cfg(not(feature = "eap-peap-rustls"))]
        EapMethodConfig::Peap { .. } => Err(anyhow::anyhow!(
            "EAP-PEAP requires the `eap-peap-rustls` feature"
        )),
        #[cfg(feature = "eap-teap-rustls")]
        EapMethodConfig::Teap { cert, key, ca } => build_teap(cert, key, ca),
        #[cfg(not(feature = "eap-teap-rustls"))]
        EapMethodConfig::Teap { .. } => Err(anyhow::anyhow!(
            "EAP-TEAP requires the `eap-teap-rustls` feature"
        )),
    }
}

/// Build an EAP-TLS method from PEM file paths.
fn build_tls(cert_path: &str, key_path: &str, ca_path: &str) -> Result<MethodFactoryOutput> {
    let cert_pem = read_pem(cert_path)?;
    let key_pem = read_pem(key_path)?;
    let ca_pem = read_pem(ca_path)?;

    let tls_config = TlsClientConfig {
        cert_chain: vec![cert_pem],
        private_key: zeroize::Zeroizing::new(key_pem),
        ca_certs: vec![ca_pem],
        verify_server: true,
    };

    let engine = Arc::new(Mutex::new(RustlsTlsEngine::new()));
    // The engine is initialized lazily by EapTls::handle_request when it
    // receives the TLS-Start flag and reads tls_config from ctx.

    let method = eap_peer::EapTls::new(engine);
    Ok(MethodFactoryOutput {
        methods: vec![Box::new(method)],
        tls_config,
    })
}

/// Build an EAP-PEAP method with a recursive inner method.
#[cfg(feature = "eap-peap-rustls")]
fn build_peap(ca_path: &str, inner: &EapMethodConfig) -> Result<MethodFactoryOutput> {
    let ca_pem = read_pem(ca_path)?;

    // Recursively build inner method(s).
    let inner_output = build_methods(inner)?;

    let tls_config = TlsClientConfig {
        cert_chain: Vec::new(), // PEAP outer: server-only auth typically.
        private_key: zeroize::Zeroizing::new(Vec::new()),
        ca_certs: vec![ca_pem],
        verify_server: true,
    };

    let engine = Arc::new(Mutex::new(RustlsTlsEngine::new()));

    // PEAP has exactly one inner method.
    let inner_method = inner_output
        .methods
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("PEAP requires at least one inner method"))?;

    let method = eap_peer::EapPeap::new(engine, inner_method);
    Ok(MethodFactoryOutput {
        methods: vec![Box::new(method)],
        tls_config,
    })
}

/// Build an EAP-TEAP method from PEM file paths.
///
/// Inner methods from TOML config are deferred — the current
/// [`EapMethodConfig::Teap`] has no `inner` field. TEAP with no inner
/// methods is valid for machine-only auth (the TLS tunnel itself
/// provides authentication per RFC 7170).
#[cfg(feature = "eap-teap-rustls")]
fn build_teap(
    cert_path: &Option<String>,
    key_path: &Option<String>,
    ca_path: &str,
) -> Result<MethodFactoryOutput> {
    let ca_pem = read_pem(ca_path)?;
    let cert_pem = cert_path.as_ref().map(|p| read_pem(p)).transpose()?;
    let key_pem = key_path.as_ref().map(|p| read_pem(p)).transpose()?;

    let tls_config = TlsClientConfig {
        cert_chain: cert_pem.map(|c| vec![c]).unwrap_or_default(),
        private_key: zeroize::Zeroizing::new(key_pem.unwrap_or_default()),
        ca_certs: vec![ca_pem],
        verify_server: true,
    };

    let engine = Arc::new(Mutex::new(RustlsTlsEngine::new()));

    // TEAP inner methods are not yet configurable via TOML.
    // Per #133: TEAP with no inner methods is valid for machine-only
    // auth (the TLS tunnel itself provides authentication).
    let method = eap_peer::EapTeap::new(engine, Vec::new());
    Ok(MethodFactoryOutput {
        methods: vec![Box::new(method)],
        tls_config,
    })
}

/// Read a PEM file from disk into bytes.
fn read_pem(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read PEM file {}: {}", path, e))
}
