//! Rustls-backed [`TlsEngine`] implementation for EAP-TLS.
//!
//! Implements: #133 — loads PEM certificates into a rustls
//! [`ClientConfig`], drives the TLS handshake, and exports the MSK
//! via TLS-Exporter per RFC 5216 §2.3.
//!
//! Per ADR-SM-002 (#74): the [`TlsEngine`] trait is the DI seam;
//! this module provides the production concrete implementation.
//!
//! IMPORTANT: This implementation is based on understanding of RFC 5216
//! and RFC 5705 (TLS Keying Material Exporters). No copyrighted content
//! from those RFCs is reproduced.

use std::sync::Arc;

use eap_peer::peer::TlsClientConfig;
use eap_peer::{EapError, TlsEngine};
// PEM decoding per RUSTSEC-2025-0134: rustls-pemfile is unmaintained;
// the maintained `PemObject` API lives in rustls-pki-types.
use rustls::pki_types::pem::PemObject;

/// Rustls-backed TLS engine for EAP-TLS.
///
/// Per #133: wraps a [`rustls::ClientConnection`] to implement the
/// [`TlsEngine`] trait. Tunnel methods (PEAP/TEAP) get passthrough
/// stubs for `recv_tunnel_data` / `send_tunnel_data` — actual TLS
/// record-layer splitting is deferred to a follow-up.
#[derive(Default)]
pub struct RustlsTlsEngine {
    /// The loaded TLS client connection. `None` before `init_session`.
    conn: Option<rustls::ClientConnection>,
}

impl RustlsTlsEngine {
    /// Create a new, uninitialized engine.
    ///
    /// Per #133 (REQ-F-EAP-002 / 003 / 004).
    pub fn new() -> Self {
        Self { conn: None }
    }

    /// Load PEM certificates from [`TlsClientConfig`] fields into a
    /// rustls [`ClientConfig`].
    ///
    /// Two axes, both honored:
    /// * **Server verification** (`verify_server`): when `true` (the
    ///   production default per RFC 5216 / RFC 7170) the server cert is
    ///   validated against `ca_certs`. When `false` the F-08 escape
    ///   hatch is taken — verification is skipped via rustls's
    ///   `dangerous` API. This is only for lab/interop with self-signed
    ///   certs the operator cannot pin; the factory never sets it
    ///   `false` for production EAP-TLS.
    /// * **Client auth** (`cert_chain`): when a client cert chain is
    ///   present it is offered for mutual auth (EAP-TLS); when empty
    ///   (PEAP / TEAP outer, or machine-only) `with_no_client_auth` is
    ///   used and the private key is not required.
    fn build_client_config(
        config: &TlsClientConfig,
    ) -> Result<Arc<rustls::ClientConfig>, EapError> {
        // 1. Parse the client cert chain (may be empty).
        let certs = parse_certs(&config.cert_chain, "cert")?;

        // 2. Build the server-verification half.
        let builder = if config.verify_server {
            let mut root_store = rustls::RootCertStore::empty();
            let ca_certs = parse_certs(&config.ca_certs, "ca")?;
            for ca in ca_certs {
                root_store
                    .add(ca)
                    .map_err(|e| EapError::TlsError(format!("add CA: {e}")))?;
            }
            rustls::ClientConfig::builder().with_root_certificates(root_store)
        } else {
            // F-08: skip server-cert verification. The factory never
            // reaches this branch for production EAP-TLS.
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
        };

        // 3. Apply client auth (only when a client cert was provided).
        let client_config = if certs.is_empty() {
            builder.with_no_client_auth()
        } else {
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&config.private_key)
                .map_err(|e| EapError::TlsError(format!("key parse: {e}")))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| EapError::TlsError(format!("client config: {e}")))?
        };

        // Per RFC 5216: EAP-TLS doesn't use SNI in the traditional
        // sense. The server certificate is validated against the root
        // store; SNI is not required.
        Ok(Arc::new(client_config))
    }
}

impl TlsEngine for RustlsTlsEngine {
    fn init_session(&mut self, config: &TlsClientConfig) -> Result<(), EapError> {
        let client_config = Self::build_client_config(config)?;
        // Use a dummy server name for rustls (SNI is not used in EAP-TLS).
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|e| EapError::TlsError(format!("server name: {e}")))?;
        let conn = rustls::ClientConnection::new(client_config, server_name)
            .map_err(|e| EapError::TlsError(format!("client conn: {e}")))?;
        self.conn = Some(conn);
        Ok(())
    }

    fn process_server_data(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, EapError> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| EapError::TlsError("engine not initialized".into()))?;

        // Feed server data into rustls.
        if !data.is_empty() {
            let mut cursor = std::io::Cursor::new(data);
            conn.read_tls(&mut cursor)
                .map_err(|e| EapError::TlsError(format!("read_tls: {e}")))?;
        }

        // Process any received TLS records. A rustls `Err` here is
        // fatal for the connection (corrupt record, peer misbehaved,
        // alert) — propagate it so the EAP layer can fail the method
        // instead of hanging on a dead handshake. Mid-handshake "need
        // more data" is `Ok`, not `Err`, so no benign state is lost.
        conn.process_new_packets()
            .map_err(|e| EapError::TlsError(format!("process_new_packets: {e}")))?;

        // Extract any outbound TLS data to send back.
        let mut out = Vec::new();
        if conn.wants_write() {
            conn.write_tls(&mut out)
                .map_err(|e| EapError::TlsError(format!("write_tls: {e}")))?;
        }

        if conn.is_handshaking() {
            // More data needed — return outbound bytes or empty
            Ok(Some(out))
        } else if out.is_empty() {
            // Handshake complete, no more data to send
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }

    fn is_handshake_complete(&self) -> bool {
        self.conn.as_ref().is_some_and(|c| !c.is_handshaking())
    }

    /// The TLS session identifier for the EAP Session-Id per RFC 5216
    /// §1.4 / RFC 9190 §2.3 (#174 / F-EAP-1).
    ///
    /// * TLS 1.3 — `Method-Id = TLS-Exporter("EXPORTER_EAP_TLS_Method-Id",
    ///   Type, 64)`; the EAP Session-Id is `0x0D || Method-Id`.
    /// * TLS 1.2 — RFC 5216 §1.4 wants the negotiated TLS session ID,
    ///   which rustls 0.23 does not expose publicly; this returns `None`
    ///   and the EAP Session-Id degrades to the type byte alone
    ///   (documented limitation in `docs/IMPROVEMENTS.md` F-EAP-1).
    fn session_id(&self) -> Option<Vec<u8>> {
        let conn = self.conn.as_ref()?;
        if conn.is_handshaking() {
            return None;
        }
        match conn.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => {
                // Per RFC 9190 §2.3: 64-octet exporter-derived Method-Id.
                // The EAP Type code (0x0D) is the exporter *context*.
                let mut method_id = vec![0u8; 64];
                conn.export_keying_material(
                    &mut method_id,
                    b"EXPORTER_EAP_TLS_Method-Id",
                    Some(&[eap_peer::peer::EapType::Tls.value()]),
                )
                .ok()?;
                Some(method_id)
            }
            _ => None,
        }
    }

    fn derive_msk(&mut self) -> Result<pae::Msk, EapError> {
        let conn = self
            .conn
            .as_ref()
            .ok_or_else(|| EapError::TlsError("engine not initialized".into()))?;

        if conn.is_handshaking() {
            return Err(EapError::TlsError("handshake not complete".into()));
        }

        // Per RFC 9190 §2.3 (TLS 1.3): Key_Material =
        // TLS-Exporter("EXPORTER_EAP_TLS_Key_Material", Type, 128) —
        // the EAP Type code (0x0D) is the exporter *context*. First
        // 64 bytes = MSK, next 64 = EMSK. The `Msk` type enforces
        // >= 64 bytes at construction.
        //
        // Scope note: RFC 9190 scopes this exporter derivation to
        // TLS 1.3. Under TLS 1.2, RFC 5216 §2.3 prescribes a PRF
        // derivation over the handshake randoms instead — this engine
        // reuses the exporter for both versions, so a TLS 1.2 MSK will
        // not match an RFC 5216-conformant peer (tracked as #179,
        // surfaced for F-INT-1). rustls negotiates TLS 1.3 by default.
        let mut key_material = vec![0u8; 128];
        conn.export_keying_material(
            &mut key_material,
            b"EXPORTER_EAP_TLS_Key_Material",
            Some(&[eap_peer::peer::EapType::Tls.value()]),
        )
        .map_err(|e| EapError::TlsError(format!("export_keying_material: {e}")))?;

        // Take first 64 bytes as MSK.
        pae::Msk::from_bytes(key_material[..64].to_vec())
            .map_err(|e| EapError::TlsError(e.to_string()))
    }

    fn reset(&mut self) {
        self.conn = None;
    }
}

/// Parse one or more PEM blobs into DER certificates.
///
/// Each entry in `pems` is raw PEM bytes (as stored in
/// [`TlsClientConfig`]); a single PEM file may carry several certs.
/// `label` is used only to qualify error messages ("cert" vs "ca").
fn parse_certs(
    pems: &[Vec<u8>],
    label: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, EapError> {
    let mut certs: Vec<rustls::pki_types::CertificateDer> = Vec::new();
    for pem in pems {
        let parsed = rustls::pki_types::CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| EapError::TlsError(format!("{label} parse: {e}")))?;
        certs.extend(parsed);
    }
    Ok(certs)
}

/// `ServerCertVerifier` that accepts any server certificate.
///
/// Used only on the F-08 `verify_server = false` escape-hatch —
/// lab/interop with self-signed certs the operator cannot pin. The
/// method factory never constructs a `TlsClientConfig` with
/// `verify_server = false` for production EAP-TLS, so this struct is
/// unreachable from the daemon's normal path.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Pretend to support the common schemes so negotiation never
        // fails on the no-verify path; verification is a no-op anyway.
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed cert for engine unit tests.
    fn test_cert() -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(["engine-test.example.com".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "wpa_supplicant-rs");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "engine-test.example.com");
        let cert = params.self_signed(&key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    /// Verifies: #133
    /// Engine initializes a TLS session with a valid cert.
    #[test]
    fn test_rustls_engine_init_session() {
        let (cert_pem, key_pem) = test_cert();
        let config = TlsClientConfig {
            cert_chain: vec![cert_pem.clone()],
            private_key: zeroize::Zeroizing::new(key_pem),
            ca_certs: vec![cert_pem],
            verify_server: false,
        };

        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&config).unwrap();
        // After init_session with client cert, the engine has created
        // a ClientConnection. is_handshake_complete is false because
        // the handshake hasn't started yet (no server data).
        assert!(!engine.is_handshake_complete());
    }

    /// Verifies: #133
    /// Engine reset drops the connection.
    #[test]
    fn test_rustls_engine_reset() {
        let (cert_pem, key_pem) = test_cert();
        let config = TlsClientConfig {
            cert_chain: vec![cert_pem.clone()],
            private_key: zeroize::Zeroizing::new(key_pem),
            ca_certs: vec![cert_pem],
            verify_server: false,
        };

        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&config).unwrap();
        engine.reset();
        assert!(!engine.is_handshake_complete());
        assert!(engine.conn.is_none());
    }

    /// Verifies: #133
    /// derive_msk fails when handshake is not complete.
    #[test]
    fn test_derive_msk_fails_before_handshake() {
        let (cert_pem, key_pem) = test_cert();
        let config = TlsClientConfig {
            cert_chain: vec![cert_pem.clone()],
            private_key: zeroize::Zeroizing::new(key_pem),
            ca_certs: vec![cert_pem],
            verify_server: false,
        };

        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&config).unwrap();
        let result = engine.derive_msk();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("handshake not complete"));
    }

    /// Verifies: #133 (traceability-review warning: fatal rustls errors
    /// must surface as `EapError`, not be silently swallowed).
    /// A corrupt TLS handshake record fed to the engine must return
    /// `Err` — otherwise a fatal peer error would hang the EAP
    /// conversation instead of yielding EAP-Failure.
    #[test]
    fn test_process_server_data_propagates_corrupt_record_error() {
        let (cert_pem, key_pem) = test_cert();
        let config = TlsClientConfig {
            cert_chain: vec![cert_pem.clone()],
            private_key: zeroize::Zeroizing::new(key_pem),
            ca_certs: vec![cert_pem],
            verify_server: false,
        };

        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&config).unwrap();

        // Well-formed record header (handshake, TLS 1.2 version, 32-byte
        // payload) wrapping garbage handshake bytes. `read_tls` accepts
        // the framing; `process_new_packets` must reject the content.
        let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x20];
        record.extend_from_slice(&[0xAA; 32]);

        let result = engine.process_server_data(&record);
        assert!(
            result.is_err(),
            "corrupt handshake record must surface as EapError, got {result:?}"
        );
    }

    // --- Full loopback handshake (the end-to-end engine proof) ---

    /// Generate a self-signed cert (SAN=localhost) + its PKCS#8 key for
    /// driving a real loopback TLS handshake.
    fn loopback_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "loopback-test");
        let cert = params.self_signed(&key).unwrap();
        (
            cert.der().to_vec(),          // server DER cert
            key.serialize_der().to_vec(), // PKCS#8 key
            cert.pem().into_bytes(),      // PEM (used as the client's CA)
        )
    }

    /// Drive a TLS handshake between the engine (client) and a rustls
    /// `ServerConnection` until both sides stop, alternating flights.
    fn drive_handshake(
        client: &mut RustlsTlsEngine,
        server: &mut rustls::ServerConnection,
    ) -> Result<(), EapError> {
        use std::io::Cursor;
        // Kick off: client emits ClientHello from an empty input.
        let mut to_server = client.process_server_data(&[])?.unwrap_or_default();
        for _ in 0..16 {
            if !to_server.is_empty() {
                server
                    .read_tls(&mut Cursor::new(&to_server))
                    .map_err(|e| EapError::TlsError(format!("server read_tls: {e}")))?;
                let _ = server.process_new_packets();
            }
            let mut to_client = Vec::new();
            server
                .write_tls(&mut to_client)
                .map_err(|e| EapError::TlsError(format!("server write_tls: {e}")))?;
            if to_client.is_empty() {
                break; // server has nothing more to send
            }
            match client.process_server_data(&to_client)? {
                Some(out) => to_server = out,
                None => break, // client reports complete / nothing to send
            }
            if client.is_handshake_complete() && to_server.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Verifies: #133 (REQ-F-EAP-002)
    /// Per RFC 5216 §2.3: the engine drives a real TLS 1.2 handshake
    /// to completion against a loopback rustls server (verify_server =
    /// true, server cert validated against the loaded CA) and exports an
    /// MSK of at least 64 bytes via the TLS-Exporter. This is the
    /// end-to-end proof that PEM loading + engine construction +
    /// handshake + key derivation actually authenticate.
    #[test]
    fn test_rustls_engine_full_handshake_exports_msk() {
        let (server_der, server_key_pkcs8, ca_pem) = loopback_cert();

        // Server: presents the cert, does not request client auth.
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(server_der)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(server_key_pkcs8),
                ),
            )
            .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).unwrap();

        // Client (engine): verify_server=true, CA=presented cert, no
        // client cert (server does not request one).
        let client_cfg = TlsClientConfig {
            cert_chain: Vec::new(),
            private_key: zeroize::Zeroizing::new(Vec::new()),
            ca_certs: vec![ca_pem],
            verify_server: true,
        };
        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&client_cfg).unwrap();

        drive_handshake(&mut engine, &mut server).unwrap();
        assert!(
            engine.is_handshake_complete(),
            "TLS handshake must complete against the loopback server"
        );

        let msk = engine.derive_msk().expect("MSK export must succeed");
        assert!(msk.len() >= 64, "MSK must be >=64 bytes per RFC 3748");
    }

    /// Verifies: #174 (REQ-F-EAP-002) — F-EAP-1
    /// Per RFC 9190 §2.3 (TLS 1.3): Session-Id = 0x0D || Method-Id where
    /// Method-Id = TLS-Exporter("EXPORTER_EAP_TLS_Method-Id", Type, 64).
    /// Under TLS 1.2 (RFC 5216 §1.4) the TLS session ID is needed but is
    /// not exposed by rustls 0.23 — the engine then reports `None` and
    /// the EAP Session-Id degrades to the type byte alone (documented
    /// limitation, docs/IMPROVEMENTS.md F-EAP-1).
    #[test]
    fn test_rustls_engine_session_id_after_handshake() {
        let (server_der, server_key_pkcs8, ca_pem) = loopback_cert();

        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(server_der)],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(server_key_pkcs8),
                ),
            )
            .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_cfg)).unwrap();

        let client_cfg = TlsClientConfig {
            cert_chain: Vec::new(),
            private_key: zeroize::Zeroizing::new(Vec::new()),
            ca_certs: vec![ca_pem],
            verify_server: true,
        };
        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&client_cfg).unwrap();
        drive_handshake(&mut engine, &mut server).unwrap();
        assert!(engine.is_handshake_complete());

        let negotiated = engine
            .conn
            .as_ref()
            .and_then(|c| c.protocol_version())
            .expect("negotiated version after handshake");
        if negotiated == rustls::ProtocolVersion::TLSv1_3 {
            let sid = engine
                .session_id()
                .expect("TLS 1.3 session id via exporter per RFC 9190 2.3");
            assert_eq!(sid.len(), 64, "Method-Id is 64 octets per RFC 9190 2.3");
        } else {
            // TLS 1.2: rustls 0.23 does not expose the negotiated
            // session ID; the documented fallback is `None`.
            assert_eq!(engine.session_id(), None);
        }
    }

    /// Verifies: #133 (REQ-F-EAP-003/004)
    /// The no-client-cert path (PEAP/TEAP outer, or machine-only) inits
    /// without a private key: `cert_chain` empty → `with_no_client_auth`.
    #[test]
    fn test_rustls_engine_no_client_cert_inits() {
        let (_server_der, _server_key, ca_pem) = loopback_cert();
        let config = TlsClientConfig {
            cert_chain: Vec::new(),
            private_key: zeroize::Zeroizing::new(Vec::new()),
            ca_certs: vec![ca_pem],
            verify_server: true,
        };
        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&config).unwrap();
        assert!(!engine.is_handshake_complete());
    }

    /// Verifies: #133 / security-review F-08
    /// The `verify_server = false` escape-hatch inits with NO CA certs
    /// at all — proving the NoVerify verifier path is wired and does
    /// not require pinnable roots. The factory never produces this for
    /// production EAP-TLS.
    #[test]
    fn test_rustls_engine_verify_false_needs_no_ca() {
        let config = TlsClientConfig {
            cert_chain: Vec::new(),
            private_key: zeroize::Zeroizing::new(Vec::new()),
            ca_certs: Vec::new(),
            verify_server: false,
        };
        let mut engine = RustlsTlsEngine::new();
        engine.init_session(&config).unwrap();
        assert!(!engine.is_handshake_complete());
    }
}
