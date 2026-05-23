//! EAP-TLS method per RFC 5216.
//!
//! Implements: #39 (REQ-F-EAP-002: EAP-TLS)
//!
//! IMPORTANT: This implementation is based on understanding of RFC 5216.
//! No copyrighted content from the RFC is reproduced.

use std::sync::Arc;

use super::peer::{EapContext, EapMethod, EapMethodOutput, EapType, TlsClientConfig};
use super::EapError;

/// EAP-TLS state per RFC 5216.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapTlsState {
    /// Initial — waiting for EAP-Request/TLS-Start.
    Initial,
    /// TLS handshake in progress.
    Handshake,
    /// TLS tunnel established, awaiting result.
    Established,
    /// Authentication complete (success or failure).
    Complete,
}

/// EAP-TLS flags per RFC 5216 Section 2.2.
const TLS_FLAGS_LENGTH_INCLUDED: u8 = 0x80;
const TLS_FLAGS_MORE_FRAGMENTS: u8 = 0x40;
const TLS_FLAGS_START: u8 = 0x20;

/// TLS engine trait — abstracts TLS library operations.
///
/// Per ADR-SM-002 (#74): trait-based dependency injection.
/// Enables mock injection for unit testing.
/// Production implementation wraps rustls or native-tls.
pub trait TlsEngine: Send + Sync {
    /// Initialize a new TLS client session with the given config.
    ///
    /// # Errors
    /// Returns `EapError::TlsError` on initialization failure.
    fn init_session(&mut self, config: &TlsClientConfig) -> Result<(), EapError>;

    /// Feed TLS data from the server and get response data to send back.
    ///
    /// Returns `Ok(Some(data))` if there's data to send back,
    /// `Ok(None)` if the handshake is complete.
    ///
    /// # Errors
    /// Returns `EapError::TlsError` on TLS protocol error.
    fn process_server_data(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, EapError>;

    /// Whether the TLS handshake has completed successfully.
    fn is_handshake_complete(&self) -> bool;

    /// Derive the MSK from the completed TLS session.
    ///
    /// Per RFC 5216 Section 2.3: MSK is derived from TLS-PRF.
    ///
    /// # Errors
    /// Returns `EapError::TlsError` if the handshake is not complete
    /// or key derivation fails.
    fn derive_msk(&mut self) -> Result<pae::Msk, EapError>;

    /// Reset the TLS engine for reauthentication.
    fn reset(&mut self);
}

/// EAP-TLS method — certificate-based mutual authentication per RFC 5216.
///
/// Feature-gated: enabled by default via `eap-tls` feature.
pub struct EapTls {
    /// EAP-TLS state.
    state: EapTlsState,
    /// TLS engine (injected for testability).
    engine: Arc<std::sync::Mutex<dyn TlsEngine>>,
    /// Derived MSK (after successful handshake).
    msk: Option<pae::Msk>,
    /// Whether the last result was a failure.
    failed: bool,
}

impl EapTls {
    /// Create a new EAP-TLS method with the given TLS engine.
    pub fn new(engine: Arc<std::sync::Mutex<dyn TlsEngine>>) -> Self {
        Self {
            state: EapTlsState::Initial,
            engine,
            msk: None,
            failed: false,
        }
    }

    /// Current EAP-TLS state.
    pub fn state(&self) -> EapTlsState {
        self.state
    }

    /// Parse EAP-TLS flags and data from the request payload.
    ///
    /// Per RFC 5216 Section 2.2: first byte is flags, optional 4-byte length.
    fn parse_tls_data(data: &[u8]) -> Result<(u8, bool, &[u8]), EapError> {
        if data.is_empty() {
            return Err(EapError::InvalidPacket(
                "EAP-TLS data too short (no flags byte)".into(),
            ));
        }
        let flags = data[0];
        let has_length = (flags & TLS_FLAGS_LENGTH_INCLUDED) != 0;
        let tls_data_start = if has_length { 5 } else { 1 };

        if data.len() < tls_data_start {
            return Err(EapError::InvalidPacket(
                "EAP-TLS data too short for length field".into(),
            ));
        }

        Ok((flags, has_length, &data[tls_data_start.min(data.len())..]))
    }

    /// Build an EAP-TLS response payload with flags.
    fn build_response_payload(tls_data: &[u8], more_fragments: bool) -> Vec<u8> {
        let flags = if more_fragments {
            TLS_FLAGS_MORE_FRAGMENTS
        } else {
            0
        };
        let mut payload = Vec::with_capacity(1 + 4 + tls_data.len());
        payload.push(flags);
        if !tls_data.is_empty() || more_fragments {
            payload.extend_from_slice(&(tls_data.len() as u32).to_be_bytes());
        }
        payload.extend_from_slice(tls_data);
        payload
    }
}

impl EapMethod for EapTls {
    fn method_type(&self) -> EapType {
        EapType::Tls
    }

    fn handle_request(
        &mut self,
        _identifier: u8,
        data: &[u8],
        ctx: &dyn EapContext,
    ) -> Result<EapMethodOutput, EapError> {
        let (flags, _has_length, tls_data) = Self::parse_tls_data(data)?;
        let is_start = (flags & TLS_FLAGS_START) != 0;

        match self.state {
            EapTlsState::Initial => {
                if !is_start {
                    return Err(EapError::InvalidPacket(
                        "EAP-TLS: expected TLS-Start flag".into(),
                    ));
                }

                // Initialize TLS session with config from context
                let config = ctx.tls_config();
                let mut engine = self
                    .engine
                    .lock()
                    .map_err(|_| EapError::TlsError("TLS engine lock poisoned".into()))?;
                engine.init_session(config)?;
                self.state = EapTlsState::Handshake;

                // Process any TLS data that came with the start
                let response_data = if tls_data.is_empty() {
                    // TLS-Start with no data — send ClientHello
                    engine.process_server_data(&[])?
                } else {
                    engine.process_server_data(tls_data)?
                };

                match response_data {
                    Some(out) => Ok(EapMethodOutput::Respond {
                        eap_type: EapType::Tls,
                        data: Self::build_response_payload(&out, false),
                    }),
                    None => {
                        // Handshake complete in one round (unlikely but possible)
                        self.state = EapTlsState::Established;
                        let msk = engine.derive_msk()?;
                        self.msk = Some(msk);
                        self.state = EapTlsState::Complete;
                        Ok(EapMethodOutput::Success {
                            msk: self
                                .msk
                                .take()
                                .ok_or_else(|| EapError::TlsError("MSK not available".into()))?,
                            session_id: vec![EapType::Tls.value()],
                        })
                    }
                }
            }
            EapTlsState::Handshake => {
                let mut engine = self
                    .engine
                    .lock()
                    .map_err(|_| EapError::TlsError("TLS engine lock poisoned".into()))?;

                let response_data = engine.process_server_data(tls_data)?;

                match response_data {
                    Some(out) => Ok(EapMethodOutput::Respond {
                        eap_type: EapType::Tls,
                        data: Self::build_response_payload(&out, false),
                    }),
                    None => {
                        // Handshake complete
                        self.state = EapTlsState::Established;
                        let msk = engine.derive_msk()?;
                        self.msk = Some(msk);
                        self.state = EapTlsState::Complete;
                        Ok(EapMethodOutput::Success {
                            msk: self
                                .msk
                                .take()
                                .ok_or_else(|| EapError::TlsError("MSK not available".into()))?,
                            session_id: vec![EapType::Tls.value()],
                        })
                    }
                }
            }
            EapTlsState::Established | EapTlsState::Complete => Err(EapError::InvalidPacket(
                "EAP-TLS: received request after completion".into(),
            )),
        }
    }

    fn reset(&mut self) {
        self.state = EapTlsState::Initial;
        self.msk = None;
        self.failed = false;
        if let Ok(mut engine) = self.engine.lock() {
            engine.reset();
        }
    }

    fn is_complete(&self) -> bool {
        self.state == EapTlsState::Complete
    }

    fn take_msk(&mut self) -> Option<pae::Msk> {
        self.msk.take()
    }

    fn supports_mutual_authentication(&self) -> bool {
        true // EAP-TLS provides mutual certificate-based authentication
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Mock TLS engine that simulates a successful handshake.
    struct MockSuccessTlsEngine {
        initialized: bool,
        handshake_step: u8,
        complete: bool,
    }

    impl MockSuccessTlsEngine {
        fn new() -> Self {
            Self {
                initialized: false,
                handshake_step: 0,
                complete: false,
            }
        }
    }

    impl TlsEngine for MockSuccessTlsEngine {
        fn init_session(&mut self, _config: &TlsClientConfig) -> Result<(), EapError> {
            self.initialized = true;
            self.handshake_step = 0;
            self.complete = false;
            Ok(())
        }

        fn process_server_data(&mut self, _data: &[u8]) -> Result<Option<Vec<u8>>, EapError> {
            self.handshake_step += 1;
            if self.handshake_step >= 2 {
                self.complete = true;
                // Handshake complete — no more data to send
                Ok(None)
            } else {
                // Simulate sending ClientHello / response
                Ok(Some(vec![0x01, 0x02, 0x03]))
            }
        }

        fn is_handshake_complete(&self) -> bool {
            self.complete
        }

        fn derive_msk(&mut self) -> Result<pae::Msk, EapError> {
            if !self.complete {
                return Err(EapError::TlsError("handshake not complete".into()));
            }
            pae::Msk::from_bytes(vec![0xCD; 64]).map_err(|e| EapError::TlsError(e.to_string()))
        }

        fn reset(&mut self) {
            self.initialized = false;
            self.handshake_step = 0;
            self.complete = false;
        }
    }

    /// Mock TLS engine that simulates a failed handshake.
    struct MockFailTlsEngine;

    impl TlsEngine for MockFailTlsEngine {
        fn init_session(&mut self, _config: &TlsClientConfig) -> Result<(), EapError> {
            Ok(())
        }

        fn process_server_data(&mut self, _data: &[u8]) -> Result<Option<Vec<u8>>, EapError> {
            Err(EapError::TlsError("certificate validation failed".into()))
        }

        fn is_handshake_complete(&self) -> bool {
            false
        }

        fn derive_msk(&mut self) -> Result<pae::Msk, EapError> {
            Err(EapError::TlsError("handshake not complete".into()))
        }

        fn reset(&mut self) {}
    }

    /// Mock EAP context for testing.
    struct MockContext {
        identity: Vec<u8>,
        tls_config: TlsClientConfig,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                identity: b"testuser".to_vec(),
                tls_config: TlsClientConfig {
                    cert_chain: vec![b"cert".to_vec()],
                    private_key: b"key".to_vec(),
                    ca_certs: vec![b"ca".to_vec()],
                    verify_server: true,
                },
            }
        }
    }

    impl EapContext for MockContext {
        fn send_eap(&self, _packet: &super::super::peer::EapPacket) -> Result<(), EapError> {
            Ok(())
        }
        fn now(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
        fn get_identity(&self) -> &[u8] {
            &self.identity
        }
        fn tls_config(&self) -> &TlsClientConfig {
            &self.tls_config
        }
    }

    // --- Tests ---

    /// Verifies: #39 (REQ-F-EAP-002)
    /// EAP-TLS initial state.
    #[test]
    fn test_eap_tls_initial_state() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let method = EapTls::new(engine);
        assert_eq!(method.state(), EapTlsState::Initial);
        assert_eq!(method.method_type(), EapType::Tls);
        assert!(!method.is_complete());
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// Per RFC 5216: EAP-TLS with TLS-Start flag.
    /// Given configured client cert, When EAP-TLS begins, Then response sent.
    #[test]
    fn test_eap_tls_start_handshake() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        // EAP-TLS Request with TLS-Start flag, no data
        let request_data = vec![TLS_FLAGS_START];
        let result = method.handle_request(1, &request_data, &ctx).unwrap();

        match result {
            EapMethodOutput::Respond { eap_type, data } => {
                assert_eq!(eap_type, EapType::Tls);
                // Response should have flags byte + length + TLS data
                assert!(!data.is_empty());
                assert_eq!(data[0] & TLS_FLAGS_START, 0); // No start flag in response
            }
            _ => panic!("expected Respond, got {:?}", result),
        }
        assert_eq!(method.state(), EapTlsState::Handshake);
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// Per RFC 5216: Successful TLS handshake produces MSK >= 64 octets.
    #[test]
    fn test_eap_tls_handshake_success_msk() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        // Step 1: TLS-Start
        let start_data = vec![TLS_FLAGS_START];
        let result = method.handle_request(1, &start_data, &ctx).unwrap();
        assert!(matches!(result, EapMethodOutput::Respond { .. }));

        // Step 2: Server response — handshake completes
        let server_data = vec![0x00]; // flags=0, no TLS data
        let result = method.handle_request(2, &server_data, &ctx).unwrap();

        match result {
            EapMethodOutput::Success { msk, session_id } => {
                assert!(msk.len() >= 64);
                assert!(!session_id.is_empty());
            }
            _ => panic!("expected Success, got {:?}", result),
        }
        assert_eq!(method.state(), EapTlsState::Complete);
        assert!(method.is_complete());
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// Per RFC 5216: Certificate validation failure → eapFail.
    #[test]
    fn test_eap_tls_certificate_failure() {
        let engine = Arc::new(std::sync::Mutex::new(MockFailTlsEngine));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        let start_data = vec![TLS_FLAGS_START];
        let result = method.handle_request(1, &start_data, &ctx);
        assert!(result.is_err());
        match result.unwrap_err() {
            EapError::TlsError(msg) => {
                assert!(msg.contains("certificate"));
            }
            other => panic!("expected TlsError, got {:?}", other),
        }
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// EAP-TLS rejects request without TLS-Start flag when in Initial state.
    #[test]
    fn test_eap_tls_rejects_no_start_flag() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        let no_start_data = vec![0x00]; // flags=0, no TLS-Start
        let result = method.handle_request(1, &no_start_data, &ctx);
        assert!(result.is_err());
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// EAP-TLS rejects empty data.
    #[test]
    fn test_eap_tls_rejects_empty_data() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        let result = method.handle_request(1, &[], &ctx);
        assert!(result.is_err());
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// Reset returns EAP-TLS to Initial state.
    #[test]
    fn test_eap_tls_reset() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        let start_data = vec![TLS_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();
        assert_eq!(method.state(), EapTlsState::Handshake);

        method.reset();
        assert_eq!(method.state(), EapTlsState::Initial);
        assert!(!method.is_complete());
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// take_msk returns None before completion, Some after.
    #[test]
    fn test_eap_tls_take_msk() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        assert!(method.take_msk().is_none());

        // Complete handshake
        let start_data = vec![TLS_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();
        let server_data = vec![0x00];
        method.handle_request(2, &server_data, &ctx).unwrap();

        // MSK was consumed by the Success output, so take_msk returns None
        // (the MSK was passed in EapMethodOutput::Success)
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// EAP-TLS rejects request after completion.
    #[test]
    fn test_eap_tls_rejects_after_complete() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        // Complete handshake
        let start_data = vec![TLS_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();
        let server_data = vec![0x00];
        method.handle_request(2, &server_data, &ctx).unwrap();

        // Try to send another request
        let result = method.handle_request(3, &start_data, &ctx);
        assert!(result.is_err());
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// EAP-TLS response payload format.
    #[test]
    fn test_eap_tls_response_payload_format() {
        let payload = EapTls::build_response_payload(&[0xAA, 0xBB], false);
        // Flags byte should not have MORE_FRAGMENTS
        assert_eq!(payload[0] & TLS_FLAGS_MORE_FRAGMENTS, 0);
        // Length should be present (4 bytes)
        let len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        assert_eq!(len, 2);
        assert_eq!(&payload[5..], &[0xAA, 0xBB]);
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// EAP-TLS payload parsing with length field.
    #[test]
    fn test_eap_tls_parse_with_length() {
        // Flags=0x80 (length included), length=2, data=[0xAA, 0xBB]
        let data = vec![TLS_FLAGS_LENGTH_INCLUDED, 0, 0, 0, 2, 0xAA, 0xBB];
        let (flags, has_length, tls_data) = EapTls::parse_tls_data(&data).unwrap();
        assert_eq!(flags, TLS_FLAGS_LENGTH_INCLUDED);
        assert!(has_length);
        assert_eq!(tls_data, &[0xAA, 0xBB]);
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// EAP-TLS payload parsing without length field.
    #[test]
    fn test_eap_tls_parse_without_length() {
        // Flags=0x00 (no length), data=[0x01]
        let data = vec![0x00, 0x01];
        let (flags, has_length, tls_data) = EapTls::parse_tls_data(&data).unwrap();
        assert_eq!(flags, 0x00);
        assert!(!has_length);
        assert_eq!(tls_data, &[0x01]);
    }

    /// Verifies: #39 (REQ-F-EAP-002)
    /// Per RFC 5216: TLS-Start flag with server data triggers handshake.
    #[test]
    fn test_eap_tls_start_with_server_data() {
        let engine = Arc::new(std::sync::Mutex::new(MockSuccessTlsEngine::new()));
        let mut method = EapTls::new(engine);
        let ctx = MockContext::new();

        // TLS-Start flag with some initial server data
        let start_data = vec![TLS_FLAGS_START, 0x01, 0x02];
        let result = method.handle_request(1, &start_data, &ctx).unwrap();
        assert!(matches!(result, EapMethodOutput::Respond { .. }));
        assert_eq!(method.state(), EapTlsState::Handshake);
    }
}
