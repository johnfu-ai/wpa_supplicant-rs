//! EAP-PEAP method per RFC 7170.
//!
//! Implements: #40 (REQ-F-EAP-003: PEAP)
//!
//! IMPORTANT: This implementation is based on understanding of RFC 7170.
//! No copyrighted content from the RFC is reproduced.

use std::sync::Arc;

use super::eap_tls::TlsEngine;
use super::peer::{EapContext, EapMethod, EapMethodOutput, EapType};
use super::EapError;

/// EAP-PEAP state per RFC 7170.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapPeapState {
    /// Initial — waiting for EAP-Request/PEAP-Start.
    Initial,
    /// Phase 1 — TLS tunnel establishment.
    Phase1,
    /// Phase 2 — inner authentication within TLS tunnel.
    Phase2,
    /// Authentication complete.
    Complete,
}

/// PEAP flags per RFC 7170.
const PEAP_FLAGS_START: u8 = 0x20;
const PEAP_FLAGS_LENGTH_INCLUDED: u8 = 0x80;

/// EAP-PEAP method — TLS tunnel with inner EAP authentication per RFC 7170.
///
/// Feature-gated: `#[cfg(feature = "eap-peap")]`.
pub struct EapPeap {
    /// PEAP state.
    state: EapPeapState,
    /// TLS engine for the outer tunnel.
    engine: Arc<std::sync::Mutex<dyn TlsEngine>>,
    /// Inner EAP method (injected for testability).
    inner_method: Option<Box<dyn EapMethod>>,
    /// Derived MSK.
    msk: Option<pae::Msk>,
}

impl EapPeap {
    /// Create a new PEAP method with the given TLS engine and inner method.
    pub fn new(
        engine: Arc<std::sync::Mutex<dyn TlsEngine>>,
        inner_method: Box<dyn EapMethod>,
    ) -> Self {
        Self {
            state: EapPeapState::Initial,
            engine,
            inner_method: Some(inner_method),
            msk: None,
        }
    }

    /// Current PEAP state.
    pub fn state(&self) -> EapPeapState {
        self.state
    }

    /// Parse PEAP flags and TLS data from the request payload.
    fn parse_peap_data(data: &[u8]) -> Result<(u8, &[u8]), EapError> {
        if data.is_empty() {
            return Err(EapError::InvalidPacket(
                "PEAP data too short (no flags byte)".into(),
            ));
        }
        let flags = data[0];
        let has_length = (flags & PEAP_FLAGS_LENGTH_INCLUDED) != 0;
        let tls_start = if has_length { 5 } else { 1 };

        if data.len() < tls_start {
            return Err(EapError::InvalidPacket(
                "PEAP data too short for length field".into(),
            ));
        }

        Ok((flags, &data[tls_start.min(data.len())..]))
    }

    /// Build a PEAP response payload.
    fn build_response_payload(tls_data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + 4 + tls_data.len());
        payload.push(0); // flags
        payload.extend_from_slice(&(tls_data.len() as u32).to_be_bytes());
        payload.extend_from_slice(tls_data);
        payload
    }
}

impl EapMethod for EapPeap {
    fn method_type(&self) -> EapType {
        EapType::Peap
    }

    fn handle_request(
        &mut self,
        identifier: u8,
        data: &[u8],
        ctx: &dyn EapContext,
    ) -> Result<EapMethodOutput, EapError> {
        let (flags, tls_data) = Self::parse_peap_data(data)?;
        let is_start = (flags & PEAP_FLAGS_START) != 0;

        match self.state {
            EapPeapState::Initial => {
                if !is_start {
                    return Err(EapError::InvalidPacket("PEAP: expected Start flag".into()));
                }

                let config = ctx.tls_config();
                let tunnel_complete = {
                    let mut engine = self
                        .engine
                        .lock()
                        .map_err(|_| EapError::TlsError("TLS engine lock poisoned".into()))?;
                    engine.init_session(config)?;
                    self.state = EapPeapState::Phase1;

                    let response_data = if tls_data.is_empty() {
                        engine.process_server_data(&[])?
                    } else {
                        engine.process_server_data(tls_data)?
                    };

                    match response_data {
                        Some(out) => {
                            return Ok(EapMethodOutput::Respond {
                                eap_type: EapType::Peap,
                                data: Self::build_response_payload(&out),
                            })
                        }
                        None => true,
                    }
                };
                // engine guard dropped

                if tunnel_complete {
                    self.state = EapPeapState::Phase2;
                    return self.handle_phase2(identifier, &[], ctx);
                }

                unreachable!()
            }
            EapPeapState::Phase1 => {
                let phase_result = {
                    let mut engine = self
                        .engine
                        .lock()
                        .map_err(|_| EapError::TlsError("TLS engine lock poisoned".into()))?;

                    let response_data = engine.process_server_data(tls_data)?;

                    match response_data {
                        Some(out) => Err(EapMethodOutput::Respond {
                            eap_type: EapType::Peap,
                            data: Self::build_response_payload(&out),
                        }),
                        None => Ok(()), // tunnel complete
                    }
                };
                // engine guard dropped

                match phase_result {
                    Err(response) => Ok(response),
                    Ok(()) => {
                        self.state = EapPeapState::Phase2;
                        self.handle_phase2(identifier, tls_data, ctx)
                    }
                }
            }
            EapPeapState::Phase2 => self.handle_phase2(identifier, tls_data, ctx),
            EapPeapState::Complete => Err(EapError::InvalidPacket(
                "PEAP: received request after completion".into(),
            )),
        }
    }

    fn reset(&mut self) {
        self.state = EapPeapState::Initial;
        self.msk = None;
        if let Some(ref mut inner) = self.inner_method {
            inner.reset();
        }
        if let Ok(mut engine) = self.engine.lock() {
            engine.reset();
        }
    }

    fn is_complete(&self) -> bool {
        self.state == EapPeapState::Complete
    }

    fn take_msk(&mut self) -> Option<pae::Msk> {
        self.msk.take()
    }

    fn supports_mutual_authentication(&self) -> bool {
        true // PEAP provides mutual authentication via TLS tunnel + inner method
    }
}

impl EapPeap {
    /// Handle Phase 2 — inner EAP authentication within the TLS tunnel.
    ///
    /// Per RFC 7170: inner EAP packets are tunneled through TLS.
    /// The outer PEAP data is decrypted, passed to the inner method,
    /// and the response is encrypted back through the tunnel.
    fn handle_phase2(
        &mut self,
        identifier: u8,
        tunnel_data: &[u8],
        ctx: &dyn EapContext,
    ) -> Result<EapMethodOutput, EapError> {
        let Some(ref mut inner) = self.inner_method else {
            return Err(EapError::AuthFailed(
                "PEAP: no inner method configured".into(),
            ));
        };

        // Decrypt inner EAP data from the TLS tunnel
        let inner_data = {
            let mut engine = self
                .engine
                .lock()
                .map_err(|_| EapError::TlsError("TLS engine lock poisoned".into()))?;
            engine.recv_tunnel_data(tunnel_data)?
        };

        // Process through inner method
        let inner_result = inner.handle_request(identifier, &inner_data, ctx)?;

        match inner_result {
            EapMethodOutput::Success { .. } => {
                // Inner method succeeded — derive MSK from TLS session
                let mut engine = self
                    .engine
                    .lock()
                    .map_err(|_| EapError::TlsError("TLS engine lock poisoned".into()))?;

                let msk = engine.derive_msk()?;
                self.msk = Some(msk);
                self.state = EapPeapState::Complete;

                Ok(EapMethodOutput::Success {
                    msk: self
                        .msk
                        .take()
                        .ok_or_else(|| EapError::TlsError("MSK not available".into()))?,
                    session_id: vec![EapType::Peap.value()],
                })
            }
            EapMethodOutput::Failure { reason } => {
                // Inner authentication failed — PEAP fails per RFC 7170
                self.state = EapPeapState::Complete;
                Err(EapError::AuthFailed(reason))
            }
            EapMethodOutput::Respond { data, .. } => {
                // Inner method still in progress — encrypt and wrap response
                let encrypted = {
                    let mut engine = self
                        .engine
                        .lock()
                        .map_err(|_| EapError::TlsError("TLS engine lock poisoned".into()))?;
                    engine.send_tunnel_data(&data)?
                };
                Ok(EapMethodOutput::Respond {
                    eap_type: EapType::Peap,
                    data: Self::build_response_payload(&encrypted),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eap_tls::TlsEngine;
    use crate::peer::TlsClientConfig;

    /// Mock TLS engine for PEAP testing.
    struct MockPeapTlsEngine {
        initialized: bool,
        step: u8,
        complete: bool,
    }

    impl MockPeapTlsEngine {
        fn new() -> Self {
            Self {
                initialized: false,
                step: 0,
                complete: false,
            }
        }
    }

    impl TlsEngine for MockPeapTlsEngine {
        fn init_session(&mut self, _config: &TlsClientConfig) -> Result<(), EapError> {
            self.initialized = true;
            self.step = 0;
            self.complete = false;
            Ok(())
        }

        fn process_server_data(&mut self, _data: &[u8]) -> Result<Option<Vec<u8>>, EapError> {
            self.step += 1;
            if self.step >= 2 {
                self.complete = true;
                Ok(None) // Handshake complete
            } else {
                Ok(Some(vec![0x01, 0x02])) // TLS response data
            }
        }

        fn is_handshake_complete(&self) -> bool {
            self.complete
        }

        fn derive_msk(&mut self) -> Result<pae::Msk, EapError> {
            if !self.complete {
                return Err(EapError::TlsError("handshake not complete".into()));
            }
            pae::Msk::from_bytes(vec![0xEE; 64]).map_err(|e| EapError::TlsError(e.to_string()))
        }

        fn reset(&mut self) {
            self.initialized = false;
            self.step = 0;
            self.complete = false;
        }

        fn recv_tunnel_data(&mut self, data: &[u8]) -> Result<Vec<u8>, EapError> {
            // Mock: pass through data as-is (no actual decryption)
            Ok(data.to_vec())
        }

        fn send_tunnel_data(&mut self, data: &[u8]) -> Result<Vec<u8>, EapError> {
            // Mock: pass through data as-is (no actual encryption)
            Ok(data.to_vec())
        }
    }

    /// Mock inner EAP method that completes immediately.
    struct MockInnerMethod {
        complete: bool,
    }

    impl MockInnerMethod {
        fn new() -> Self {
            Self { complete: true }
        }
    }

    impl EapMethod for MockInnerMethod {
        fn method_type(&self) -> EapType {
            EapType::Unknown(26) // MSCHAPv2
        }
        fn handle_request(
            &mut self,
            _: u8,
            _: &[u8],
            _: &dyn EapContext,
        ) -> Result<EapMethodOutput, EapError> {
            self.complete = true;
            Ok(EapMethodOutput::Success {
                msk: pae::Msk::from_bytes(vec![0xFF; 64]).unwrap(),
                session_id: vec![26],
            })
        }
        fn reset(&mut self) {
            self.complete = false;
        }
        fn is_complete(&self) -> bool {
            self.complete
        }
        fn take_msk(&mut self) -> Option<pae::Msk> {
            None
        }
        fn supports_mutual_authentication(&self) -> bool {
            true
        }
    }

    /// Mock EAP context.
    struct MockContext {
        identity: Vec<u8>,
        tls_config: TlsClientConfig,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                identity: b"testuser".to_vec(),
                tls_config: TlsClientConfig {
                    cert_chain: Vec::new(),
                    private_key: Vec::new(),
                    ca_certs: vec![b"ca".to_vec()],
                    verify_server: true,
                },
            }
        }
    }

    impl EapContext for MockContext {
        fn send_eap(&self, _: &super::super::peer::EapPacket) -> Result<(), EapError> {
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

    /// Verifies: #40 (REQ-F-EAP-003)
    /// PEAP initial state and method type.
    #[test]
    fn test_peap_initial_state() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        assert_eq!(method.state(), EapPeapState::Initial);
        assert_eq!(method.method_type(), EapType::Peap);
        assert!(!method.is_complete());
        assert!(method.supports_mutual_authentication());
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Per RFC 7170: PEAP Start triggers Phase 1.
    #[test]
    fn test_peap_start_phase1() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        let ctx = MockContext::new();

        let start_data = vec![PEAP_FLAGS_START];
        let result = method.handle_request(1, &start_data, &ctx).unwrap();

        assert!(matches!(result, EapMethodOutput::Respond { .. }));
        assert_eq!(method.state(), EapPeapState::Phase1);
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Per RFC 7170: TLS tunnel establishment completes, moves to Phase 2.
    #[test]
    fn test_peap_tunnel_established() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        let ctx = MockContext::new();

        // Start
        let start_data = vec![PEAP_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();

        // Continue Phase 1 — tunnel completes
        let server_data = vec![0x00];
        let result = method.handle_request(2, &server_data, &ctx).unwrap();

        // Should move to Phase 2 (inner method already complete)
        assert!(matches!(result, EapMethodOutput::Success { .. }));
        assert_eq!(method.state(), EapPeapState::Complete);
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Per RFC 7170: Successful PEAP produces MSK >= 64 octets.
    #[test]
    fn test_peap_msk_derivation() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        let ctx = MockContext::new();

        // Complete the full PEAP exchange
        let start_data = vec![PEAP_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();
        let server_data = vec![0x00];
        let result = method.handle_request(2, &server_data, &ctx).unwrap();

        if let EapMethodOutput::Success { msk, session_id } = result {
            assert!(msk.len() >= 64);
            assert!(!session_id.is_empty());
        } else {
            panic!("expected Success, got {:?}", result);
        }
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Per RFC 7170: PEAP rejects request without Start flag in Initial state.
    #[test]
    fn test_peap_rejects_no_start() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        let ctx = MockContext::new();

        let no_start = vec![0x00];
        let result = method.handle_request(1, &no_start, &ctx);
        assert!(result.is_err());
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// PEAP rejects empty data.
    #[test]
    fn test_peap_rejects_empty() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        let ctx = MockContext::new();

        let result = method.handle_request(1, &[], &ctx);
        assert!(result.is_err());
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Reset returns PEAP to Initial state.
    #[test]
    fn test_peap_reset() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        let ctx = MockContext::new();

        let start_data = vec![PEAP_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();
        assert_eq!(method.state(), EapPeapState::Phase1);

        method.reset();
        assert_eq!(method.state(), EapPeapState::Initial);
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// PEAP rejects request after completion.
    #[test]
    fn test_peap_rejects_after_complete() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockInnerMethod::new()));
        let ctx = MockContext::new();

        // Complete the exchange
        let start_data = vec![PEAP_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();
        let server_data = vec![0x00];
        method.handle_request(2, &server_data, &ctx).unwrap();

        // Try another request
        let result = method.handle_request(3, &start_data, &ctx);
        assert!(result.is_err());
    }

    /// Mock inner EAP method that fails authentication.
    struct MockFailingInnerMethod;

    impl EapMethod for MockFailingInnerMethod {
        fn method_type(&self) -> EapType {
            EapType::Unknown(26) // MSCHAPv2
        }
        fn handle_request(
            &mut self,
            _: u8,
            _: &[u8],
            _: &dyn EapContext,
        ) -> Result<EapMethodOutput, EapError> {
            Ok(EapMethodOutput::Failure {
                reason: "invalid credentials".into(),
            })
        }
        fn reset(&mut self) {}
        fn is_complete(&self) -> bool {
            false
        }
        fn take_msk(&mut self) -> Option<pae::Msk> {
            None
        }
        fn supports_mutual_authentication(&self) -> bool {
            true
        }
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Per RFC 7170: inner authentication failure causes PEAP to fail.
    #[test]
    fn test_peap_inner_auth_failure() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockFailingInnerMethod));
        let ctx = MockContext::new();

        // Start → Phase 1
        let start_data = vec![PEAP_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();

        // Tunnel completes → Phase 2 → inner method fails
        let server_data = vec![0x00];
        let result = method.handle_request(2, &server_data, &ctx);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, EapError::AuthFailed(_)));
    }

    /// Mock inner EAP method that requires multiple rounds.
    struct MockMultiRoundInnerMethod {
        round: u8,
    }

    impl MockMultiRoundInnerMethod {
        fn new() -> Self {
            Self { round: 0 }
        }
    }

    impl EapMethod for MockMultiRoundInnerMethod {
        fn method_type(&self) -> EapType {
            EapType::Unknown(26)
        }
        fn handle_request(
            &mut self,
            _: u8,
            _: &[u8],
            _: &dyn EapContext,
        ) -> Result<EapMethodOutput, EapError> {
            self.round += 1;
            if self.round >= 2 {
                Ok(EapMethodOutput::Success {
                    msk: pae::Msk::from_bytes(vec![0xFF; 64]).unwrap(),
                    session_id: vec![26],
                })
            } else {
                Ok(EapMethodOutput::Respond {
                    eap_type: EapType::Unknown(26),
                    data: vec![0x01],
                })
            }
        }
        fn reset(&mut self) {
            self.round = 0;
        }
        fn is_complete(&self) -> bool {
            self.round >= 2
        }
        fn take_msk(&mut self) -> Option<pae::Msk> {
            None
        }
        fn supports_mutual_authentication(&self) -> bool {
            true
        }
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Per RFC 7170: multi-round inner authentication within TLS tunnel.
    #[test]
    fn test_peap_inner_auth_multi_round() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockMultiRoundInnerMethod::new()));
        let ctx = MockContext::new();

        // Start → Phase 1
        let start_data = vec![PEAP_FLAGS_START];
        method.handle_request(1, &start_data, &ctx).unwrap();

        // Tunnel completes → Phase 2 → inner method needs more rounds
        let server_data = vec![0x00];
        let result = method.handle_request(2, &server_data, &ctx).unwrap();
        assert!(matches!(result, EapMethodOutput::Respond { .. }));
        assert_eq!(method.state(), EapPeapState::Phase2);

        // Next Phase 2 request → inner method succeeds
        let server_data = vec![0x00];
        let result = method.handle_request(3, &server_data, &ctx).unwrap();
        assert!(matches!(result, EapMethodOutput::Success { .. }));
        assert_eq!(method.state(), EapPeapState::Complete);
    }

    /// Verifies: #40 (REQ-F-EAP-003)
    /// Per RFC 7170: PEAP with no inner method configured returns error.
    #[test]
    fn test_peap_no_inner_method() {
        let engine = Arc::new(std::sync::Mutex::new(MockPeapTlsEngine::new()));
        let mut method = EapPeap::new(engine, Box::new(MockFailingInnerMethod));
        // Remove the inner method to test error path
        method.inner_method = None;
        let ctx = MockContext::new();

        // Force into Phase 2 state
        method.state = EapPeapState::Phase2;
        let server_data = vec![0x00];
        let result = method.handle_request(1, &server_data, &ctx);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, EapError::AuthFailed(_)));
    }
}
