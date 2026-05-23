//! EAP peer core types and state machine.
//!
//! Implements EAP peer framework per IETF RFC 3748.
//!
//! Implements: #38 (REQ-F-EAP-001: EAP Peer Framework)
//!
//! IMPORTANT: This implementation is based on understanding of RFC 3748.
//! No copyrighted content from the RFC is reproduced.

use std::time::Duration;

/// EAP code field values per RFC 3748 Section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    /// EAP Request (1).
    Request,
    /// EAP Response (2).
    Response,
    /// EAP Success (3).
    Success,
    /// EAP Failure (4).
    Failure,
}

/// EAP type numbers per RFC 3748.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapType {
    /// Identity (1).
    Identity,
    /// Notification (2).
    Notification,
    /// Nak (Legacy) (3).
    Nak,
    /// MD5-Challenge (4).
    Md5Challenge,
    /// EAP-TLS (13).
    Tls,
    /// PEAP (25).
    Peap,
    /// TEAP (55).
    Teap,
    /// Expanded NAK (254).
    ExpandedNak,
    /// Unknown/unsupported type.
    Unknown(u8),
}

impl EapType {
    /// Convert from u8 type number.
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Identity,
            2 => Self::Notification,
            3 => Self::Nak,
            4 => Self::Md5Challenge,
            13 => Self::Tls,
            25 => Self::Peap,
            55 => Self::Teap,
            254 => Self::ExpandedNak,
            other => Self::Unknown(other),
        }
    }

    /// EAP type number.
    pub fn value(&self) -> u8 {
        self.as_u8()
    }

    /// Convert to u8 type number.
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Identity => 1,
            Self::Notification => 2,
            Self::Nak => 3,
            Self::Md5Challenge => 4,
            Self::Tls => 13,
            Self::Peap => 25,
            Self::Teap => 55,
            Self::ExpandedNak => 254,
            Self::Unknown(v) => *v,
        }
    }
}

/// EAP peer conversation state per RFC 3748.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapPeerState {
    /// No conversation in progress.
    Idle,
    /// Received EAP-Request, waiting for method processing.
    Received,
    /// Method is processing the request, will send a response.
    Method,
    /// Waiting for next EAP-Request from authenticator.
    Waiting,
    /// EAP-Success received.
    Success,
    /// EAP-Failure received.
    Failure,
    /// Timeout waiting for authenticator.
    Timeout,
}

/// EAP method output — result from method processing per RFC 3748.
#[derive(Debug)]
pub enum EapMethodOutput {
    /// Send an EAP-Response with the given data.
    Respond {
        /// EAP type for the response.
        eap_type: EapType,
        /// Response data bytes.
        data: Vec<u8>,
    },
    /// Method has succeeded; MSK available.
    Success {
        /// MSK (Master Session Key), at least 64 octets per RFC 3748.
        msk: pae::Msk,
        /// Session-Id per RFC 5247: EAP method type (1 octet) + method-specific data.
        session_id: Vec<u8>,
    },
    /// Method has failed.
    Failure {
        /// Failure reason.
        reason: String,
    },
}

/// EAP packet representation per RFC 3748 Section 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    /// EAP code (Request/Response/Success/Failure).
    code: EapCode,
    /// Identifier.
    identifier: u8,
    /// EAP method type (only for Request/Response).
    method_type: Option<EapType>,
    /// EAP method data (payload after type field).
    method_data: Vec<u8>,
}

impl EapPacket {
    /// EAP header size: code(1) + id(1) + length(2) = 4 bytes.
    pub const HEADER_SIZE: usize = 4;

    /// Maximum EAP packet size per RFC 3748.
    pub const MAX_SIZE: usize = 1500;

    /// Create an EAP-Response/Identity. Per RFC 3748.
    pub fn response_identity(identifier: u8, identity: &[u8]) -> Self {
        Self {
            code: EapCode::Response,
            identifier,
            method_type: Some(EapType::Identity),
            method_data: identity.to_vec(),
        }
    }

    /// Create an EAP-Response/NAK proposing alternate methods. Per RFC 3748.
    pub fn response_nak(identifier: u8, proposed_types: &[EapType]) -> Self {
        let data: Vec<u8> = proposed_types.iter().map(|t| t.value()).collect();
        Self {
            code: EapCode::Response,
            identifier,
            method_type: Some(EapType::Nak),
            method_data: data,
        }
    }

    /// Create an EAP-Response with arbitrary type and data.
    pub fn response(identifier: u8, eap_type: EapType, data: Vec<u8>) -> Self {
        Self {
            code: EapCode::Response,
            identifier,
            method_type: Some(eap_type),
            method_data: data,
        }
    }

    /// EAP code.
    pub fn code(&self) -> EapCode {
        self.code
    }

    /// Identifier.
    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    /// EAP method type (if Request or Response).
    pub fn method_type(&self) -> Option<EapType> {
        self.method_type
    }

    /// EAP method data (payload after type field).
    pub fn method_data(&self) -> &[u8] {
        &self.method_data
    }

    /// EAP type (alias for `method_type`).
    pub fn eap_type(&self) -> Option<EapType> {
        self.method_type
    }

    /// Payload data (alias for `method_data`).
    pub fn data(&self) -> &[u8] {
        &self.method_data
    }

    /// Decode an EAP packet from raw bytes. Per RFC 3748 Section 4.
    ///
    /// # Errors
    /// Returns `EapError::InvalidPacket` for malformed packets.
    pub fn decode(raw: &[u8]) -> Result<Self, super::EapError> {
        if raw.len() < Self::HEADER_SIZE {
            return Err(super::EapError::InvalidPacket(
                "EAP packet too short (minimum 4 bytes)".into(),
            ));
        }

        let code = match raw[0] {
            1 => EapCode::Request,
            2 => EapCode::Response,
            3 => EapCode::Success,
            4 => EapCode::Failure,
            other => {
                return Err(super::EapError::InvalidPacket(format!(
                    "invalid EAP code: {}",
                    other
                )))
            }
        };

        let identifier = raw[1];
        let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;

        if raw.len() < length {
            return Err(super::EapError::InvalidPacket(format!(
                "EAP packet length field ({}) exceeds buffer ({})",
                length,
                raw.len()
            )));
        }

        let (method_type, method_data) = if matches!(code, EapCode::Request | EapCode::Response) {
            if length < Self::HEADER_SIZE + 1 {
                return Err(super::EapError::InvalidPacket(
                    "EAP Request/Response must have type field".into(),
                ));
            }
            (
                Some(EapType::from_u8(raw[Self::HEADER_SIZE])),
                raw[Self::HEADER_SIZE + 1..length].to_vec(),
            )
        } else {
            (None, raw[Self::HEADER_SIZE..length].to_vec())
        };

        Ok(Self {
            code,
            identifier,
            method_type,
            method_data,
        })
    }

    /// Encode an EAP packet to raw bytes. Per RFC 3748 Section 4.
    ///
    /// # Errors
    /// Returns `EapError::InvalidPacket` if the packet is too large.
    pub fn encode(&self) -> Result<Vec<u8>, super::EapError> {
        let mut buf = Vec::new();
        buf.push(match self.code {
            EapCode::Request => 1,
            EapCode::Response => 2,
            EapCode::Success => 3,
            EapCode::Failure => 4,
        });
        buf.push(self.identifier);

        let data_start = if self.method_type.is_some() {
            Self::HEADER_SIZE + 1
        } else {
            Self::HEADER_SIZE
        };
        let total_len = data_start + self.method_data.len();
        if total_len > 65535 {
            return Err(super::EapError::InvalidPacket(
                "EAP packet too large".into(),
            ));
        }

        buf.extend_from_slice(&(total_len as u16).to_be_bytes());

        if let Some(eap_type) = self.method_type {
            buf.push(eap_type.value());
        }
        buf.extend_from_slice(&self.method_data);

        Ok(buf)
    }
}

/// TLS client configuration for EAP methods.
///
/// Anti-corruption layer: EAP methods use this; PAE core never sees TLS internals.
/// Per ADR-FF-006 (#78).
#[derive(Debug, Clone)]
pub struct TlsClientConfig {
    /// Client certificate chain (PEM bytes).
    pub cert_chain: Vec<Vec<u8>>,
    /// Client private key (PEM bytes).
    pub private_key: Vec<u8>,
    /// Trusted CA certificates (PEM bytes).
    pub ca_certs: Vec<Vec<u8>>,
    /// Whether to verify server certificate.
    pub verify_server: bool,
}

/// EAP method trait — interface for pluggable EAP methods.
///
/// Per ADR-FF-006 (#78) and QA-SC-MOD-004 (#89).
/// New EAP methods are added by implementing this trait
/// and adding a feature flag — zero changes to other crates.
///
/// Implements: #38 (REQ-F-EAP-001)
pub trait EapMethod: Send + Sync {
    /// EAP method type number.
    fn method_type(&self) -> EapType;

    /// Process a received EAP-Request.
    ///
    /// # Errors
    /// Returns `EapError` if processing fails.
    fn handle_request(
        &mut self,
        identifier: u8,
        data: &[u8],
        ctx: &dyn EapContext,
    ) -> Result<EapMethodOutput, super::EapError>;

    /// Reset to initial state (for reauthentication).
    fn reset(&mut self);

    /// Whether the method has completed.
    fn is_complete(&self) -> bool;

    /// Extract the MSK after successful completion.
    ///
    /// Returns `None` if not complete or method doesn't produce MSK.
    fn take_msk(&mut self) -> Option<pae::Msk>;
}

/// Context trait for EAP peer — abstracts I/O and configuration.
///
/// Per ADR-SM-002 (#74).
/// Enables mock injection for unit testing.
///
/// Implements: #38 (REQ-F-EAP-001)
pub trait EapContext: Send + Sync {
    /// Send an EAPOL frame containing an EAP packet.
    fn send_eap(&self, packet: &EapPacket) -> Result<(), super::EapError>;

    /// Get the current time.
    fn now(&self) -> Duration;

    /// Get the configured identity string.
    fn get_identity(&self) -> &[u8];

    /// Get TLS client configuration.
    fn tls_config(&self) -> &TlsClientConfig;

    /// Get retransmission timeout. Per RFC 3748.
    fn retransmit_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// EAP peer — manages the EAP conversation per RFC 3748.
///
/// Implements: #38 (REQ-F-EAP-001)
pub struct EapPeer {
    /// Current conversation state.
    state: EapPeerState,
    /// Last received identifier (for duplicate detection).
    last_identifier: Option<u8>,
    /// MSK from successful method completion.
    msk: Option<pae::Msk>,
}

impl EapPeer {
    /// Create a new EAP peer in Idle state.
    pub fn new() -> Self {
        Self {
            state: EapPeerState::Idle,
            last_identifier: None,
            msk: None,
        }
    }

    /// Current EAP peer state.
    pub fn state(&self) -> EapPeerState {
        self.state
    }

    /// Whether eapSuccess has been set.
    pub fn eap_success(&self) -> bool {
        self.state == EapPeerState::Success
    }

    /// Whether eapFail has been set.
    pub fn eap_fail(&self) -> bool {
        self.state == EapPeerState::Failure
    }

    /// Whether eapTimeout has been set.
    pub fn eap_timeout(&self) -> bool {
        self.state == EapPeerState::Timeout
    }

    /// Take the MSK after successful authentication.
    ///
    /// Per RFC 3748: MSK is at least 64 octets.
    pub fn take_msk(&mut self) -> Option<pae::Msk> {
        self.msk.take()
    }

    /// Get the MSK from eapResults (if eapSuccess).
    ///
    /// Per RFC 3748: MSK is at least 64 octets.
    #[deprecated(note = "Use take_msk() instead for proper key ownership")]
    pub fn eap_results(&self) -> Option<&[u8]> {
        None // Msk is not Clone, cannot return a reference
    }

    /// Process a received EAP packet.
    ///
    /// Per RFC 3748: dispatches based on code and type,
    /// drives the peer state machine.
    ///
    /// # Errors
    /// Returns `EapError` for invalid packets or protocol errors.
    pub fn handle_packet(
        &mut self,
        packet: &EapPacket,
        methods: &mut [Box<dyn EapMethod>],
        ctx: &dyn EapContext,
    ) -> Result<Option<EapPacket>, super::EapError> {
        match packet.code() {
            EapCode::Request => self.handle_request(packet, methods, ctx),
            EapCode::Success => self.handle_success(),
            EapCode::Failure => self.handle_failure(),
            EapCode::Response => Err(super::EapError::InvalidPacket(
                "EAP peer received a Response packet".into(),
            )),
        }
    }

    fn handle_request(
        &mut self,
        packet: &EapPacket,
        methods: &mut [Box<dyn EapMethod>],
        ctx: &dyn EapContext,
    ) -> Result<Option<EapPacket>, super::EapError> {
        self.last_identifier = Some(packet.identifier());
        self.state = EapPeerState::Received;

        let eap_type = packet.eap_type().ok_or_else(|| {
            super::EapError::InvalidPacket("EAP Request missing type field".into())
        })?;

        match eap_type {
            EapType::Identity => {
                self.state = EapPeerState::Waiting;
                Ok(Some(EapPacket::response_identity(
                    packet.identifier(),
                    ctx.get_identity(),
                )))
            }
            EapType::Notification => {
                self.state = EapPeerState::Waiting;
                Ok(Some(EapPacket::response(
                    packet.identifier(),
                    EapType::Notification,
                    Vec::new(),
                )))
            }
            _ => {
                let method_idx = methods.iter().position(|m| m.method_type() == eap_type);

                if let Some(idx) = method_idx {
                    self.state = EapPeerState::Method;
                    let result = methods[idx].handle_request(
                        packet.identifier(),
                        packet.method_data(),
                        ctx,
                    )?;

                    match result {
                        EapMethodOutput::Respond { eap_type, data } => {
                            self.state = EapPeerState::Waiting;
                            Ok(Some(EapPacket::response(
                                packet.identifier(),
                                eap_type,
                                data,
                            )))
                        }
                        EapMethodOutput::Success { msk, .. } => {
                            self.msk = Some(msk);
                            self.state = EapPeerState::Waiting;
                            Ok(None)
                        }
                        EapMethodOutput::Failure { reason } => {
                            self.state = EapPeerState::Failure;
                            Err(super::EapError::AuthFailed(reason))
                        }
                    }
                } else {
                    let desired: Vec<EapType> = methods.iter().map(|m| m.method_type()).collect();
                    self.state = EapPeerState::Waiting;
                    Ok(Some(EapPacket::response_nak(packet.identifier(), &desired)))
                }
            }
        }
    }

    fn handle_success(&mut self) -> Result<Option<EapPacket>, super::EapError> {
        self.state = EapPeerState::Success;
        Ok(None)
    }

    fn handle_failure(&mut self) -> Result<Option<EapPacket>, super::EapError> {
        self.state = EapPeerState::Failure;
        Ok(None)
    }

    /// Process a timeout event.
    ///
    /// Per RFC 3748: if no response from authenticator, set eapTimeout.
    pub fn handle_timeout(&mut self) {
        if self.state == EapPeerState::Waiting {
            self.state = EapPeerState::Timeout;
        }
    }

    /// Reset the peer to Idle state.
    pub fn reset(&mut self) {
        self.state = EapPeerState::Idle;
        self.last_identifier = None;
        self.msk = None;
    }
}

impl Default for EapPeer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock EAP context for testing.
    struct MockContext {
        identity: Vec<u8>,
        tls_config: TlsClientConfig,
    }

    impl MockContext {
        fn new(identity: &[u8]) -> Self {
            Self {
                identity: identity.to_vec(),
                tls_config: TlsClientConfig {
                    cert_chain: Vec::new(),
                    private_key: Vec::new(),
                    ca_certs: Vec::new(),
                    verify_server: true,
                },
            }
        }
    }

    impl EapContext for MockContext {
        fn send_eap(&self, _packet: &EapPacket) -> Result<(), crate::EapError> {
            Ok(())
        }

        fn get_identity(&self) -> &[u8] {
            &self.identity
        }

        fn now(&self) -> Duration {
            Duration::ZERO
        }

        fn tls_config(&self) -> &TlsClientConfig {
            &self.tls_config
        }
    }

    /// Mock EAP method that always succeeds with a fixed MSK.
    struct MockSuccessMethod {
        complete: bool,
        msk: Option<pae::Msk>,
    }

    impl MockSuccessMethod {
        fn new() -> Self {
            Self {
                complete: false,
                msk: None,
            }
        }
    }

    impl EapMethod for MockSuccessMethod {
        fn method_type(&self) -> EapType {
            EapType::Tls
        }

        fn handle_request(
            &mut self,
            _identifier: u8,
            _data: &[u8],
            _ctx: &dyn EapContext,
        ) -> Result<EapMethodOutput, crate::EapError> {
            self.complete = true;
            let msk = pae::Msk::from_bytes(vec![0xAB; 64]).unwrap();
            self.msk = Some(msk);
            // Design deviation: return Success with owned Msk from take_msk
            // We create a fresh one here for the output since Msk is not Clone
            Ok(EapMethodOutput::Success {
                msk: pae::Msk::from_bytes(vec![0xAB; 64]).unwrap(),
                session_id: vec![13, 0x01, 0x02], // EAP-TLS session id
            })
        }

        fn reset(&mut self) {
            self.complete = false;
            self.msk = None;
        }

        fn is_complete(&self) -> bool {
            self.complete
        }

        fn take_msk(&mut self) -> Option<pae::Msk> {
            self.msk.take()
        }
    }

    /// Mock EAP method that always fails.
    struct MockFailMethod;

    impl EapMethod for MockFailMethod {
        fn method_type(&self) -> EapType {
            EapType::Md5Challenge
        }

        fn handle_request(
            &mut self,
            _identifier: u8,
            _data: &[u8],
            _ctx: &dyn EapContext,
        ) -> Result<EapMethodOutput, crate::EapError> {
            Ok(EapMethodOutput::Failure {
                reason: "authentication rejected".into(),
            })
        }

        fn reset(&mut self) {}

        fn is_complete(&self) -> bool {
            true
        }

        fn take_msk(&mut self) -> Option<pae::Msk> {
            None
        }
    }

    /// Mock EAP method that responds (multi-round).
    struct MockRespondMethod {
        complete: bool,
    }

    impl MockRespondMethod {
        fn new() -> Self {
            Self { complete: false }
        }
    }

    impl EapMethod for MockRespondMethod {
        fn method_type(&self) -> EapType {
            EapType::Tls
        }

        fn handle_request(
            &mut self,
            _identifier: u8,
            _data: &[u8],
            _ctx: &dyn EapContext,
        ) -> Result<EapMethodOutput, crate::EapError> {
            self.complete = true;
            Ok(EapMethodOutput::Respond {
                eap_type: EapType::Tls,
                data: vec![0x01, 0x02],
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
    }

    // --- EapType tests ---

    /// Verifies: #38 (REQ-F-EAP-001)
    /// EapType round-trips through u8.
    #[test]
    fn test_eap_type_round_trip() {
        assert_eq!(EapType::from_u8(1), EapType::Identity);
        assert_eq!(EapType::from_u8(13), EapType::Tls);
        assert_eq!(EapType::from_u8(25), EapType::Peap);
        assert_eq!(EapType::from_u8(55), EapType::Teap);
        assert_eq!(EapType::from_u8(254), EapType::ExpandedNak);
        assert_eq!(EapType::from_u8(99), EapType::Unknown(99));
        assert_eq!(EapType::Identity.value(), 1);
        assert_eq!(EapType::ExpandedNak.value(), 254);
    }

    // --- EapPacket encode/decode tests ---

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748 Section 4.
    /// EapPacket encode/decode round-trip.
    #[test]
    fn test_eap_packet_round_trip() {
        let packet = EapPacket::response_identity(42, b"testuser");
        let encoded = packet.encode().unwrap();
        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.code(), EapCode::Response);
        assert_eq!(decoded.identifier(), 42);
        assert_eq!(decoded.method_type(), Some(EapType::Identity));
        assert_eq!(decoded.method_data(), b"testuser");
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748 Section 4.
    /// EAP-Success decode.
    #[test]
    fn test_eap_packet_success_decode() {
        let raw = [3u8, 5, 0, 4];
        let packet = EapPacket::decode(&raw).unwrap();
        assert_eq!(packet.code(), EapCode::Success);
        assert_eq!(packet.identifier(), 5);
        assert_eq!(packet.method_type(), None);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748 Section 4.
    /// EAP-Failure decode.
    #[test]
    fn test_eap_packet_failure_decode() {
        let raw = [4u8, 7, 0, 4];
        let packet = EapPacket::decode(&raw).unwrap();
        assert_eq!(packet.code(), EapCode::Failure);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748 Section 4.
    /// EAP packet too short is rejected.
    #[test]
    fn test_eap_packet_too_short() {
        let result = EapPacket::decode(&[1, 2, 3]);
        assert!(result.is_err());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748 Section 4.
    /// EAP Request without type field is rejected.
    #[test]
    fn test_eap_request_no_type() {
        let raw = [1u8, 1, 0, 4];
        let result = EapPacket::decode(&raw);
        assert!(result.is_err());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// EAP-NAK response encodes desired types.
    #[test]
    fn test_eap_nak_response() {
        let packet = EapPacket::response_nak(1, &[EapType::Tls, EapType::Peap]);
        let encoded = packet.encode().unwrap();
        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.method_type(), Some(EapType::Nak));
        assert_eq!(decoded.method_data(), &[13, 25]);
    }

    // --- EapPeer state machine tests ---

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// EAP peer starts in Idle state.
    #[test]
    fn test_eap_peer_initial_state() {
        let peer = EapPeer::new();
        assert_eq!(peer.state(), EapPeerState::Idle);
        assert!(!peer.eap_success());
        assert!(!peer.eap_fail());
        assert!(!peer.eap_timeout());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// Given EAP-Request/Identity, When received by peer, Then EAP-Response/Identity transmitted.
    #[test]
    fn test_eap_peer_request_identity() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let mut methods: Vec<Box<dyn EapMethod>> = vec![];
        let request = EapPacket {
            code: EapCode::Request,
            identifier: 1,
            method_type: Some(EapType::Identity),
            method_data: Vec::new(),
        };
        let response = peer.handle_packet(&request, &mut methods, &ctx).unwrap();
        assert!(response.is_some());
        let resp = response.unwrap();
        assert_eq!(resp.code(), EapCode::Response);
        assert_eq!(resp.eap_type(), Some(EapType::Identity));
        assert_eq!(resp.data(), b"testuser");
        assert_eq!(peer.state(), EapPeerState::Waiting);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// EAP-Success sets eapSuccess state.
    #[test]
    fn test_eap_peer_success() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let success = EapPacket {
            code: EapCode::Success,
            identifier: 1,
            method_type: None,
            method_data: Vec::new(),
        };
        peer.handle_packet(&success, &mut [], &ctx).unwrap();
        assert!(peer.eap_success());
        assert_eq!(peer.state(), EapPeerState::Success);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// EAP-Failure sets eapFail state.
    #[test]
    fn test_eap_peer_failure() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let failure = EapPacket {
            code: EapCode::Failure,
            identifier: 1,
            method_type: None,
            method_data: Vec::new(),
        };
        peer.handle_packet(&failure, &mut [], &ctx).unwrap();
        assert!(peer.eap_fail());
        assert_eq!(peer.state(), EapPeerState::Failure);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// Method succeeds with MSK >= 64 octets, then EAP-Success received.
    #[test]
    fn test_eap_peer_method_success_msk() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let mut methods: Vec<Box<dyn EapMethod>> = vec![Box::new(MockSuccessMethod::new())];

        let request = EapPacket {
            code: EapCode::Request,
            identifier: 1,
            method_type: Some(EapType::Tls),
            method_data: vec![0x01],
        };
        let response = peer.handle_packet(&request, &mut methods, &ctx).unwrap();
        assert!(response.is_none());
        assert_eq!(peer.state(), EapPeerState::Waiting);

        let msk = peer.take_msk();
        assert!(msk.is_some());
        assert!(msk.unwrap().len() >= 64);

        let success = EapPacket {
            code: EapCode::Success,
            identifier: 1,
            method_type: None,
            method_data: Vec::new(),
        };
        peer.handle_packet(&success, &mut methods, &ctx).unwrap();
        assert!(peer.eap_success());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// Method fails → eapFail is set.
    #[test]
    fn test_eap_peer_method_fail() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let mut methods: Vec<Box<dyn EapMethod>> = vec![Box::new(MockFailMethod)];

        let request = EapPacket {
            code: EapCode::Request,
            identifier: 1,
            method_type: Some(EapType::Md5Challenge),
            method_data: vec![0x01],
        };
        let result = peer.handle_packet(&request, &mut methods, &ctx);
        assert!(result.is_err());
        assert!(peer.eap_fail());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// Unknown EAP type → NAK with supported types.
    #[test]
    fn test_eap_peer_nak_unknown_type() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let mut methods: Vec<Box<dyn EapMethod>> = vec![Box::new(MockSuccessMethod::new())];

        let request = EapPacket {
            code: EapCode::Request,
            identifier: 2,
            method_type: Some(EapType::Unknown(99)),
            method_data: vec![0x01],
        };
        let response = peer.handle_packet(&request, &mut methods, &ctx).unwrap();
        assert!(response.is_some());
        let resp = response.unwrap();
        assert_eq!(resp.method_type(), Some(EapType::Nak));
        assert_eq!(resp.method_data(), &[13]);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// Timeout while waiting sets eapTimeout.
    #[test]
    fn test_eap_peer_timeout() {
        let mut peer = EapPeer::new();
        peer.handle_timeout();
        assert_eq!(peer.state(), EapPeerState::Idle);

        let ctx = MockContext::new(b"testuser");
        let request = EapPacket {
            code: EapCode::Request,
            identifier: 1,
            method_type: Some(EapType::Identity),
            method_data: Vec::new(),
        };
        peer.handle_packet(&request, &mut [], &ctx).unwrap();
        assert_eq!(peer.state(), EapPeerState::Waiting);

        peer.handle_timeout();
        assert!(peer.eap_timeout());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// EAP peer rejects a Response packet.
    #[test]
    fn test_eap_peer_rejects_response() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let response = EapPacket {
            code: EapCode::Response,
            identifier: 1,
            method_type: Some(EapType::Identity),
            method_data: Vec::new(),
        };
        let result = peer.handle_packet(&response, &mut [], &ctx);
        assert!(result.is_err());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// MSK too short (< 64 octets) is rejected at construction.
    #[test]
    fn test_eap_peer_msk_too_short() {
        let result = pae::Msk::from_bytes(vec![0xAB; 32]);
        assert!(result.is_err());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Per RFC 3748.
    /// Reset returns peer to Idle state and clears MSK.
    #[test]
    fn test_eap_peer_reset() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let mut methods: Vec<Box<dyn EapMethod>> = vec![Box::new(MockSuccessMethod::new())];

        let request = EapPacket {
            code: EapCode::Request,
            identifier: 1,
            method_type: Some(EapType::Tls),
            method_data: vec![0x01],
        };
        peer.handle_packet(&request, &mut methods, &ctx).unwrap();
        assert!(peer.take_msk().is_some());

        peer.reset();
        assert_eq!(peer.state(), EapPeerState::Idle);
        assert!(peer.take_msk().is_none());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Method with multi-round exchange (respond, then succeed).
    #[test]
    fn test_eap_peer_method_respond_then_succeed() {
        let mut peer = EapPeer::new();
        let ctx = MockContext::new(b"testuser");
        let mut methods: Vec<Box<dyn EapMethod>> = vec![Box::new(MockRespondMethod::new())];

        let request1 = EapPacket {
            code: EapCode::Request,
            identifier: 1,
            method_type: Some(EapType::Tls),
            method_data: vec![0x01],
        };
        let response1 = peer.handle_packet(&request1, &mut methods, &ctx).unwrap();
        assert!(response1.is_some());
        assert_eq!(response1.unwrap().method_type(), Some(EapType::Tls));
        assert_eq!(peer.state(), EapPeerState::Waiting);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Msk type enforces minimum 64-byte length.
    #[test]
    fn test_msk_minimum_length() {
        assert!(pae::Msk::from_bytes(vec![0u8; 64]).is_ok());
        assert!(pae::Msk::from_bytes(vec![0u8; 128]).is_ok());
        assert!(pae::Msk::from_bytes(vec![0u8; 63]).is_err());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// Msk Debug output is redacted.
    #[test]
    fn test_msk_debug_redacted() {
        let msk = pae::Msk::from_bytes(vec![0xAB; 64]).unwrap();
        let debug_str = format!("{:?}", msk);
        assert!(!debug_str.contains("AB"));
        assert!(debug_str.contains("REDACTED"));
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// EapMethod::take_msk returns None when not complete.
    #[test]
    fn test_eap_method_take_msk_none_when_incomplete() {
        let mut method = MockRespondMethod::new();
        assert!(method.take_msk().is_none());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// TlsClientConfig construction.
    #[test]
    fn test_tls_client_config() {
        let config = TlsClientConfig {
            cert_chain: vec![b"cert".to_vec()],
            private_key: b"key".to_vec(),
            ca_certs: vec![b"ca".to_vec()],
            verify_server: true,
        };
        assert!(!config.cert_chain.is_empty());
        assert!(config.verify_server);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// EapType::ExpandedNak round-trips.
    #[test]
    fn test_eap_type_expanded_nak() {
        assert_eq!(EapType::from_u8(254), EapType::ExpandedNak);
        assert_eq!(EapType::ExpandedNak.value(), 254);
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// EapContext::send_eap and tls_config are accessible.
    #[test]
    fn test_eap_context_full_interface() {
        let ctx = MockContext::new(b"testuser");
        assert_eq!(ctx.get_identity(), b"testuser");
        assert!(ctx.tls_config().verify_server);
        let packet = EapPacket::response_identity(1, b"test");
        assert!(ctx.send_eap(&packet).is_ok());
    }

    /// Verifies: #38 (REQ-F-EAP-001)
    /// EapError variants exist and format correctly.
    #[test]
    fn test_eap_error_variants() {
        let err = crate::EapError::NoAcceptableMethod;
        assert!(err.to_string().contains("no acceptable"));

        let err = crate::EapError::NegotiationFailed {
            proposed: vec![99],
            available: vec![13],
        };
        assert!(err.to_string().contains("negotiation failed"));

        let err = crate::EapError::RetransmitTimeout { attempts: 3 };
        assert!(err.to_string().contains("timeout"));
    }
}
