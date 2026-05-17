# Component Design: eap-peer — EAP Authentication Methods

Per IEEE 1016-2009 | ARC-C-EAP-003 (#83)

## Component Identity

| Field | Value |
|---|---|
| **Crate** | `crates/eap-peer/` |
| **Bounded Context** | EAP Authentication |
| **IEEE Clause** | RFC 3748 (EAP), RFC 5216 (EAP-TLS), RFC 7170 (PEAP/TEAP) |
| **ADRs** | #73 (ADR-WS-001), #74 (ADR-SM-002), #78 (ADR-FF-006) |
| **Requirements** | #38–#43 (REQ-F-EAP) |

## DDD Pattern Classification

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `EapPeer` | Aggregate | `struct<C>` owning state, method handler | Transactional boundary for EAP conversation (RFC 3748) |
| `EapCode` | Value Object | `enum` (Copy) | Finite enumeration of EAP code field |
| `EapType` | Value Object | `enum` (Copy) | EAP method type numbers |
| `EapPacket` | Value Object | `struct` with `Clone, PartialEq` | Immutable EAP frame; identity is its bytes |
| `Msk` | Value Object | `struct` with `ZeroizeOnDrop`, no `Clone` | Ephemeral key material; zeroized on drop |
| `EapMethod` | Repository (trait) | `trait` | Abstract method interface for pluggable EAP methods |
| `EapTls` | Entity | `struct` with mutable handshake state | TLS handshake has identity and mutable progress |
| `EapPeap` | Entity | `struct` with mutable tunnel state | Phased authentication has mutable state |
| `EapTeap` | Entity | `struct` with mutable compound binding state | Multi-phase with compound binding |
| `EapContext` | Repository (trait) | `trait` | Abstracts I/O for EAP peer (ADR-SM-002) |
| `EapError` | Domain Event (error) | `thiserror` enum | Error classification per ADR-ERR-005 |

## Struct and Enum Definitions

### EAP Peer Framework (RFC 3748)

```rust
/// EAP code field values.
///
/// Per RFC 3748, Section 4.1.
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

/// EAP method type numbers.
///
/// Per IANA EAP Method Type Registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapType {
    /// Identity (1).
    Identity,
    /// Notification (2).
    Notification,
    /// NAK (Legacy) (3).
    Nak,
    /// EAP-TLS (13).
    Tls,
    /// PEAP (25).
    Peap,
    /// TEAP (55).
    Teap,
    /// Expanded NAK (254).
    ExpandedNak,
    /// Experimental/Unknown type.
    Unknown(u8),
}

impl EapType {
    /// EAP type number.
    pub fn value(&self) -> u8;
}

/// EAP packet — Value Object for EAP frame encoding/decoding.
///
/// Per RFC 3748, Section 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    /// EAP code.
    pub code: EapCode,
    /// EAP identifier.
    pub identifier: u8,
    /// EAP method type (for Request/Response).
    pub method_type: Option<EapType>,
    /// EAP method data (payload after type field).
    pub method_data: Vec<u8>,
}

impl EapPacket {
    /// EAP header size: code(1) + id(1) + length(2) = 4 bytes.
    pub const HEADER_SIZE: usize = 4;

    /// Maximum EAP packet size (per RFC 3748).
    pub const MAX_SIZE: usize = 1500;

    /// Encode to bytes for transmission. Per RFC 3748.
    pub fn encode(&self) -> Result<Vec<u8>, EapError>;

    /// Decode from raw bytes. Per RFC 3748.
    pub fn decode(bytes: &[u8]) -> Result<Self, EapError>;

    /// Create an EAP-Response/Identity packet. Per RFC 3748.
    pub fn response_identity(identifier: u8, identity: &[u8]) -> Self;

    /// Create an EAP-Response/NAK packet proposing alternate methods. Per RFC 3748.
    pub fn response_nak(identifier: u8, proposed_types: &[EapType]) -> Self;
}
```

### EAP Context Trait (Dependency Injection)

```rust
/// Context trait for EAP peer — abstracts I/O and configuration.
///
/// Per ADR-SM-002 (#74).
/// Enables mock injection for unit testing.
pub trait EapContext: Send + Sync {
    /// Send an EAPOL frame containing an EAP packet.
    fn send_eap(&self, packet: &EapPacket) -> Result<(), EapError>;

    /// Get the current time.
    fn now(&self) -> Duration;

    /// Get the configured identity string.
    fn get_identity(&self) -> &[u8];

    /// Get TLS client configuration (certificates, private key).
    fn tls_config(&self) -> &TlsClientConfig;

    /// Get the retransmission timeout.
    fn retransmit_timeout(&self) -> Duration;
}
```

### EAP Method Trait (Pluggable Methods)

```rust
/// EAP method trait — interface for pluggable EAP authentication methods.
///
/// Per ADR-FF-006 (#78) — each method is feature-gated.
/// Per QA-SC-MOD-004 (#89) — new methods added without core changes.
pub trait EapMethod: Send + Sync {
    /// EAP method type number.
    fn method_type(&self) -> EapType;

    /// Process a received EAP-Request for this method.
    ///
    /// Returns `EapMethodOutput` indicating the next action.
    fn handle_request(
        &mut self,
        identifier: u8,
        data: &[u8],
        ctx: &dyn EapContext,
    ) -> Result<EapMethodOutput, EapError>;

    /// Reset the method to initial state (for reauthentication).
    fn reset(&mut self);

    /// Whether the method has completed successfully and produced an MSK.
    fn is_complete(&self) -> bool;

    /// Extract the MSK after successful completion.
    ///
    /// Returns `None` if not complete or method doesn't produce MSK.
    fn take_msk(&mut self) -> Option<Msk>;
}

/// Output from an EAP method processing a request.
#[derive(Debug)]
pub enum EapMethodOutput {
    /// Send an EAP-Response with the given data.
    Respond { data: Vec<u8> },
    /// Authentication succeeded, MSK available.
    Success { msk: Msk },
    /// Authentication failed.
    Failure { reason: String },
}
```

### EAP Peer Aggregate

```rust
/// EAP peer — Aggregate root for an EAP authentication conversation.
///
/// Per RFC 3748.
/// Owns the method handler and manages the EAP conversation state.
/// Generic over context trait for testability.
pub struct EapPeer<C: EapContext> {
    /// Current EAP state.
    state: EapPeerState,
    /// Current method identifier (for request matching).
    current_identifier: u8,
    /// Active EAP method handler (if negotiated).
    method: Option<Box<dyn EapMethod>>,
    /// Available EAP methods (ordered by preference).
    methods: Vec<Box<dyn EapMethod>>,
    /// MSK from completed authentication.
    msk: Option<Msk>,
    /// Context (injected).
    ctx: C,
}

/// EAP peer state machine state.
///
/// Per RFC 3748, Section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapPeerState {
    /// Initial — waiting for EAP-Request/Identity.
    Initial,
    /// Method negotiation in progress.
    Negotiating,
    /// Method-specific exchange in progress.
    Method,
    /// Authentication succeeded.
    Success,
    /// Authentication failed.
    Failure,
}

impl<C: EapContext> EapPeer<C> {
    /// Create a new EAP peer with the given methods and context.
    pub fn new(ctx: C, methods: Vec<Box<dyn EapMethod>>) -> Self;

    /// Process a received EAP packet. Per RFC 3748.
    ///
    /// Returns events generated by processing.
    pub fn handle_packet(&mut self, packet: &EapPacket) -> Result<Vec<pae::PaeEvent>, EapError>;

    /// Current EAP peer state.
    pub fn state(&self) -> EapPeerState;

    /// Take the MSK after successful authentication.
    pub fn take_msk(&mut self) -> Option<Msk>;

    /// Reset for reauthentication.
    pub fn reset(&mut self);
}
```

### EAP-TLS (RFC 5216)

```rust
/// EAP-TLS method — certificate-based mutual authentication.
///
/// Per RFC 5216.
/// Feature-gated: `#[cfg(feature = "eap-tls")]`.
#[cfg(feature = "eap-tls")]
pub struct EapTls {
    /// TLS handshake state.
    state: EapTlsState,
    /// TLS client configuration (certificates, private key).
    tls_config: TlsClientConfig,
    /// Derived MSK (after successful handshake).
    msk: Option<Msk>,
}

#[cfg(feature = "eap-tls")]
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

#[cfg(feature = "eap-tls")]
impl EapMethod for EapTls {
    fn method_type(&self) -> EapType { EapType::Tls }
    fn handle_request(&mut self, identifier: u8, data: &[u8], ctx: &dyn EapContext) -> Result<EapMethodOutput, EapError>;
    fn reset(&mut self);
    fn is_complete(&self) -> bool;
    fn take_msk(&mut self) -> Option<Msk>;
}
```

### EAP-PEAP (RFC 7170)

```rust
/// EAP-PEAP method — TLS tunnel with inner EAP-MSCHAPv2.
///
/// Per RFC 7170.
/// Feature-gated: `#[cfg(feature = "eap-peap")]`.
#[cfg(feature = "eap-peap")]
pub struct EapPeap {
    /// PEAP state.
    state: EapPeapState,
    /// TLS client configuration.
    tls_config: TlsClientConfig,
    /// Inner EAP method (typically MSCHAPv2).
    inner_method: Option<Box<dyn EapMethod>>,
    /// Derived MSK.
    msk: Option<Msk>,
}

#[cfg(feature = "eap-peap")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapPeapState {
    /// Initial state.
    Initial,
    /// Phase 1 — TLS tunnel establishment.
    Phase1,
    /// Phase 2 — inner authentication.
    Phase2,
    /// Authentication complete.
    Complete,
}

#[cfg(feature = "eap-peap")]
impl EapMethod for EapPeap {
    fn method_type(&self) -> EapType { EapType::Peap }
    fn handle_request(&mut self, identifier: u8, data: &[u8], ctx: &dyn EapContext) -> Result<EapMethodOutput, EapError>;
    fn reset(&mut self);
    fn is_complete(&self) -> bool;
    fn take_msk(&mut self) -> Option<Msk>;
}
```

### EAP-TEAP (RFC 7170)

```rust
/// EAP-TEAP method — TLS tunnel with compound binding.
///
/// Per RFC 7170.
/// Feature-gated: `#[cfg(feature = "eap-teap")]`.
#[cfg(feature = "eap-teap")]
pub struct EapTeap {
    /// TEAP state.
    state: EapTeapState,
    /// TLS client configuration.
    tls_config: TlsClientConfig,
    /// Inner method(s).
    inner_methods: Vec<Box<dyn EapMethod>>,
    /// Derived MSK.
    msk: Option<Msk>,
    /// Compound MAC for result validation.
    compound_mac: Option<Vec<u8>>,
}

#[cfg(feature = "eap-teap")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapTeapState {
    /// Initial state.
    Initial,
    /// TLS tunnel establishment.
    TunnelEstablish,
    /// Inner authentication.
    InnerAuth,
    /// Result indication with compound binding.
    Result,
    /// Authentication complete.
    Complete,
}

#[cfg(feature = "eap-teap")]
impl EapMethod for EapTeap {
    fn method_type(&self) -> EapType { EapType::Teap }
    fn handle_request(&mut self, identifier: u8, data: &[u8], ctx: &dyn EapContext) -> Result<EapMethodOutput, EapError>;
    fn reset(&mut self);
    fn is_complete(&self) -> bool;
    fn take_msk(&mut self) -> Option<Msk>;
}
```

### TLS Configuration

```rust
/// TLS client configuration for EAP methods.
///
/// Abstracts TLS library specifics. Anti-corruption layer:
/// EAP methods use this; PAE core never sees TLS internals.
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
```

## Error Types

```rust
/// Errors for EAP peer operations.
///
/// Per ADR-ERR-005 (#77).
#[derive(Debug, thiserror::Error)]
pub enum EapError {
    /// EAP authentication failed.
    #[error("EAP authentication failed: {0}")]
    AuthFailed(String),

    /// Invalid EAP packet (malformed, truncated).
    #[error("invalid EAP packet: {0}")]
    InvalidPacket(String),

    /// TLS handshake error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// No acceptable EAP method (NAK exhausted).
    #[error("no acceptable EAP method")]
    NoAcceptableMethod,

    /// EAP method negotiation failed.
    #[error("method negotiation failed: proposed {proposed:?}, available {available:?}")]
    NegotiationFailed { proposed: Vec<u8>, available: Vec<u8> },

    /// Retransmission timeout.
    #[error("retransmission timeout after {attempts} attempts")]
    RetransmitTimeout { attempts: u32 },

    /// PAE core error propagated from `pae` crate.
    #[error("PAE error: {0}")]
    Pae(#[from] pae::PaeError),
}
```

## Invariants

| ID | Invariant | Enforced By |
|---|---|---|
| INV-EAP-001 | MSK is zeroized on drop | `#[derive(ZeroizeOnDrop)]` on `Msk` |
| INV-EAP-002 | MSK never implements `Clone` | No `Clone` derive on `Msk` |
| INV-EAP-003 | EAP methods are feature-gated per ADR-FF-006 | `#[cfg(feature = "eap-tls")]` etc. |
| INV-EAP-004 | `handle_packet()` never panics on malformed input | All parse paths return `Result` |
| INV-EAP-005 | TLS internals never leak to PAE core | Anti-corruption layer via `TlsClientConfig` |
| INV-EAP-006 | New EAP methods require zero changes to other crates (QA-SC-MOD-004) | `EapMethod` trait + feature flags |
| INV-EAP-007 | Method negotiation follows RFC 3748 NAK procedure | `EapPeer::handle_packet()` |

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `pae` | workspace | Shared kernel (PaeEvent, PaeError, Msk) |
| `tracing` | 0.1 | Structured logging |
| `thiserror` | 2.x | Error type derivation |

## Feature Flags

| Feature | Default | Enables |
|---|---|---|
| `eap-tls` | yes | EAP-TLS method (RFC 5216) |
| `eap-peap` | no | EAP-PEAP method (RFC 7170) |
| `eap-teap` | no | EAP-TEAP method (RFC 7170) |
