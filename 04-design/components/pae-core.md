# Component Design: pae — PAE Core (MKA, CP, Port)

Per IEEE 1016-2009 | ARC-C-PAE-001 (#81)

## Component Identity

| Field | Value |
|---|---|
| **Crate** | `crates/pae/` |
| **Bounded Context** | PAE Core (Shared Kernel) |
| **IEEE Clause** | 9 (MKA), 10 (CP) |
| **ADRs** | #73 (ADR-WS-001), #74 (ADR-SM-002), #75 (ADR-TMR-003), #76 (ADR-SEC-004), #80 (ADR-KDF-008) |
| **Requirements** | #19–#28 (REQ-F-MKA), #29–#32 (REQ-F-CP), #48–#49 (REQ-NF-PERF), #54 (REQ-NF-SEC-003), #61 (REQ-NF-PORT-002) |

## DDD Pattern Classification

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `MkaParticipant` | Aggregate | `struct` owning child entities, enforcing invariants | Transactional consistency boundary for MKA session (Cl.9) |
| `Cak` | Value Object | `struct` with `ZeroizeOnDrop`, no `Clone` | Immutable key material; identity is its value (Cl.9.3) |
| `Ckn` | Value Object | `struct` with `ZeroizeOnDrop`, `Clone` | CKN identifies a CAK; may be copied for peer list lookup (Cl.9.3) |
| `Sak` | Value Object | `struct` with `ZeroizeOnDrop`, no `Clone` | Ephemeral session key; never duplicated (Cl.9.8) |
| `Ick` | Value Object | `struct` with `ZeroizeOnDrop`, no `Clone` | Integrity check key; never duplicated (Cl.9.6) |
| `Kek` | Value Object | `struct` with `ZeroizeOnDrop`, no `Clone` | Key wrap key; never duplicated (Cl.9.6) |
| `MkaState` | Value Object | `enum` (Copy) | Finite state enumeration |
| `MkaPeer` | Entity | `struct` with mutable `status` field | Peer has identity (MI) that persists across status changes (Cl.9.4) |
| `MkaPeerList` | Entity | `struct` with mutable `Vec<MkaPeer>` | Ordered list with mutable membership (Cl.9.4) |
| `CpState` | Value Object | `enum` (Copy) | Finite state enumeration |
| `CpStateMachine` | Entity | `struct` with mutable `CpState` | State machine with identity (port_id) and mutable state (Cl.10) |
| `PortState` | Value Object | `enum` (Copy) | Finite state enumeration |
| `CipherSuite` | Value Object | `enum` (Copy) | Finite enumeration of MACsec cipher suites |
| `PaeEvent` | Domain Event | `enum` with variant data | Inter-crate signaling (ADR-EVT-007) |
| `TimerWheel` | Domain Service | `struct` with `BTreeMap<Instant, Vec<TimerId>>` | Bounded execution, tick-driven (ADR-TMR-003) |
| `Kdf` | Repository (trait) | `trait` | Abstract KDF for testability (ADR-KDF-008) |
| `KeyWrap` | Repository (trait) | `trait` | Abstract key wrap/unwrap (ADR-KDF-008) |
| `Rng` | Repository (trait) | `trait` | Abstract random number generation (ADR-KDF-008) |

## Struct and Enum Definitions

### Key Types (Cl.9.3, Cl.9.6, Cl.9.8)

```rust
/// Connectivity Association Key — the root key for MKA key hierarchy.
///
/// Per IEEE 802.1X-2020, Clause 9.3.
/// Zeroized on drop; no Clone to prevent key duplication.
#[derive(Debug, zeroize::ZeroizeOnDrop)]
pub struct Cak {
    /// Raw key bytes (32 bytes for AES-256, 16 for AES-128).
    key: [u8; Self::MAX_LEN],
    /// Active key length in bytes.
    len: usize,
}

impl Cak {
    /// Maximum CAK length (AES-256).
    const MAX_LEN: usize = 32;

    /// Create a CAK from raw bytes. Per Cl.9.3.
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if `key` is empty or exceeds 32 bytes.
    pub fn from_bytes(key: &[u8]) -> Result<Self, PaeError>;

    /// CAK length in bytes.
    pub fn len(&self) -> usize;

    /// Whether the CAK is empty (zero-length, should not occur after construction).
    pub fn is_empty(&self) -> bool;

    /// Key bytes as a slice (for KDF operations only).
    /// Not exported outside the crate; internal use only.
    pub(crate) fn as_bytes(&self) -> &[u8];
}

impl std::fmt::Debug for Cak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cak([REDACTED])")
    }
}

/// CAK Name — identifies a Connectivity Association.
///
/// Per IEEE 802.1X-2020, Clause 9.3.
/// Clonable for peer list lookup; zeroized on drop.
#[derive(Clone, Debug, zeroize::ZeroizeOnDrop, PartialEq, Eq)]
pub struct Ckn {
    /// CKN bytes (variable length, up to 32 bytes per Cl.9.3).
    value: Vec<u8>,
}

impl Ckn {
    /// Create a CKN from raw bytes. Per Cl.9.3.
    pub fn from_bytes(value: Vec<u8>) -> Result<Self, PaeError>;

    /// CKN bytes as a slice.
    pub fn as_bytes(&self) -> &[u8];
}

/// Secure Association Key — ephemeral per-session key.
///
/// Per IEEE 802.1X-2020, Clause 9.8.
/// Zeroized on drop; no Clone.
#[derive(Debug, zeroize::ZeroizeOnDrop)]
pub struct Sak {
    /// SAK key bytes.
    key: [u8; Self::MAX_LEN],
    /// Active key length.
    len: usize,
    /// Association Number (AN) for this SAK.
    an: u8,
}

impl Sak {
    const MAX_LEN: usize = 32;

    /// Create a SAK from raw bytes with an AN. Per Cl.9.8.
    pub fn from_bytes(key: &[u8], an: u8) -> Result<Self, PaeError>;

    /// Association Number.
    pub fn an(&self) -> u8;

    /// SAK length in bytes.
    pub fn len(&self) -> usize;
}

/// Integrity Check Key — derived from CAK for MKPDU integrity.
///
/// Per IEEE 802.1X-2020, Clause 9.6.
/// Zeroized on drop; no Clone.
#[derive(Debug, zeroize::ZeroizeOnDrop)]
pub struct Ick {
    key: [u8; Self::MAX_LEN],
    len: usize,
}

impl Ick {
    const MAX_LEN: usize = 32;

    /// Create an ICK from raw bytes. Per Cl.9.6.
    pub fn from_bytes(key: &[u8]) -> Result<Self, PaeError>;
}

/// Key Encryption Key — derived from CAK for SAK wrapping.
///
/// Per IEEE 802.1X-2020, Clause 9.6.
/// Zeroized on drop; no Clone.
#[derive(Debug, zeroize::ZeroizeOnDrop)]
pub struct Kek {
    key: [u8; Self::MAX_LEN],
    len: usize,
}

impl Kek {
    const MAX_LEN: usize = 32;

    /// Create a KEK from raw bytes. Per Cl.9.6.
    pub fn from_bytes(key: &[u8]) -> Result<Self, PaeError>;
}

/// Master Session Key — output from EAP authentication.
///
/// Per IEEE 802.1X-2020, Cl.6.2.2.
/// Zeroized on drop; no Clone.
/// Used to derive the initial CAK when no PSK is configured.
#[derive(Debug, zeroize::ZeroizeOnDrop)]
pub struct Msk {
    key: [u8; Self::MAX_LEN],
    len: usize,
}

impl Msk {
    const MAX_LEN: usize = 64;

    /// Create an MSK from raw bytes.
    pub fn from_bytes(key: &[u8]) -> Result<Self, PaeError>;

    /// MSK length in bytes.
    pub fn len(&self) -> usize;
}
```

### MKA State Machine (Cl.9)

```rust
/// MKA participant state.
///
/// Per IEEE 802.1X-2020, Clause 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkaState {
    /// Initial — no CAK available, awaiting key material.
    Initial,
    /// Pending — CAK available, key derivation in progress or awaiting peers.
    Pending,
    /// Established — MKA session active, SAK installed.
    Established,
}

/// MKA peer status within a participant's peer list.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkaPeerStatus {
    /// Peer is in the Potential Peer List.
    Potential,
    /// Peer is in the Live Peer List.
    Live,
}

/// MKA peer entry — identity and status of a remote MKA participant.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
#[derive(Debug, Clone)]
pub struct MkaPeer {
    /// Member Identifier (MI) — 12-byte unique identifier per Cl.9.4.
    mi: [u8; 12],
    /// Member Number (MN) — monotonically increasing per Cl.9.4.
    mn: u32,
    /// Peer status (Live or Potential).
    status: MkaPeerStatus,
    /// Time of last received MKPDU from this peer.
    last_rx: Option<Duration>,
}

impl MkaPeer {
    /// Create a peer from MI and MN. Per Cl.9.4.
    pub fn new(mi: [u8; 12], mn: u32) -> Self;

    /// Member Identifier.
    pub fn mi(&self) -> &[u8; 12];

    /// Member Number.
    pub fn mn(&self) -> u32;

    /// Peer status.
    pub fn status(&self) -> MkaPeerStatus;

    /// Promote peer from Potential to Live.
    pub fn promote(&mut self);

    /// Update MN from received MKPDU. Per Cl.9.4.
    ///
    /// # Errors
    /// Returns `PaeError::InvalidTransition` if MN is not monotonically increasing.
    pub fn update_mn(&mut self, mn: u32) -> Result<(), PaeError>;

    /// Update last receive timestamp.
    pub fn touch(&mut self, now: Duration);
}

/// MKA peer list — ordered collection of MKA peers.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
/// At most 2 Live Peers and 2 Potential Peers (supplicant limit).
#[derive(Debug, Clone)]
pub struct MkaPeerList {
    /// Live peers (max 2 for supplicant).
    live: Vec<MkaPeer>,
    /// Potential peers (max 2 for supplicant).
    potential: Vec<MkaPeer>,
}

impl MkaPeerList {
    /// Maximum live peers for a supplicant.
    const MAX_LIVE: usize = 2;
    /// Maximum potential peers for a supplicant.
    const MAX_POTENTIAL: usize = 2;

    /// Create an empty peer list.
    pub fn new() -> Self;

    /// Find a peer by MI.
    pub fn find_by_mi(&self, mi: &[u8; 12]) -> Option<&MkaPeer>;

    /// Find a peer by MI (mutable).
    pub fn find_by_mi_mut(&mut self, mi: &[u8; 12]) -> Option<&mut MkaPeer>;

    /// Add or update a peer from a received MKPDU. Per Cl.9.4.
    ///
    /// # Errors
    /// Returns `PaeError::PeerListFull` if both lists are at capacity.
    pub fn update_peer(&mut self, mi: [u8; 12], mn: u32, now: Duration) -> Result<(), PaeError>;

    /// Remove peers whose MKA Life timer has expired. Per Cl.9.4.
    pub fn expire_peers(&mut self, now: Duration, mka_life: Duration) -> Vec<[u8; 12]>;

    /// Live peers iterator.
    pub fn live_peers(&self) -> impl Iterator<Item = &MkaPeer>;

    /// Number of live peers.
    pub fn live_count(&self) -> usize;
}

/// Key Server election result.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyServerRole {
    /// This participant is the Key Server.
    Actor,
    /// A remote peer is the Key Server.
    Partner,
}

/// MKA Participant — the Aggregate root for an MKA session.
///
/// Per IEEE 802.1X-2020, Clause 9.
/// Owns the key hierarchy, peer lists, and enforces invariants.
/// Generic over crypto context trait for testability.
pub struct MkaParticipant<C: MkaContext> {
    /// Current MKA state.
    state: MkaState,
    /// Connectivity Association Key.
    cak: Option<Cak>,
    /// CAK Name.
    ckn: Option<Ckn>,
    /// Derived ICK.
    ick: Option<Ick>,
    /// Derived KEK.
    kek: Option<Kek>,
    /// Installed SAK (current).
    sak: Option<Sak>,
    /// Cipher suite for this CA.
    cipher_suite: CipherSuite,
    /// This participant's MI.
    mi: [u8; 12],
    /// This participant's MN.
    mn: u32,
    /// SCI (Secure Channel Identifier) for this participant.
    sci: Sci,
    /// Peer list.
    peers: MkaPeerList,
    /// Key server election result.
    key_server: KeyServerRole,
    /// MKA Hello Time (default 2000ms per Cl.9.5).
    hello_time: Duration,
    /// MKA Life Time (default 6000ms per Cl.9.5).
    life_time: Duration,
    /// SAK retire time (default 3000ms per Cl.9.8).
    sak_retire_time: Duration,
    /// Crypto context (injected).
    ctx: C,
}

/// Secure Channel Identifier.
///
/// Per IEEE 802.1X-2020, Clause 9.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sci {
    /// System MAC address (6 bytes).
    mac: [u8; 6],
    /// Port number.
    port: u16,
}

impl Sci {
    /// Create an SCI from MAC and port number.
    pub fn new(mac: [u8; 6], port: u16) -> Self;

    /// MAC address bytes.
    pub fn mac(&self) -> &[u8; 6];

    /// Port number.
    pub fn port(&self) -> u16;
}
```

### MKA Context Trait (Dependency Injection)

```rust
/// Context trait for MKA participant — abstracts I/O and crypto.
///
/// Per ADR-SM-002 (#74) and ADR-KDF-008 (#80).
/// Enables mock injection for unit testing.
pub trait MkaContext: Send + Sync {
    /// Derive ICK and KEK from CAK. Per Cl.9.6.
    fn derive_keys(&self, cak: &Cak, ckn: &Ckn) -> Result<(Ick, Kek), PaeError>;

    /// Generate a new SAK. Per Cl.9.8.
    fn generate_sak(&self, cipher_suite: CipherSuite) -> Result<Sak, PaeError>;

    /// Wrap a SAK with KEK for distribution. Per Cl.9.8.
    fn wrap_sak(&self, sak: &Sak, kek: &Kek) -> Result<Vec<u8>, PaeError>;

    /// Unwrap a distributed SAK. Per Cl.9.8.
    fn unwrap_sak(&self, wrapped: &[u8], kek: &Kek, an: u8) -> Result<Sak, PaeError>;

    /// Compute ICV (Integrity Check Value) for MKPDU. Per Cl.9.7.
    fn compute_icv(&self, payload: &[u8], ick: &Ick) -> Result<[u8; 16], PaeError>;

    /// Verify ICV of received MKPDU. Per Cl.9.7.
    fn verify_icv(&self, payload: &[u8], icv: &[u8], ick: &Ick) -> Result<bool, PaeError>;

    /// Generate a random MI for this participant. Per Cl.9.4.
    fn random_mi(&self) -> [u8; 12];

    /// Get current time (for timer calculations).
    fn now(&self) -> Duration;

    /// Send an MKPDU on the Uncontrolled Port.
    fn send_mkpdu(&self, frame: &[u8]) -> Result<(), PaeError>;
}
```

### MKA Participant Methods

```rust
impl<C: MkaContext> MkaParticipant<C> {
    /// Initialize a new MKA participant. Per Cl.9.
    ///
    /// # Errors
    /// Returns `PaeError::KeyError` if CAK/CKN derivation fails.
    pub fn new(ctx: C, cak: Cak, ckn: Ckn, cipher_suite: CipherSuite, sci: Sci) -> Result<Self, PaeError>;

    /// Process a received MKPDU. Per Cl.9.4, Cl.9.7.
    ///
    /// Returns events generated by processing.
    ///
    /// # Errors
    /// Returns `PaeError` on ICV failure or peer list overflow.
    pub fn handle_mkpdu(&mut self, mkpdu: &[u8]) -> Result<Vec<PaeEvent>, PaeError>;

    /// Perform a single timer-driven step. Per Cl.9.5, Cl.9.8.
    ///
    /// Called by the event loop on each tick.
    /// Returns events generated (e.g., MKPDU to transmit, SAK to install).
    pub fn step(&mut self) -> Result<Vec<PaeEvent>, PaeError>;

    /// Current MKA state.
    pub fn state(&self) -> MkaState;

    /// Current SAK, if installed.
    pub fn sak(&self) -> Option<&Sak>;

    /// Current cipher suite.
    pub fn cipher_suite(&self) -> CipherSuite;

    /// Current peer list.
    pub fn peers(&self) -> &MkaPeerList;

    /// Whether this participant is the Key Server. Per Cl.9.4.
    pub fn is_key_server(&self) -> bool;

    /// Initiate SAK distribution (Key Server only). Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::NotKeyServer` if this participant is not the Key Server.
    pub fn distribute_sak(&mut self) -> Result<Vec<PaeEvent>, PaeError>;
}
```

### CP State Machine (Cl.10)

```rust
/// Controlled Port state.
///
/// Per IEEE 802.1X-2020, Clause 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpState {
    /// Controlled Port is disabled (blocked).
    Disabled,
    /// Controlled Port is unsecured (open, no MACsec).
    Unsecured,
    /// Controlled Port is secured (MACsec active).
    Secured,
}

/// CP State Machine — manages Controlled Port transitions.
///
/// Per IEEE 802.1X-2020, Clause 10.
/// Transitions driven by MKA SAK installation and Logon Process.
pub struct CpStateMachine {
    /// Current CP state.
    state: CpState,
    /// Port identifier.
    port_id: u32,
    /// Current Secure Channel (if in Secured state).
    secure_channel: Option<SecureChannel>,
    /// Current Secure Association (if SAK installed).
    current_sa: Option<SecureAssociation>,
}

/// Secure Channel — represents an active MACsec secure channel.
///
/// Per IEEE 802.1X-2020, Clause 10.
#[derive(Debug, Clone)]
pub struct SecureChannel {
    /// SCI for this channel.
    sci: Sci,
    /// Cipher suite in use.
    cipher_suite: CipherSuite,
    /// Channel offset for XPN mode.
    offset: u64,
}

/// Secure Association — represents a SAK within a Secure Channel.
///
/// Per IEEE 802.1X-2020, Clause 10.
#[derive(Debug, Clone)]
pub struct SecureAssociation {
    /// Association Number (AN), 0-3.
    an: u8,
    /// SAK for this association.
    sak: Sak,
    /// Whether this SA is receiving.
    receiving: bool,
    /// Whether this SA is transmitting.
    transmitting: bool,
}

impl CpStateMachine {
    /// Create a new CP state machine in Disabled state. Per Cl.10.
    pub fn new(port_id: u32) -> Self;

    /// Process a CP event. Per Cl.10.
    ///
    /// Returns events generated by the transition.
    pub fn handle_event(&mut self, event: CpEvent) -> Result<Vec<PaeEvent>, PaeError>;

    /// Current CP state.
    pub fn state(&self) -> CpState;

    /// Install a SAK — transitions to Secured. Per Cl.10.
    ///
    /// # Errors
    /// Returns `PaeError::InvalidTransition` if not in Unsecured state.
    pub fn install_sak(&mut self, sak: Sak, sci: Sci, cipher_suite: CipherSuite) -> Result<Vec<PaeEvent>, PaeError>;

    /// Retire current SAK. Per Cl.10.
    pub fn retire_sak(&mut self) -> Result<Vec<PaeEvent>, PaeError>;

    /// Disable the Controlled Port. Per Cl.10.
    pub fn disable(&mut self) -> Result<Vec<PaeEvent>, PaeError>;
}

/// Events that drive CP state transitions.
#[derive(Debug, Clone)]
pub enum CpEvent {
    /// MKA has produced a new SAK for installation.
    SakAvailable { sak: Sak, sci: Sci, cipher_suite: CipherSuite },
    /// Logon Process requests port enable (unsecured).
    EnableUnsecured,
    /// Logon Process or MKA requests port disable.
    Disable,
    /// SAK retire timer expired.
    SakRetireExpired,
}
```

### Cipher Suite (Cl.9)

```rust
/// MACsec cipher suite identifiers.
///
/// Per IEEE 802.1X-2020, Clause 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// GCM-AES-128 (default).
    GcmAes128,
    /// GCM-AES-256.
    GcmAes256,
    /// GCM-AES-XPN-256 (extended packet number).
    GcmAesXpn256,
    /// Null cipher suite (no encryption, authentication only).
    Null,
}

impl CipherSuite {
    /// Key length in bytes for this cipher suite.
    pub fn key_len(&self) -> usize;

    /// Whether this cipher suite uses XPN (extended packet number).
    pub fn is_xpn(&self) -> bool;
}
```

### Timer Wheel (ADR-TMR-003)

```rust
/// Protocol timer identifiers.
///
/// Per IEEE 802.1X-2020 and ADR-TMR-003 (#75).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// MKA Hello Time (default 2000ms). Per Cl.9.5.
    MkaHello,
    /// MKA Bounded Hello Time (default 500ms). Per Cl.9.5.
    MkaBoundedHello,
    /// MKA Life Time (default 6000ms). Per Cl.9.5.
    MkaLife,
    /// Held While timer for Supplicant PAE. Per Cl.8.
    HeldWhile,
    /// SAK Retire timer. Per Cl.9.8.
    SakRetire,
}

/// Deterministic timer wheel for protocol timers.
///
/// Per ADR-TMR-003 (#75).
/// Tick-driven (no async); virtual clock for testing.
/// BTreeMap-based for O(log n) expiry lookup.
pub struct TimerWheel {
    /// Current virtual time.
    now: Duration,
    /// Scheduled timers: expiry time → list of timer IDs.
    timers: BTreeMap<Duration, Vec<TimerId>>,
    /// Active timer IDs and their expiry times (for cancellation).
    active: HashMap<TimerId, Duration>,
}

impl TimerWheel {
    /// Create a timer wheel starting at time zero.
    pub fn new() -> Self;

    /// Schedule a timer. Returns the expiry time.
    ///
    /// If the timer is already active, it is rescheduled.
    pub fn schedule(&mut self, id: TimerId, duration: Duration) -> Duration;

    /// Cancel a timer.
    pub fn cancel(&mut self, id: TimerId);

    /// Advance the clock and return all expired timer IDs.
    ///
    /// Bounded execution: O(k log n) where k is expired timers.
    pub fn advance_to(&mut self, now: Duration) -> Vec<TimerId>;

    /// Current virtual time.
    pub fn now(&self) -> Duration;

    /// Whether a timer is currently active.
    pub fn is_active(&self, id: TimerId) -> bool;
}

impl Default for TimerWheel {
    fn default() -> Self { Self::new() }
}
```

### Domain Events (ADR-EVT-007)

```rust
/// Inter-crate events dispatched through the event loop.
///
/// Per ADR-EVT-007 (#79).
/// Owned values — no lifetimes. All state machines return `Vec<PaeEvent>`.
#[derive(Debug, Clone)]
pub enum PaeEvent {
    // --- MKA events ---
    /// MKA participant needs to transmit an MKPDU.
    MkaTransmit { mkpdu: Vec<u8> },
    /// MKA has derived and installed a new SAK.
    MkaSakInstalled { sak: Sak, sci: Sci, cipher_suite: CipherSuite },
    /// MKA session established (peer list is live).
    MkaSessionEstablished,
    /// MKA session terminated (no live peers).
    MkaSessionTerminated,
    /// MKA SAK retire timer expired.
    MkaSakRetire,

    // --- CP events ---
    /// Controlled Port transitioned to a new state.
    CpStateChanged { new_state: CpState, port_id: u32 },
    /// CP requests SAK installation.
    CpSakInstall { sak: Sak, sci: Sci, cipher_suite: CipherSuite },

    // --- EAPOL events ---
    /// EAPOL frame received on Uncontrolled Port.
    EapolFrameReceived { frame: Vec<u8> },
    /// EAPOL frame needs to be transmitted.
    EapolFrameTransmit { frame: Vec<u8> },

    // --- EAP events ---
    /// EAP authentication succeeded; MSK available.
    EapSuccess { msk: Msk },
    /// EAP authentication failed.
    EapFailure,

    // --- Logon events ---
    /// Logon Process requests authentication start.
    LogonAuthStart { nid: Option<Vec<u8>> },
    /// Logon Process requests logoff.
    LogonLogoff,

    // --- Timer events ---
    /// A protocol timer has expired.
    TimerExpired { id: TimerId },

    // --- System events ---
    /// Link status changed.
    LinkChanged { up: bool },
    /// Graceful shutdown requested.
    Shutdown,
}
```

### Crypto Trait Abstractions (ADR-KDF-008)

```rust
/// Key Derivation Function trait.
///
/// Per ADR-KDF-008 (#80).
/// Abstracts KDF operations for testability.
pub trait Kdf: Send + Sync {
    /// Derive ICK from CAK and CKN. Per Cl.9.6.
    fn derive_ick(&self, cak: &Cak, ckn: &Ckn) -> Result<Ick, PaeError>;

    /// Derive KEK from CAK and CKN. Per Cl.9.6.
    fn derive_kek(&self, cak: &Cak, ckn: &Ckn) -> Result<Kek, PaeError>;

    /// Derive CAK from MSK. Per Cl.6.2.2.
    fn derive_cak_from_msk(&self, msk: &Msk) -> Result<(Cak, Ckn), PaeError>;
}

/// Key Wrap trait — AES Key Wrap per RFC 3394.
///
/// Per ADR-KDF-008 (#80).
pub trait KeyWrap: Send + Sync {
    /// Wrap (encrypt) a SAK with KEK. Per Cl.9.8.
    fn wrap(&self, sak: &Sak, kek: &Kek) -> Result<Vec<u8>, PaeError>;

    /// Unwrap (decrypt) a SAK with KEK. Per Cl.9.8.
    fn unwrap(&self, wrapped: &[u8], kek: &Kek, an: u8) -> Result<Sak, PaeError>;
}

/// Random Number Generator trait.
///
/// Per ADR-KDF-008 (#80).
pub trait Rng: Send + Sync {
    /// Fill buffer with cryptographically secure random bytes.
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), PaeError>;

    /// Generate a random MI (12 bytes). Per Cl.9.4.
    fn random_mi(&self) -> Result<[u8; 12], PaeError>;
}
```

## Error Types

```rust
/// Errors for PAE core operations.
///
/// Per ADR-ERR-005 (#77).
#[derive(Debug, thiserror::Error)]
pub enum PaeError {
    /// Invalid state transition.
    #[error("invalid state transition: from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    /// Key operation failed.
    #[error("key error: {0}")]
    KeyError(String),

    /// Peer list is full (supplicant limit reached).
    #[error("peer list full: {which}")]
    PeerListFull { which: String },

    /// Operation requires Key Server role.
    #[error("not key server")]
    NotKeyServer,

    /// ICV verification failed.
    #[error("ICV verification failed")]
    IcvFailed,

    /// MKPDU parsing failed.
    #[error("invalid MKPDU: {0}")]
    InvalidMkpdu(String),

    /// Timer operation failed.
    #[error("timer error: {0}")]
    TimerError(String),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    CryptoError(String),
}
```

## Invariants

| ID | Invariant | Enforced By |
|---|---|---|
| INV-PAE-001 | CAK/ICK/KEK/SAK/MSK are zeroized on drop | `#[derive(ZeroizeOnDrop)]` |
| INV-PAE-002 | CAK/ICK/KEK/SAK/MSK never implement `Clone` | No `Clone` derive on key types |
| INV-PAE-003 | Debug for key types shows `[REDACTED]` | Custom `Debug` impl |
| INV-PAE-004 | MN is monotonically increasing per peer | `MkaPeer::update_mn()` validates |
| INV-PAE-005 | Live peer list ≤ 2, Potential peer list ≤ 2 | `MkaPeerList` constants |
| INV-PAE-006 | CP transitions: Disabled→Unsecured→Secured (and reverse) | `CpStateMachine::handle_event()` |
| INV-PAE-007 | SAK distribution only by Key Server | `MkaParticipant::distribute_sak()` checks role |
| INV-PAE-008 | `pae` crate has no workspace crate dependencies | Cargo.toml |
| INV-PAE-009 | TimerWheel `advance_to` is O(k log n) bounded | BTreeMap-based implementation |
| INV-PAE-010 | `step()` never panics — returns `Result` | All paths return `Result<T, PaeError>` |

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `zeroize` | 1.x (with derive) | Key material zeroization |
| `tracing` | 0.1 | Structured logging |
| `thiserror` | 2.x | Error type derivation |

No workspace crate dependencies — `pae` is the shared kernel.

## Feature Flags

| Feature | Default | Enables |
|---|---|---|
| `macsec` | yes | MKA, CP state machine, cipher suite types |
| `std` | yes | `std` library; disable for `no_std` |
