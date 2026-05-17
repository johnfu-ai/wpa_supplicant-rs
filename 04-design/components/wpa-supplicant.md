# Component Design: wpa-supplicant — Application Integration

Per IEEE 1016-2009 | ARC-C-WPA-005 (#85)

## Component Identity

| Field | Value |
|---|---|
| **Crate** | `crates/wpa-supplicant/` |
| **Bounded Context** | Application Integration |
| **IEEE Clause** | — (assembly, not protocol) |
| **ADRs** | #73 (ADR-WS-001), #79 (ADR-EVT-007) |
| **Requirements** | #68–#72 (REQ-NF-DEPLOY), #59 (REQ-NF-REL-003), #60 (REQ-NF-PORT-001) |

## DDD Pattern Classification

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `Supplicant` | Aggregate Root | `struct` owning all state machines | Top-level assembly and lifecycle |
| `EventLoop` | Domain Service | `struct` with `run()` method | Central dispatch; not a domain entity |
| `Config` | Value Object | `struct` with `Clone, Deserialize` | Immutable after loading; identity is its values |
| `NetworkIo` | Repository (trait) | `trait` | Abstracts L2 socket I/O for testability |
| `ControlInterface` | Repository (trait) | `trait` | Abstracts D-Bus/Unix socket for testability |
| `SupplicantError` | Domain Event (error) | `thiserror`/`anyhow` | Binary crate uses `anyhow` per ADR-ERR-005 |

## Struct and Enum Definitions

### Supplicant (Top-Level Assembly)

```rust
/// IEEE 802.1X-2020 Supplicant — top-level application.
///
/// Assembles all protocol state machines and runs the event loop.
/// This is the binary crate entry point.
pub struct Supplicant {
    /// Application configuration.
    config: Config,
    /// Supplicant PAE state machine.
    pae: eapol_supp::SupplicantPae<NetworkIo>,
    /// EAP peer (if EAP authentication is configured).
    eap_peer: Option<eap_peer::EapPeer<EapIoAdapter>>,
    /// MKA participant (if MACsec is enabled).
    mka: Option<pae::MkaParticipant<MkaIoAdapter>>,
    /// CP state machine.
    cp: pae::CpStateMachine,
    /// Logon Process (if configured).
    logon: Option<logon::LogonProcess<LogonIoAdapter>>,
    /// Timer wheel (shared across state machines).
    timers: pae::TimerWheel,
    /// Network I/O (L2 socket).
    network: NetworkIo,
    /// Control interface (D-Bus or Unix socket).
    control: Option<Box<dyn ControlInterface>>,
    /// Shutdown signal.
    shutdown: bool,
}

impl Supplicant {
    /// Initialize the supplicant from configuration. Per Cl.1.
    pub fn new(config: Config) -> Result<Self, anyhow::Error>;

    /// Run the main event loop. Per ADR-EVT-007 (#79).
    ///
    /// Blocks until shutdown is requested.
    /// Dispatches PaeEvents between state machines.
    pub fn run(&mut self) -> Result<(), anyhow::Error>;

    /// Request graceful shutdown.
    pub fn shutdown(&mut self);
}
```

### Event Loop (ADR-EVT-007)

```rust
/// Event loop — dispatches PaeEvents between state machines.
///
/// Per ADR-EVT-007 (#79).
/// Central dispatch: receives events from state machines,
/// routes them to the appropriate handler.
impl Supplicant {
    /// Dispatch a single event to the appropriate state machine.
    fn dispatch_event(&mut self, event: pae::PaeEvent) -> Result<Vec<pae::PaeEvent>, anyhow::Error> {
        match event {
            // EAPOL frame received → Supplicant PAE
            pae::PaeEvent::EapolFrameReceived { frame } => { ... }

            // EAP Success → Logon Process
            pae::PaeEvent::EapSuccess { msk } => { ... }

            // EAP Failure → Logon Process
            pae::PaeEvent::EapFailure => { ... }

            // MKA SAK installed → CP state machine
            pae::PaeEvent::MkaSakInstalled { sak, sci, cipher_suite } => { ... }

            // CP state changed → control interface notification
            pae::PaeEvent::CpStateChanged { new_state, port_id } => { ... }

            // Timer expired → appropriate state machine
            pae::PaeEvent::TimerExpired { id } => { ... }

            // Link changed → all state machines
            pae::PaeEvent::LinkChanged { up } => { ... }

            // Shutdown → set flag
            pae::PaeEvent::Shutdown => { ... }

            // ... other events
        }
    }

    /// Perform one iteration of the event loop.
    ///
    /// 1. Check for incoming EAPOL frames (non-blocking)
    /// 2. Check for control interface commands (non-blocking)
    /// 3. Advance timer wheel
    /// 4. Call step() on each active state machine
    /// 5. Dispatch resulting events
    fn tick(&mut self) -> Result<(), anyhow::Error>;
}
```

### Configuration (REQ-NF-DEPLOY-003)

```rust
/// Supplicant configuration — loaded from TOML file.
///
/// Per REQ-NF-DEPLOY-003 (#70).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    /// Network interface name.
    pub interface: String,

    /// EAP configuration.
    pub eap: EapConfig,

    /// MACsec/MKA configuration.
    #[serde(default)]
    pub macsec: MacsecConfig,

    /// Logon Process configuration.
    #[serde(default)]
    pub logon: LogonConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Control interface configuration.
    #[serde(default)]
    pub control: ControlConfig,
}

/// EAP authentication configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EapConfig {
    /// EAP identity string.
    pub identity: String,

    /// EAP method configuration.
    pub method: EapMethodConfig,
}

/// EAP method configuration.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type")]
pub enum EapMethodConfig {
    /// EAP-TLS configuration.
    #[serde(rename = "tls")]
    Tls {
        /// Client certificate path.
        cert: String,
        /// Client private key path.
        key: String,
        /// CA certificate path.
        ca: String,
    },

    /// EAP-PEAP configuration.
    #[serde(rename = "peap")]
    Peap {
        /// CA certificate path.
        ca: String,
        /// Inner method configuration.
        inner: Box<EapMethodConfig>,
    },

    /// EAP-TEAP configuration.
    #[serde(rename = "teap")]
    Teap {
        /// Client certificate path (optional for machine-only).
        cert: Option<String>,
        /// Client private key path.
        key: Option<String>,
        /// CA certificate path.
        ca: String,
    },
}

/// MACsec/MKA configuration.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct MacsecConfig {
    /// Whether MACsec is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Cipher suite preference.
    #[serde(default = "default_cipher_suite")]
    pub cipher_suite: String,

    /// MKA Hello Time in seconds.
    #[serde(default = "default_hello_time")]
    pub hello_time: f64,

    /// Pre-shared CAK (hex-encoded, optional).
    pub psk: Option<String>,
}

fn default_cipher_suite() -> String { "gcm-aes-128".to_string() }
fn default_hello_time() -> f64 { 2.0 }

/// Logon Process configuration.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct LogonConfig {
    /// Whether Logon Process is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// NID groups to match.
    #[serde(default)]
    pub nid_groups: Vec<NidGroupConfig>,

    /// Allow unsecured connectivity fallback.
    #[serde(default)]
    pub allow_unsecured: bool,

    /// Allow PSK fallback.
    #[serde(default)]
    pub allow_psk: bool,
}

/// NID group configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NidGroupConfig {
    /// NID name.
    pub name: String,
    /// NID identifier (hex-encoded).
    pub id: String,
    /// Preferred cipher suite.
    #[serde(default)]
    pub cipher_suite: String,
}

/// Logging configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LoggingConfig {
    /// Log level filter (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log output format (text, json).
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "text".to_string() }

/// Control interface configuration.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ControlConfig {
    /// Control interface type.
    #[serde(default)]
    pub r#type: ControlType,

    /// Unix socket path (for Unix socket control).
    pub socket_path: Option<String>,

    /// D-Bus service name (for D-Bus control).
    pub dbus_name: Option<String>,
}

/// Control interface type.
#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlType {
    /// No control interface.
    #[default]
    None,
    /// Unix domain socket.
    Unix,
    /// D-Bus.
    Dbus,
}

impl Config {
    /// Load configuration from a TOML file. Per REQ-NF-DEPLOY-003.
    pub fn load(path: &std::path::Path) -> Result<Self, anyhow::Error>;

    /// Load configuration from TOML string.
    pub fn from_toml(toml: &str) -> Result<Self, anyhow::Error>;
}
```

### Network I/O Trait (Repository)

```rust
/// Network I/O abstraction — abstracts L2 packet socket.
///
/// Per ADR-SM-002 (#74).
/// Enables testability without real network interfaces.
pub trait NetworkIo: Send + Sync {
    /// Send an EAPOL frame on the Uncontrolled Port.
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<(), anyhow::Error>;

    /// Receive an EAPOL frame (non-blocking).
    ///
    /// Returns `Ok(None)` if no frame is available.
    fn recv_eapol(&self) -> Result<Option<Vec<u8>>, anyhow::Error>;

    /// Get the MAC address of the interface.
    fn mac_address(&self) -> [u8; 6];

    /// Check if the link is up.
    fn link_up(&self) -> bool;
}
```

### Control Interface Trait (Repository)

```rust
/// Control interface — abstracts D-Bus or Unix socket control.
///
/// Per REQ-NF-DEPLOY-005 (#72).
/// Enables testability without real D-Bus/socket.
pub trait ControlInterface: Send + Sync {
    /// Poll for control commands (non-blocking).
    ///
    /// Returns `Ok(None)` if no command is available.
    fn poll_command(&self) -> Result<Option<ControlCommand>, anyhow::Error>;

    /// Notify control interface of state change.
    fn notify_state(&self, state: &SupplicantState) -> Result<(), anyhow::Error>;
}

/// Commands from the control interface.
#[derive(Debug, Clone)]
pub enum ControlCommand {
    /// Request reauthentication.
    Reauthenticate,
    /// Request logoff.
    Logoff,
    /// Get current state.
    GetState,
    /// Set log level.
    SetLogLevel { level: String },
    /// Request shutdown.
    Shutdown,
}

/// Supplicant state exposed to the control interface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SupplicantState {
    /// Current PAE state.
    pub pae_state: String,
    /// Current CP state.
    pub cp_state: String,
    /// Current Logon state (if applicable).
    pub logon_state: Option<String>,
    /// Selected NID (if applicable).
    pub selected_nid: Option<String>,
    /// MKA session status.
    pub mka_established: bool,
    /// Number of live MKA peers.
    pub mka_live_peers: usize,
}
```

### Signal Handling (REQ-NF-DEPLOY-002)

```rust
/// Graceful shutdown handler.
///
/// Per REQ-NF-DEPLOY-002 (#69).
/// Catches SIGTERM/SIGINT and sets shutdown flag within 5 seconds.
pub struct ShutdownHandler {
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl ShutdownHandler {
    /// Install signal handlers. Per REQ-NF-DEPLOY-002.
    pub fn install() -> Result<Self, anyhow::Error>;

    /// Whether shutdown has been requested.
    pub fn is_shutdown(&self) -> bool;
}
```

## Error Handling

Binary crate uses `anyhow` per ADR-ERR-005 (#77). Library crates (pae, eapol-supp, eap-peer, logon) use crate-local `thiserror` enums. The binary converts library errors to `anyhow::Error` at the boundary:

```rust
// In the event loop, library errors are converted:
let events = self.pae.handle_eapol(&frame)
    .map_err(|e| anyhow::anyhow!("PAE error: {}", e))?;
```

## Invariants

| ID | Invariant | Enforced By |
|---|---|---|
| INV-WPA-001 | Event loop processes events in FIFO order | `dispatch_event()` processes sequentially |
| INV-WPA-002 | Graceful shutdown within 5 seconds of SIGTERM/SIGINT | `ShutdownHandler` with timeout |
| INV-WPA-003 | No `anyhow` in library crates | ADR-ERR-005; `anyhow` only in `wpa-supplicant` |
| INV-WPA-004 | Configuration validated before state machine initialization | `Config::load()` validates |
| INV-WPA-005 | Network I/O errors do not crash the supplicant | `tick()` catches and logs errors |
| INV-WPA-006 | Structured logging via `tracing` | `tracing-subscriber` with env-filter |

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `pae` | workspace | PAE core types and state machines |
| `eapol-supp` | workspace | Supplicant PAE and EAPOL frames |
| `eap-peer` | workspace | EAP authentication methods |
| `logon` | workspace | Logon Process and NID |
| `tracing` | 0.1 | Structured logging |
| `tracing-subscriber` | 0.3 (with env-filter) | Log subscriber setup |
| `anyhow` | 1.x | Error handling in binary crate |
| `serde` | 1.x (with derive) | Configuration deserialization |
| `toml` | 0.8 | TOML configuration parsing |

## Feature Flags

| Feature | Default | Enables |
|---|---|---|
| `dbus-control` | no | D-Bus control interface |
| `systemd` | no | systemd socket activation |
