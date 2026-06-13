//! Configuration file support per REQ-NF-DEPLOY-003 (#70).
//!
//! Implements TOML-based configuration loading for the supplicant daemon.
//!
//! Design: 04-design/components/wpa-supplicant.md
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

/// Pre-shared CAK in TOML configuration.
///
/// Newtype wrapper around the hex-encoded PSK string so that:
/// 1. The `Debug` impl emits `Psk("[REDACTED]")` instead of the raw hex —
///    if a future log site adds `tracing::debug!(?config)` (a common
///    debug pattern), the root key does not leak. Verified by
///    `test_psk_debug_is_redacted` below.
/// 2. The underlying `String` is wrapped in `zeroize::Zeroizing` so the
///    backing allocation is scrubbed on drop (and on every clone's drop
///    too).
///
/// Per ADR-SEC-004 (#76), REQ-NF-SEC-003 (#54), and security-review F-03 (#151).
#[derive(Clone)]
pub struct Psk(zeroize::Zeroizing<String>);

impl Psk {
    /// Borrow the hex string. The returned `&str` lives no longer than
    /// `&self`, so callers cannot stash it past the `Psk`'s drop.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Psk").field(&"[REDACTED]").finish()
    }
}

impl From<String> for Psk {
    fn from(s: String) -> Self {
        Self(zeroize::Zeroizing::new(s))
    }
}

// Custom serde deserialiser — `Zeroizing<String>` does not derive
// `Deserialize`, so we deserialise to a temporary `String` and wrap.
// The temporary's allocation goes via `From<String>` directly into the
// `Zeroizing` wrapper; no plaintext copy survives this function.
impl<'de> serde::Deserialize<'de> for Psk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s))
    }
}

/// EAP authentication configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EapConfig {
    /// EAP identity string.
    pub identity: String,
    /// EAP method configuration.
    pub method: EapMethodConfig,
}

/// EAP method configuration (tagged enum).
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
#[derive(Debug, Clone, serde::Deserialize)]
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

    /// Pre-shared CAK (hex-encoded, optional). Wrapped in [`Psk`] so the
    /// hex bytes are zeroized on drop and redacted from `Debug` output —
    /// see ADR-SEC-004 (#76) and security-review F-03 (#151).
    pub psk: Option<Psk>,
}

impl Default for MacsecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cipher_suite: default_cipher_suite(),
            hello_time: default_hello_time(),
            psk: None,
        }
    }
}

fn default_cipher_suite() -> String {
    "gcm-aes-128".to_string()
}

fn default_hello_time() -> f64 {
    2.0
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

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
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

impl Config {
    /// Load configuration from a TOML file. Per REQ-NF-DEPLOY-003.
    pub fn load(path: &std::path::Path) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Load configuration from TOML string.
    pub fn from_toml(toml: &str) -> Result<Self, anyhow::Error> {
        let config: Config = toml::from_str(toml)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values.
    fn validate(&self) -> Result<(), anyhow::Error> {
        if self.interface.is_empty() {
            anyhow::bail!("interface must not be empty");
        }
        if self.eap.identity.is_empty() {
            anyhow::bail!("eap.identity must not be empty");
        }
        if self.macsec.hello_time <= 0.0 {
            anyhow::bail!("macsec.hello_time must be positive");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: ADR-SEC-004 (#76), security-review F-03 (#151).
    ///
    /// `Psk`'s `Debug` emits `[REDACTED]`, never the underlying hex.
    /// This guards against any future log site adding `tracing::debug!(?config)`
    /// or similar — the root key must not appear in the rendered output.
    #[test]
    fn test_psk_debug_is_redacted() {
        let psk = Psk::from("deadbeefcafebabe0102030405060708".to_string());
        let rendered = format!("{:?}", psk);
        assert!(
            !rendered.contains("deadbeef"),
            "Psk Debug must not contain the hex; got {rendered:?}",
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "Psk Debug must contain [REDACTED]; got {rendered:?}",
        );
    }

    /// Verifies: ADR-SEC-004 (#76), security-review F-03 (#151).
    ///
    /// Debug-formatting an entire `Config` whose `MacsecConfig.psk` is
    /// `Some(...)` does not leak the hex. This is the realistic
    /// foot-gun the F-03 finding called out — a future
    /// `tracing::debug!(?config)` somewhere in the loader would have
    /// silently dumped the CAK before this fix.
    #[test]
    fn test_config_debug_does_not_leak_psk() {
        let toml = r#"
interface = "eth0"

[eap]
identity = "alice@example.com"

[eap.method]
type = "tls"
cert = "/etc/wpa-supplicant/client.pem"
key = "/etc/wpa-supplicant/client.key"
ca = "/etc/wpa-supplicant/ca.pem"

[macsec]
enabled = true
cipher_suite = "gcm-aes-128"
hello_time = 2.0
psk = "deadbeefcafebabe0102030405060708"
"#;
        let config = Config::from_toml(toml).expect("must parse");
        let rendered = format!("{:?}", config);
        assert!(
            !rendered.contains("deadbeef"),
            "Config Debug must not leak the PSK hex; got {rendered:?}",
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "Config Debug must propagate Psk's [REDACTED] marker; got {rendered:?}",
        );
    }

    /// Verifies: ADR-SEC-004 (#76), security-review F-03 (#151).
    ///
    /// `Psk` carries `Zeroizing<String>` internally; cloning preserves
    /// the wrapper so a clone also zeroizes on drop. Type-asserts the
    /// internal field type so any future change dropping the wrapper
    /// fails to compile.
    #[test]
    fn test_psk_inner_is_zeroizing() {
        let psk = Psk::from("hex_bytes".to_string());
        let cloned = psk.clone();
        // Type-assert the inner allocation is wrapped in Zeroizing.
        let _: &zeroize::Zeroizing<String> = &cloned.0;
        assert_eq!(cloned.as_str(), "hex_bytes");
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC1: Load minimal valid TOML config with required fields.
    #[test]
    fn test_config_minimal_valid() {
        let toml = r#"
interface = "eth0"

[eap]
identity = "user@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#;
        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.eap.identity, "user@example.com");
        assert!(!config.macsec.enabled);
        assert_eq!(config.macsec.cipher_suite, "gcm-aes-128");
        assert!((config.macsec.hello_time - 2.0).abs() < f64::EPSILON);
        assert!(!config.logon.enabled);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "text");
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC2: Load full TOML config with all sections.
    #[test]
    fn test_config_full() {
        let toml = r#"
interface = "eth0"

[eap]
identity = "user@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"

[macsec]
enabled = true
cipher_suite = "gcm-aes-256"
hello_time = 1.0
psk = "0102030405060708090a0b0c0d0e0f10"

[logon]
enabled = true
allow_unsecured = true
allow_psk = true

[[logon.nid_groups]]
name = "corp"
id = "0102030405"
cipher_suite = "gcm-aes-128"

[logging]
level = "debug"
format = "json"

[control]
type = "unix"
socket_path = "/run/wpa-supply.sock"
"#;
        let config = Config::from_toml(toml).unwrap();
        assert!(config.macsec.enabled);
        assert_eq!(config.macsec.cipher_suite, "gcm-aes-256");
        assert!((config.macsec.hello_time - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            config.macsec.psk.as_ref().map(|p| p.as_str()),
            Some("0102030405060708090a0b0c0d0e0f10")
        );
        assert!(config.logon.enabled);
        assert!(config.logon.allow_unsecured);
        assert!(config.logon.allow_psk);
        assert_eq!(config.logon.nid_groups.len(), 1);
        assert_eq!(config.logon.nid_groups[0].name, "corp");
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, "json");
        assert!(matches!(config.control.r#type, ControlType::Unix));
        assert_eq!(
            config.control.socket_path.as_deref(),
            Some("/run/wpa-supply.sock")
        );
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC3: EAP-PEAP method with inner method.
    #[test]
    fn test_config_eap_peap() {
        let toml = r#"
interface = "eth0"

[eap]
identity = "user@example.com"

[eap.method]
type = "peap"
ca = "/etc/certs/ca.pem"

[eap.method.inner]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#;
        let config = Config::from_toml(toml).unwrap();
        match &config.eap.method {
            EapMethodConfig::Peap { ca, inner } => {
                assert_eq!(ca, "/etc/certs/ca.pem");
                match inner.as_ref() {
                    EapMethodConfig::Tls { .. } => {}
                    other => panic!("expected Tls inner, got {:?}", other),
                }
            }
            other => panic!("expected Peap, got {:?}", other),
        }
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC4: EAP-TEAP method with optional cert/key.
    #[test]
    fn test_config_eap_teap() {
        let toml = r#"
interface = "eth0"

[eap]
identity = "host.example.com"

[eap.method]
type = "teap"
ca = "/etc/certs/ca.pem"
"#;
        let config = Config::from_toml(toml).unwrap();
        match &config.eap.method {
            EapMethodConfig::Teap { cert, key, ca } => {
                assert!(cert.is_none());
                assert!(key.is_none());
                assert_eq!(ca, "/etc/certs/ca.pem");
            }
            other => panic!("expected Teap, got {:?}", other),
        }
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC5: Reject empty interface name.
    #[test]
    fn test_config_reject_empty_interface() {
        let toml = r#"
interface = ""

[eap]
identity = "user@example.com"

[eap.method]
type = "tls"
cert = "c"
key = "k"
ca = "a"
"#;
        let result = Config::from_toml(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("interface"));
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC6: Reject empty EAP identity.
    #[test]
    fn test_config_reject_empty_identity() {
        let toml = r#"
interface = "eth0"

[eap]
identity = ""

[eap.method]
type = "tls"
cert = "c"
key = "k"
ca = "a"
"#;
        let result = Config::from_toml(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("identity"));
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC7: Reject negative hello_time.
    #[test]
    fn test_config_reject_negative_hello_time() {
        let toml = r#"
interface = "eth0"

[eap]
identity = "user@example.com"

[eap.method]
type = "tls"
cert = "c"
key = "k"
ca = "a"

[macsec]
hello_time = -1.0
"#;
        let result = Config::from_toml(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hello_time"));
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC8: Load config from file.
    #[test]
    fn test_config_load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let toml = r#"
interface = "eth0"

[eap]
identity = "user@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#;
        std::fs::write(&path, toml).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.interface, "eth0");
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC9: File not found returns error.
    #[test]
    fn test_config_file_not_found() {
        let result = Config::load(std::path::Path::new("/nonexistent/path.toml"));
        assert!(result.is_err());
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// AC10: Invalid TOML syntax returns error.
    #[test]
    fn test_config_invalid_toml() {
        let toml = "this is not valid toml {{{{";
        let result = Config::from_toml(toml);
        assert!(result.is_err());
    }

    /// Verifies: #70 (REQ-NF-DEPLOY-003)
    /// D-Bus control interface config.
    #[test]
    fn test_config_dbus_control() {
        let toml = r#"
interface = "eth0"

[eap]
identity = "user@example.com"

[eap.method]
type = "tls"
cert = "c"
key = "k"
ca = "a"

[control]
type = "dbus"
dbus_name = "org.example.wpa"
"#;
        let config = Config::from_toml(toml).unwrap();
        assert!(matches!(config.control.r#type, ControlType::Dbus));
        assert_eq!(config.control.dbus_name.as_deref(), Some("org.example.wpa"));
    }
}
