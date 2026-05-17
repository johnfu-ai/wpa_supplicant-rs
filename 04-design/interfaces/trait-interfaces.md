# Trait Interface Specifications

Per IEEE 1016-2009 | ADR-SM-002 (#74), ADR-KDF-008 (#80), ADR-EVT-007 (#79)

## Overview

Trait interfaces are the primary mechanism for dependency injection and testability across the workspace. Per ADR-SM-002, all state machines accept a context trait that abstracts I/O. Per ADR-KDF-008, cryptographic operations are trait-based. This document provides a consolidated view of all trait interfaces.

## Trait Summary

| Trait | Crate | Purpose | REQ-F |
|---|---|---|---|
| `MkaContext` | `pae` | MKA participant I/O and crypto | #19–#28 |
| `Kdf` | `pae` | Key Derivation Function | #19, #24 |
| `KeyWrap` | `pae` | SAK wrap/unwrap | #25 |
| `Rng` | `pae` | Cryptographic random number generation | #28 |
| `SupplicantPaeContext` | `eapol-supp` | Supplicant PAE I/O and configuration | #11–#18 |
| `EapMethod` | `eap-peer` | Pluggable EAP method interface | #38–#43 |
| `EapContext` | `eap-peer` | EAP peer I/O and TLS config | #38–#43 |
| `LogonContext` | `logon` | Logon Process orchestration I/O | #33–#37 |
| `NetworkIo` | `wpa-supplicant` | L2 packet socket abstraction | #44–#47 |
| `ControlInterface` | `wpa-supplicant` | D-Bus/Unix socket control | #72 |

---

## 1. MkaContext (pae)

```rust
/// Context trait for MKA participant — abstracts I/O and crypto.
///
/// Per ADR-SM-002 (#74) and ADR-KDF-008 (#80).
/// Enables mock injection for unit testing.
///
/// Requirements: #19–#28 (REQ-F-MKA)
/// IEEE Clause: 9
pub trait MkaContext: Send + Sync {
    /// Derive ICK and KEK from CAK and CKN. Per Cl.9.6.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on derivation failure.
    fn derive_keys(&self, cak: &Cak, ckn: &Ckn) -> Result<(Ick, Kek), PaeError>;

    /// Generate a new SAK. Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on generation failure.
    fn generate_sak(&self, cipher_suite: CipherSuite) -> Result<Sak, PaeError>;

    /// Wrap a SAK with KEK for distribution. Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on wrap failure.
    fn wrap_sak(&self, sak: &Sak, kek: &Kek) -> Result<Vec<u8>, PaeError>;

    /// Unwrap a distributed SAK. Per Cl.9.8.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on unwrap failure.
    fn unwrap_sak(&self, wrapped: &[u8], kek: &Kek, an: u8) -> Result<Sak, PaeError>;

    /// Compute ICV for MKPDU. Per Cl.9.7.
    ///
    /// # Errors
    /// Returns `PaeError::CryptoError` on computation failure.
    fn compute_icv(&self, payload: &[u8], ick: &Ick) -> Result<[u8; 16], PaeError>;

    /// Verify ICV of received MKPDU. Per Cl.9.7.
    ///
    /// # Errors
    /// Returns `PaeError::IcvFailed` on verification failure.
    fn verify_icv(&self, payload: &[u8], icv: &[u8], ick: &Ick) -> Result<bool, PaeError>;

    /// Generate a random MI. Per Cl.9.4.
    fn random_mi(&self) -> [u8; 12];

    /// Get current time.
    fn now(&self) -> Duration;

    /// Send an MKPDU. Per Cl.9.7.
    fn send_mkpdu(&self, frame: &[u8]) -> Result<(), PaeError>;
}
```

**Trait Bounds**: `Send + Sync` — required for cross-thread usage in the event loop.

**Mock Strategy**: `MockMkaContext` in test module with controllable return values.

---

## 2. Kdf (pae)

```rust
/// Key Derivation Function trait.
///
/// Per ADR-KDF-008 (#80).
/// Abstracts KDF operations for testability.
///
/// Requirements: #19 (REQ-F-MKA-001), #24 (REQ-F-MKA-006)
/// IEEE Clause: 9.6, 6.2.2
pub trait Kdf: Send + Sync {
    /// Derive ICK from CAK and CKN. Per Cl.9.6.
    fn derive_ick(&self, cak: &Cak, ckn: &Ckn) -> Result<Ick, PaeError>;

    /// Derive KEK from CAK and CKN. Per Cl.9.6.
    fn derive_kek(&self, cak: &Cak, ckn: &Ckn) -> Result<Kek, PaeError>;

    /// Derive CAK from MSK. Per Cl.6.2.2.
    fn derive_cak_from_msk(&self, msk: &Msk) -> Result<(Cak, Ckn), PaeError>;
}
```

**Default Implementation**: `AesCmacKdf` using AES-CMAC per IEEE 802.1X-2020.

**Mock Strategy**: `MockKdf` returns predetermined key material for deterministic tests.

---

## 3. KeyWrap (pae)

```rust
/// Key Wrap trait — AES Key Wrap per RFC 3394.
///
/// Per ADR-KDF-008 (#80).
///
/// Requirements: #25 (REQ-F-MKA-007)
/// IEEE Clause: 9.8
pub trait KeyWrap: Send + Sync {
    /// Wrap (encrypt) a SAK with KEK. Per Cl.9.8.
    fn wrap(&self, sak: &Sak, kek: &Kek) -> Result<Vec<u8>, PaeError>;

    /// Unwrap (decrypt) a SAK with KEK. Per Cl.9.8.
    fn unwrap(&self, wrapped: &[u8], kek: &Kek, an: u8) -> Result<Sak, PaeError>;
}
```

**Default Implementation**: `AesKeyWrap` per RFC 3394.

---

## 4. Rng (pae)

```rust
/// Random Number Generator trait.
///
/// Per ADR-KDF-008 (#80).
///
/// Requirements: #28 (REQ-F-MKA-010)
/// IEEE Clause: 9.4
pub trait Rng: Send + Sync {
    /// Fill buffer with cryptographically secure random bytes.
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), PaeError>;

    /// Generate a random MI (12 bytes). Per Cl.9.4.
    fn random_mi(&self) -> Result<[u8; 12], PaeError>;
}
```

**Default Implementation**: `SystemRng` wrapping `getrandom` crate.

---

## 5. SupplicantPaeContext (eapol-supp)

```rust
/// Context trait for Supplicant PAE — abstracts I/O and time.
///
/// Per ADR-SM-002 (#74).
///
/// Requirements: #11–#18 (REQ-F-PAE)
/// IEEE Clause: 8.3
pub trait SupplicantPaeContext: Send + Sync {
    /// Send an EAPOL frame on the Uncontrolled Port.
    fn send_eapol(&self, frame: &EapolFrame) -> Result<(), EapolError>;

    /// Get the current port state.
    fn get_port_state(&self) -> pae::PortState;

    /// Get the current time.
    fn now(&self) -> Duration;

    /// Get the EAP identity string.
    fn get_identity(&self) -> &[u8];

    /// Get the maximum reauthentication retries.
    fn get_max_retries(&self) -> u32;

    /// Get the heldWhile timer duration (default 60s). Per Cl.8.3.
    fn get_held_while(&self) -> Duration;

    /// Get the startWhen timer duration (default 30s). Per Cl.8.3.
    fn get_start_when(&self) -> Duration;

    /// Get the authWhile timer duration (default 30s). Per Cl.8.3.
    fn get_auth_while(&self) -> Duration;
}
```

**Mock Strategy**: `MockSupplicantPaeContext` with controllable port state, time, and frame capture.

---

## 6. EapMethod (eap-peer)

```rust
/// EAP method trait — interface for pluggable EAP methods.
///
/// Per ADR-FF-006 (#78) and QA-SC-MOD-004 (#89).
/// New EAP methods are added by implementing this trait
/// and adding a feature flag — zero changes to other crates.
///
/// Requirements: #38–#43 (REQ-F-EAP)
pub trait EapMethod: Send + Sync {
    /// EAP method type number.
    fn method_type(&self) -> EapType;

    /// Process a received EAP-Request.
    fn handle_request(
        &mut self,
        identifier: u8,
        data: &[u8],
        ctx: &dyn EapContext,
    ) -> Result<EapMethodOutput, EapError>;

    /// Reset to initial state.
    fn reset(&mut self);

    /// Whether the method has completed.
    fn is_complete(&self) -> bool;

    /// Extract the MSK after success.
    fn take_msk(&mut self) -> Option<Msk>;
}
```

**Extensibility**: Adding EAP-FAST, EAP-SIM, etc. requires only a new `impl EapMethod` + feature flag.

---

## 7. EapContext (eap-peer)

```rust
/// Context trait for EAP peer — abstracts I/O and configuration.
///
/// Per ADR-SM-002 (#74).
///
/// Requirements: #38–#43 (REQ-F-EAP)
pub trait EapContext: Send + Sync {
    /// Send an EAPOL frame containing an EAP packet.
    fn send_eap(&self, packet: &EapPacket) -> Result<(), EapError>;

    /// Get the current time.
    fn now(&self) -> Duration;

    /// Get the configured identity string.
    fn get_identity(&self) -> &[u8];

    /// Get TLS client configuration.
    fn tls_config(&self) -> &TlsClientConfig;

    /// Get retransmission timeout.
    fn retransmit_timeout(&self) -> Duration;
}
```

---

## 8. LogonContext (logon)

```rust
/// Context trait for Logon Process — abstracts PAE/CP/EAPOL interactions.
///
/// Per ADR-SM-002 (#74).
///
/// Requirements: #33–#37 (REQ-F-LOGON)
/// IEEE Clause: 12
pub trait LogonContext: Send + Sync {
    /// Start PAE authentication. Per Cl.12.
    fn start_authentication(&self, nid: Option<&[u8]>) -> Result<(), LogonError>;

    /// Get current Supplicant PAE state.
    fn pae_state(&self) -> eapol_supp::PaeState;

    /// Get current CP state.
    fn cp_state(&self) -> pae::CpState;

    /// Send EAPOL-Announcement-Req. Per Cl.12.
    fn send_announcement_req(&self) -> Result<(), LogonError>;

    /// Install a pre-shared CAK from cache. Per Cl.12.6.
    fn install_cak(&self, cak: pae::Cak, ckn: pae::Ckn) -> Result<(), LogonError>;

    /// Get current time.
    fn now(&self) -> Duration;
}
```

---

## 9. NetworkIo (wpa-supplicant)

```rust
/// Network I/O abstraction — abstracts L2 packet socket.
///
/// Per ADR-SM-002 (#74).
///
/// Requirements: #44–#47 (REQ-F-EAPOL)
pub trait NetworkIo: Send + Sync {
    /// Send an EAPOL frame.
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<(), anyhow::Error>;

    /// Receive an EAPOL frame (non-blocking).
    fn recv_eapol(&self) -> Result<Option<Vec<u8>>, anyhow::Error>;

    /// Get the interface MAC address.
    fn mac_address(&self) -> [u8; 6];

    /// Check if the link is up.
    fn link_up(&self) -> bool;
}
```

**Production Implementation**: `L2PacketSocket` using Linux AF_PACKET socket.

**Test Implementation**: `LoopbackNetworkIo` for integration tests.

---

## 10. ControlInterface (wpa-supplicant)

```rust
/// Control interface — abstracts D-Bus or Unix socket control.
///
/// Per REQ-NF-DEPLOY-005 (#72).
///
/// Requirements: #72 (REQ-NF-DEPLOY-005)
pub trait ControlInterface: Send + Sync {
    /// Poll for control commands (non-blocking).
    fn poll_command(&self) -> Result<Option<ControlCommand>, anyhow::Error>;

    /// Notify of state change.
    fn notify_state(&self, state: &SupplicantState) -> Result<(), anyhow::Error>;
}
```

**Production Implementations**: `DbusControlInterface`, `UnixSocketControlInterface`.

---

## Traceability Matrix

| Trait | ARC-C | ADR | REQ-F | IEEE Clause |
|---|---|---|---|---|
| `MkaContext` | #81 | #74, #80 | #19–#28 | 9 |
| `Kdf` | #81 | #80 | #19, #24 | 9.6, 6.2.2 |
| `KeyWrap` | #81 | #80 | #25 | 9.8 |
| `Rng` | #81 | #80 | #28 | 9.4 |
| `SupplicantPaeContext` | #82 | #74 | #11–#18 | 8.3 |
| `EapMethod` | #83 | #74, #78 | #38–#43 | RFC 3748 |
| `EapContext` | #83 | #74 | #38–#43 | RFC 3748 |
| `LogonContext` | #84 | #74 | #33–#37 | 12 |
| `NetworkIo` | #85 | #74 | #44–#47 | 11 |
| `ControlInterface` | #85 | #74 | #72 | — |
