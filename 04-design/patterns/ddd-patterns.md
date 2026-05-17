# DDD Tactical Pattern Documentation

Per IEEE 1016-2009 | DDD Tactical Patterns in Rust

## Overview

This document maps each domain concept in the IEEE 802.1X-2020 supplicant to its DDD tactical pattern, Rust idiom, and rationale. The classification follows Domain-Driven Design (Evans, 2003) adapted for Rust's type system.

## Pattern Reference

| DDD Pattern | Rust Idiom | Key Trait | When to Apply |
|---|---|---|---|
| Entity | `struct` with mutable fields + `impl` | Identity persists across state changes | Object has identity independent of attributes |
| Value Object | `struct` with `#[derive(Clone, PartialEq)]` | Immutable, equality by value | Object defined by attributes, no identity |
| Aggregate | `struct` owning child entities | Enforces invariants, transactional boundary | Group of entities with consistency rules |
| Repository | `trait` for data access | `dyn Trait` for implementation hiding | Abstract persistence/retrieval |
| Factory | `impl From<T>` or `fn new()` | Encapsulates construction | Complex construction logic |
| Domain Service | Free functions or `impl` on service struct | Cross-aggregate logic | Logic not belonging to a single entity |
| Domain Event | `enum Event` with variant data | State machine transitions, signaling | Something happened that other components care about |

---

## PAE Core (pae crate)

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `MkaParticipant` | **Aggregate** | `pub struct MkaParticipant<C: MkaContext>` | Owns key hierarchy (CAK→ICK/KEK→SAK), peer lists, and enforces MKA session invariants. Transactional boundary: all key operations go through the participant. |
| `Cak` | **Value Object** | `pub struct Cak` with `ZeroizeOnDrop` | Identity is the key bytes. No Clone — key material must not be duplicated. Immutable after creation. |
| `Ckn` | **Value Object** | `pub struct Ckn` with `Clone, ZeroizeOnDrop` | Identity is the CKN bytes. Clonable for peer list lookup keys. Immutable after creation. |
| `Sak` | **Value Object** | `pub struct Sak` with `ZeroizeOnDrop` | Identity is the key bytes + AN. No Clone. Ephemeral per-session. |
| `Ick` | **Value Object** | `pub struct Ick` with `ZeroizeOnDrop` | Identity is the key bytes. No Clone. Derived from CAK, used for ICV. |
| `Kek` | **Value Object** | `pub struct Kek` with `ZeroizeOnDrop` | Identity is the key bytes. No Clone. Derived from CAK, used for SAK wrap. |
| `Msk` | **Value Object** | `pub struct Msk` with `ZeroizeOnDrop` | Identity is the key bytes. No Clone. Output from EAP, used to derive CAK. |
| `MkaPeer` | **Entity** | `pub struct MkaPeer` with `pub fn promote(&mut self)` | Identity is MI (Member Identifier). Status (Live/Potential) changes over time. MN is mutable. |
| `MkaPeerList` | **Entity** | `pub struct MkaPeerList` with `update_peer()`, `expire_peers()` | Ordered collection with mutable membership. Peers are added, promoted, and expired. |
| `MkaState` | **Value Object** | `pub enum MkaState` (Copy) | Finite state enumeration. Equality is structural. |
| `MkaPeerStatus` | **Value Object** | `pub enum MkaPeerStatus` (Copy) | Finite enumeration. |
| `CpStateMachine` | **Entity** | `pub struct CpStateMachine` with `handle_event()` | Identity is port_id. State (Disabled/Unsecured/Secured) is mutable. |
| `CpState` | **Value Object** | `pub enum CpState` (Copy) | Finite state enumeration. |
| `PortState` | **Value Object** | `pub enum PortState` (Copy) | Finite state enumeration. |
| `CipherSuite` | **Value Object** | `pub enum CipherSuite` (Copy) | Finite enumeration with behavior (`key_len()`, `is_xpn()`). |
| `Sci` | **Value Object** | `pub struct Sci` (Copy) | MAC + port. Identity is the address. Immutable. |
| `PaeEvent` | **Domain Event** | `pub enum PaeEvent` with variant data | Inter-crate signaling per ADR-EVT-007. State machines return `Vec<PaeEvent>`. |
| `CpEvent` | **Domain Event** | `pub enum CpEvent` with variant data | CP-specific events driving state transitions. |
| `TimerWheel` | **Domain Service** | `pub struct TimerWheel` with `schedule()`, `advance_to()` | Provides timer management across all state machines. Bounded execution per ADR-TMR-003. |
| `TimerId` | **Value Object** | `pub enum TimerId` (Copy, Hash) | Finite enumeration of protocol timers. |
| `Kdf` | **Repository** | `pub trait Kdf: Send + Sync` | Abstract KDF for testability per ADR-KDF-008. Implementation hidden behind `dyn Kdf`. |
| `KeyWrap` | **Repository** | `pub trait KeyWrap: Send + Sync` | Abstract key wrap per ADR-KDF-008. |
| `Rng` | **Repository** | `pub trait Rng: Send + Sync` | Abstract RNG per ADR-KDF-008. |
| `MkaContext` | **Repository** | `pub trait MkaContext: Send + Sync` | Composite trait abstracting all MKA I/O. |

### Key Factory Methods

| Type | Factory | Purpose |
|---|---|---|
| `Cak` | `Cak::from_bytes()` | Create from raw key material (Cl.9.3) |
| `Ckn` | `Ckn::from_bytes()` | Create from CKN bytes (Cl.9.3) |
| `Sak` | `Sak::from_bytes()` | Create with AN (Cl.9.8) |
| `MkaParticipant` | `MkaParticipant::new()` | Initialize with CAK, CKN, cipher suite, SCI (Cl.9) |
| `CpStateMachine` | `CpStateMachine::new()` | Create in Disabled state (Cl.10) |
| `TimerWheel` | `TimerWheel::new()` | Create starting at time zero |

---

## Supplicant EAPOL (eapol-supp crate)

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `SupplicantPae` | **Aggregate** | `pub struct SupplicantPae<C: SupplicantPaeContext>` | Owns state, timers, counters. Enforces PACP transition invariants. Transactional boundary for authentication flow. |
| `PaeState` | **Value Object** | `pub enum PaeState` (Copy) | Finite PACP state enumeration (Cl.8.3). |
| `EapolFrame` | **Value Object** | `pub struct EapolFrame` with `Clone, PartialEq` | Immutable after creation. Encode/decode are pure functions. Identity is the frame bytes. |
| `EapolPacketType` | **Value Object** | `pub enum EapolPacketType` (Copy) | Finite enumeration (Cl.11). |
| `EapolVersion` | **Value Object** | `pub enum EapolVersion` (Copy) | Finite enumeration (Cl.11). |
| `EapolAnnouncement` | **Value Object** | `pub struct EapolAnnouncement` with `Clone` | Parsed announcement payload. Immutable after parse. |
| `PaeCounters` | **Value Object** | `pub struct PaeCounters` with `Clone, Default` | Diagnostic counters. Value-based identity. |
| `SupplicantPaeContext` | **Repository** | `pub trait SupplicantPaeContext: Send + Sync` | Abstracts I/O for dependency injection per ADR-SM-002. |

### Key Factory Methods

| Type | Factory | Purpose |
|---|---|---|
| `EapolFrame` | `EapolFrame::start()` | Create EAPOL-Start (Cl.11) |
| `EapolFrame` | `EapolFrame::logoff()` | Create EAPOL-Logoff (Cl.11) |
| `EapolFrame` | `EapolFrame::eap_packet()` | Create EAP Packet frame (Cl.11) |
| `EapolFrame` | `EapolFrame::mka()` | Create EAPOL-MKA frame (Cl.11) |
| `EapolFrame` | `EapolFrame::decode()` | Parse from raw bytes (Cl.11) |
| `SupplicantPae` | `SupplicantPae::new()` | Create in Disconnected state (Cl.8.3) |

---

## EAP Authentication (eap-peer crate)

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `EapPeer` | **Aggregate** | `pub struct EapPeer<C: EapContext>` | Owns method handler and conversation state. Enforces EAP conversation flow per RFC 3748. |
| `EapPeerState` | **Value Object** | `pub enum EapPeerState` (Copy) | Finite EAP conversation state. |
| `EapCode` | **Value Object** | `pub enum EapCode` (Copy) | Finite enumeration (RFC 3748). |
| `EapType` | **Value Object** | `pub enum EapType` (Copy) | EAP method type numbers. Unknown variant for extensibility. |
| `EapPacket` | **Value Object** | `pub struct EapPacket` with `Clone, PartialEq` | Immutable EAP frame. Encode/decode are pure functions. |
| `Msk` | **Value Object** | `pub struct Msk` with `ZeroizeOnDrop` | Ephemeral key material. No Clone. Zeroized on drop. |
| `EapTls` | **Entity** | `pub struct EapTls` with mutable handshake state | TLS handshake progresses through states. Mutable. |
| `EapTlsState` | **Value Object** | `pub enum EapTlsState` (Copy) | Finite TLS handshake state. |
| `EapPeap` | **Entity** | `pub struct EapPeap` with mutable tunnel state | Phased authentication. Mutable. |
| `EapPeapState` | **Value Object** | `pub enum EapPeapState` (Copy) | Finite PEAP state. |
| `EapTeap` | **Entity** | `pub struct EapTeap` with mutable compound binding | Multi-phase with compound MAC. Mutable. |
| `EapTeapState` | **Value Object** | `pub enum EapTeapState` (Copy) | Finite TEAP state. |
| `TlsClientConfig` | **Value Object** | `pub struct TlsClientConfig` | TLS configuration. Immutable after creation. Anti-corruption layer. |
| `EapMethod` | **Repository** | `pub trait EapMethod: Send + Sync` | Pluggable EAP method interface per ADR-FF-006. |
| `EapMethodOutput` | **Domain Event** | `pub enum EapMethodOutput` | Method processing result — respond, success, or failure. |
| `EapContext` | **Repository** | `pub trait EapContext: Send + Sync` | Abstracts EAP I/O per ADR-SM-002. |

### Key Factory Methods

| Type | Factory | Purpose |
|---|---|---|
| `EapPacket` | `EapPacket::response_identity()` | Create EAP-Response/Identity (RFC 3748) |
| `EapPacket` | `EapPacket::response_nak()` | Create EAP-Response/NAK (RFC 3748) |
| `EapPacket` | `EapPacket::decode()` | Parse from raw bytes (RFC 3748) |
| `EapPeer` | `EapPeer::new()` | Create with method list and context |
| `EapTls` | `EapTls::new()` | Create with TLS config (feature-gated) |

---

## Logon Process (logon crate)

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `LogonProcess` | **Aggregate** | `pub struct LogonProcess<C: LogonContext>` | Orchestrates PAE, CP, EAPOL. Owns NID groups and CAK cache. Enforces logon flow invariants (Cl.12). |
| `LogonState` | **Value Object** | `pub enum LogonState` (Copy) | Finite Logon Process state (Cl.12). |
| `NidGroup` | **Value Object** | `pub struct NidGroup` with `Clone, PartialEq, Eq` | Immutable NID definition. Identity is the ID bytes. |
| `CakCache` | **Entity** | `pub struct CakCache` with `HashMap` | Mutable cache. Entries are inserted, looked up, expired. |
| `CakCacheEntry` | **Value Object** | `pub struct CakCacheEntry` with `Clone` | Cached CAK+CKN with metadata. Immutable after creation. |
| `LogonContext` | **Repository** | `pub trait LogonContext: Send + Sync` | Abstracts PAE/CP/EAPOL interactions per ADR-SM-002. |

### Key Factory Methods

| Type | Factory | Purpose |
|---|---|---|
| `NidGroup` | `NidGroup::new()` | Create with name, ID, cipher suite (Cl.12.5) |
| `CakCacheEntry` | `CakCacheEntry::new()` | Create with CAK, CKN, lifetime (Cl.12.6) |
| `CakCache` | `CakCache::new()` | Create empty cache |
| `LogonProcess` | `LogonProcess::new()` | Create with NID groups, cache, config (Cl.12) |

---

## Application (wpa-supplicant crate)

| Concept | DDD Pattern | Rust Idiom | Rationale |
|---|---|---|---|
| `Supplicant` | **Aggregate Root** | `pub struct Supplicant` | Top-level assembly. Owns all state machines. Binary crate entry point. |
| `EventLoop` | **Domain Service** | `impl Supplicant { fn tick() }` | Central dispatch per ADR-EVT-007. Not a separate entity — method on Supplicant. |
| `Config` | **Value Object** | `pub struct Config` with `Clone, Deserialize` | Immutable after loading. Identity is its values. |
| `NetworkIo` | **Repository** | `pub trait NetworkIo: Send + Sync` | Abstracts L2 socket for testability. |
| `ControlInterface` | **Repository** | `pub trait ControlInterface: Send + Sync` | Abstracts control channel for testability. |
| `ControlCommand` | **Domain Event** | `pub enum ControlCommand` | External commands from control interface. |
| `SupplicantState` | **Value Object** | `pub struct SupplicantState` with `Serialize` | State snapshot for control interface reporting. |
| `ShutdownHandler` | **Domain Service** | `pub struct ShutdownHandler` | Signal handling per REQ-NF-DEPLOY-002. |

---

## Pattern Decision Rules

### Entity vs Value Object

Use **Entity** when:
- The object has identity that persists across state changes (e.g., `MkaPeer` has MI)
- The object has mutable fields that change over time (e.g., `MkaPeer.status`)
- Two objects with the same attributes are different (e.g., two peers with same MI but different MN)

Use **Value Object** when:
- The object is defined entirely by its attributes (e.g., `Cak` is its key bytes)
- The object is immutable after creation (e.g., `EapolFrame`)
- Two objects with the same attributes are interchangeable (e.g., two `CpState::Secured` values)

### Key Type Special Rules

Key types (`Cak`, `Ick`, `Kek`, `Sak`, `Msk`) are Value Objects with additional constraints:
- **No `Clone`**: Key material must not be duplicated in memory
- **`ZeroizeOnDrop`**: Key material is zeroed when the value goes out of scope
- **Custom `Debug`**: Shows `[REDACTED]` instead of key bytes
- **No `Serialize`/`Deserialize`**: Key material is never persisted to disk

Exception: `Ckn` implements `Clone` because it is used as a HashMap key for CAK cache lookup.

### Aggregate Boundaries

Each state machine struct is an Aggregate:
- `MkaParticipant` — MKA session boundary
- `SupplicantPae` — PACP authentication boundary
- `EapPeer` — EAP conversation boundary
- `LogonProcess` — Network logon orchestration boundary
- `CpStateMachine` — Controlled Port boundary
- `Supplicant` — Application-level assembly

Aggregates enforce invariants internally. External code never modifies internal state directly — all mutations go through methods that validate transitions.

### Repository Trait Conventions

All context/repository traits follow these conventions:
- **`Send + Sync`** bounds for cross-thread safety
- **`&self` receiver** for all methods (no `&mut self`)
- **`Result<T, Error>`** return type for all fallible operations
- **No generic lifetime parameters** — events are owned values (ADR-EVT-007)
- **Named after the bounded context they serve** (e.g., `MkaContext`, `LogonContext`)
