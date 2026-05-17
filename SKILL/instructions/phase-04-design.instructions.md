---
description: "Phase 04 guidance for detailed design following IEEE 1016-2009. Covers component designs, trait definitions, data models, and design patterns for the IEEE 802.1X-2020 Rust supplicant."
applyTo: "04-design/**"
---

# Phase 04: Detailed Design

**Standards**: IEEE 1016-2009 (Software Design Descriptions)
**XP Integration**: Simple Design, CRC Cards, Design Patterns
**DDD Integration**: Entity, Value Object, Aggregate, Repository, Factory, Domain Service

## Phase Objectives

1. Transform architecture into detailed component designs using DDD tactical patterns
2. Define Rust trait interfaces, struct layouts, and enum definitions
3. Specify data models and serialization respecting domain model
4. Document design patterns and implementation approaches
5. Create design specifications enabling implementation

## Rust Design Patterns

### Entity (Mutable Identity)

```rust
/// Supplicant PAE state machine — Entity with identity and mutable state.
///
/// Per IEEE 802.1X-2020, Clause 8.3.
pub struct SupplicantPae {
    state: PaeState,
    port_id: PortId,
    // ...
}
```

### Value Object (Immutable Identity)

```rust
/// EAPOL frame — Value Object, immutable after creation.
#[derive(Clone, Debug, PartialEq)]
pub struct EapolFrame {
    pub version: u8,
    pub packet_type: EapolPacketType,
    pub body: Vec<u8>,
}
```

### Trait Interface (Dependency Injection)

```rust
/// Trait for Supplicant PAE I/O context.
pub trait SupplicantPaeContext {
    fn send_eapol(&self, dest: &[u8], frame: &[u8]) -> Result<(), EapolError>;
    fn get_port_state(&self) -> PortState;
    fn get_current_time(&self) -> Duration;
}
```

### Error Type (Crate-Level)

```rust
/// Errors for the eapol-supp crate.
#[derive(Debug, thiserror::Error)]
pub enum EapolError {
    #[error("EAPOL send failed: {0}")]
    SendFailed(String),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("timeout: {0}")]
    Timeout(String),
}
```

### Feature-Gated Code

```rust
/// Logon Process is only available with the `logon` feature.
#[cfg(feature = "logon")]
pub mod logon {
    /// Logon Process state machine per IEEE 802.1X-2020, Clause 12.
    pub struct LogonProcess { /* ... */ }
}
```

## DDD Tactical Patterns in Rust

| DDD Pattern | Rust Idiom |
|---|---|
| Entity | `struct` with mutable fields, `impl` block with methods |
| Value Object | `struct` with `#[derive(Clone, PartialEq)]`, no mutation |
| Aggregate | `struct` that owns and enforces invariants on child entities |
| Repository | Trait for data access; implementation hidden behind `dyn Trait` |
| Factory | `impl From<T>` or `fn new()` constructors |
| Domain Service | Free functions or `impl` block on a service struct |
| Domain Event | `enum Event` with variants for each event type |

## Deliverables

- **Files**:
  - `04-design/components/*.md` - Component design specifications
  - `04-design/patterns/*.md` - Design pattern documentation
  - `04-design/interfaces/*.md` - Trait interface specifications

## Phase Exit Criteria

- All component designs reference architecture issues (ARC-C)
- All trait interfaces defined with method signatures
- Error types defined per crate
- Data models specified
- Design decisions trace to requirements

## Phase Gate Approval

Upon gate check approval, the following post-approval actions are required:

1. Post approval comments on all component design GitHub Issues confirming the design is approved for implementation
2. Add `phase:04-approved` label to all design issues
3. Record the gate check report in `04-design/phase-gate-report.md`

## Next Phase

Phase 05: Implementation (`05-implementation/`)
