---
description: "Phase 03 guidance for architecture design following ISO/IEC/IEEE 42010:2011. Covers architectural views, decisions (ADRs), patterns, and component boundaries for the IEEE 802.1X-2020 Rust supplicant."
applyTo: "03-architecture/**"
---

# Phase 03: Architecture Design

**Standards**: ISO/IEC/IEEE 42010:2011 (Architecture Description), IEEE 1016-2009
**XP Integration**: Simple Design, Metaphor, Refactoring Foundation

## Phase Objectives

1. Define system architecture and structure
2. Create architectural views for different stakeholder concerns
3. Document architectural decisions (ADRs)
4. Identify architectural patterns and styles
5. Define workspace crate boundaries and interfaces
6. Establish technical foundation for detailed design

## Cargo Workspace Architecture

```
wpa_supplicant-rs/
├── Cargo.toml                  # [workspace]
├── crates/
│   ├── eapol-supp/             # Supplicant EAPOL state machine (Clause 8)
│   ├── eap-peer/               # EAP peer methods (TLS, PEAP, TEAP)
│   ├── pae/                    # PAE, MKA, CP state machines (Clauses 9-10)
│   ├── logon/                  # Logon Process (Clause 12)
│   └── wpa-supplicant/         # Top-level binary crate
```

### Dependency Graph

```
wpa-supplicant → eapol-supp, eap-peer, pae, logon
logon → pae, eapol-supp
eapol-supp → pae
eap-peer → pae
pae → (minimal deps: zeroize, tracing)
```

### Crate Boundaries (Bounded Contexts)

| Crate | Bounded Context | Key Types |
|---|---|---|
| `pae` | Port Access Entity core | `PaeState`, `MkaKey`, `CpState`, `PortState` |
| `eapol-supp` | Supplicant EAPOL | `SupplicantPae`, `EapolFrame` |
| `eap-peer` | EAP authentication | `EapMethod`, `EapPeer` |
| `logon` | Logon Process / NID | `LogonState`, `NidGroup` |
| `wpa-supplicant` | Application integration | CLI, config, event loop |

## Architectural Patterns

- **Trait-based dependency injection**: State machines accept `&dyn Context` traits for testability
- **Error handling**: Each crate defines its own `Error` enum; use `thiserror` for derives
- **Feature flags**: `#[cfg(feature = "macsec")]`, `#[cfg(feature = "logon")]`, `#[cfg(feature = "eap-teap")]`
- **No global state**: All state in structs; pass by reference
- **Async optional**: Sync by default; `tokio` feature flag for async I/O

## Deliverables

- **GitHub Issues**: ADR-XXX-NNN, ARC-C-XXX-NNN, QA-SC-XXX-NNN
- **Files**:
  - `03-architecture/adr/` - Architecture Decision Records
  - `03-architecture/context-map.md` - Bounded Context relationships
  - `03-architecture/quality-scenarios/` - ATAM quality scenarios

## Phase Exit Criteria

- All ADRs documented with rationale
- Crate boundaries and dependency graph defined
- Quality scenarios defined
- All architecture issues link to requirements
- Context map shows bounded context relationships

## Next Phase

Phase 04: Detailed Design (`04-design/`)
