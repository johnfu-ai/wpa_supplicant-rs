# ADR-WS-001: Workspace Crate Boundaries and Dependency Graph

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #73

**Status**: Accepted
**Date**: 2026-05-17

## Context

The IEEE 802.1X-2020 supplicant comprises 5 distinct protocol areas (Supplicant PAE Cl.8, MKA Cl.9, CP Cl.10, Logon Cl.12, EAP methods). Each area has its own state machine, types, and concerns. The Cargo workspace must separate these into crates that respect bounded contexts while avoiding circular dependencies.

## Decision

Adopt a 5-crate workspace with a strict unidirectional dependency graph:

```
wpa-supplicant → eapol-supp, eap-peer, pae, logon
logon → pae, eapol-supp
eapol-supp → pae
eap-peer → pae
pae → (minimal deps: zeroize, tracing, thiserror)
```

| Crate | Bounded Context | IEEE Clause | Key Types |
|---|---|---|---|
| `pae` | PAE Core (MKA, CP, Port) | 9, 10 | `MkaParticipant`, `CpState`, `PortState`, `Cak`, `Sak` |
| `eapol-supp` | Supplicant EAPOL / PACP | 8, 11 | `SupplicantPae`, `EapolFrame`, `PaeState` |
| `eap-peer` | EAP Authentication | RFC 3748/5216 | `EapPeer`, `EapMethod`, `Msk` |
| `logon` | Logon Process / NID | 12 | `LogonProcess`, `NidGroup`, `CakCache` |
| `wpa-supplicant` | Application Integration | — | CLI, config, event loop, daemon |

`pae` is the shared kernel — its types (MKA, CP, Port) are used across all crates.

## Consequences

### Positive
- No circular dependencies — Cargo enforces acyclic dependency graph
- Each crate is a bounded context with clear responsibility
- Crates can be compiled and tested independently
- `no_std` achievable for `pae` core

### Negative
- Cross-crate refactoring requires coordinated changes
- `pae` may grow large (MKA + CP + Port) — may need splitting later

## Requirements Satisfied

- #11–#18 (REQ-F-PAE), #19–#28 (REQ-F-MKA), #29–#32 (REQ-F-CP), #33–#37 (REQ-F-LOGON), #38–#43 (REQ-F-EAP), #44–#47 (REQ-F-EAPOL)
- #57 (REQ-NF-REL-001), #61 (REQ-NF-PORT-002)

## Traceability

- **Traces to**: StR-001 (#1), StR-002 (#2), StR-003 (#3), StR-004 (#4), StR-005 (#5)
