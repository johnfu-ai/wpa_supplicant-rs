# Phase 04: Detailed Design

IEEE 1016-2009 — Software Design Descriptions

## Purpose

Transform architecture into detailed component designs using DDD tactical patterns, define Rust trait interfaces, struct layouts, and enum definitions.

## Instructions

See `SKILL/instructions/phase-04-design.instructions.md`

## Deliverables

### Component Designs

| Document | Component | Crate | ARC-C | IEEE Clause |
|---|---|---|---|---|
| [pae-core.md](components/pae-core.md) | PAE Core (MKA, CP, Port) | `pae` | #81 | 9, 10 |
| [eapol-supp.md](components/eapol-supp.md) | Supplicant EAPOL / PACP | `eapol-supp` | #82 | 8, 11 |
| [eap-peer.md](components/eap-peer.md) | EAP Authentication Methods | `eap-peer` | #83 | RFC 3748/5216/7170 |
| [logon.md](components/logon.md) | Logon Process / NID | `logon` | #84 | 12 |
| [wpa-supplicant.md](components/wpa-supplicant.md) | Application Integration | `wpa-supplicant` | #85 | — |

### Interface Specifications

| Document | Content |
|---|---|
| [trait-interfaces.md](interfaces/trait-interfaces.md) | All 10 trait interfaces: `MkaContext`, `Kdf`, `KeyWrap`, `Rng`, `SupplicantPaeContext`, `EapMethod`, `EapContext`, `LogonContext`, `NetworkIo`, `ControlInterface` |

### Pattern Documentation

| Document | Content |
|---|---|
| [ddd-patterns.md](patterns/ddd-patterns.md) | DDD tactical pattern classification for all 50+ domain concepts, pattern decision rules, aggregate boundaries, key type special rules |

## Traceability

| Design Artifact | ARC-C | ADRs | REQ-F |
|---|---|---|---|
| pae-core.md | #81 | #73, #74, #75, #76, #80 | #19–#28, #29–#32 |
| eapol-supp.md | #82 | #73, #74, #79 | #11–#18, #44–#47 |
| eap-peer.md | #83 | #73, #74, #78 | #38–#43 |
| logon.md | #84 | #73, #74, #79 | #33–#37 |
| wpa-supplicant.md | #85 | #73, #79 | #68–#72 |
| trait-interfaces.md | #81–#85 | #74, #78, #80 | #11–#28, #33–#43, #44–#47, #72 |
| ddd-patterns.md | #81–#85 | #74, #78, #80 | All |

## Phase Exit Criteria

- [x] All component designs reference architecture issues (ARC-C)
- [x] All trait interfaces defined with method signatures
- [x] Error types defined per crate
- [x] Data models specified
- [x] Design decisions trace to requirements
