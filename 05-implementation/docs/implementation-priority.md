# REQ-F Implementation Priority

Phase 05 — TDD implementation order based on crate dependency graph and protocol criticality.

## Priority Rules

1. **Crate dependency order**: `pae` first (shared kernel), then `eapol-supp`/`eap-peer`, then `logon`, then `wpa-supplicant`
2. **Foundation before protocol**: Value Objects and traits before Aggregates and state machines
3. **Core path before features**: Required protocol path before feature-gated options (EAP-TLS before PEAP/TEAP)

## P0 — Foundation (pae crate, no dependencies)

| # | REQ-F | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 19 | REQ-F-MKA-001 | MKA Key Hierarchy | `pae` | — | Done |
| 23 | REQ-F-MKA-005 | MKA Cipher Suite Selection | `pae` | — | Done |
| 28 | REQ-F-MKA-010 | Random Number Generation | `pae` | — | Done |
| 27 | REQ-F-MKA-009 | CAK Identification | `pae` | MKA-001 | Done |
| 29 | REQ-F-CP-001 | CP State Machine | `pae` | — | Done |

## P1 — EAPOL Frame Layer (eapol-supp crate, depends on pae)

| # | REQ-F | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 44 | REQ-F-EAPOL-001 | EAPOL Frame Encoding/Decoding | `eapol-supp` | — | Done |
| 11 | REQ-F-PAE-001 | Supplicant PACP State Machine | `eapol-supp` | EAPOL-001, CP-001 | Done |
| 14 | REQ-F-PAE-004 | Supplicant PAE Timers | `eapol-supp` | PAE-001 | Done |
| 12 | REQ-F-PAE-002 | Supplicant PAE Higher Layer Interface | `eapol-supp` | PAE-001 | Done |
| 15 | REQ-F-PAE-005 | EAPOL-Start Transmission | `eapol-supp` | PAE-001, EAPOL-001 | Done |
| 45 | REQ-F-EAPOL-002 | EAPOL Frame Transmission | `eapol-supp` | EAPOL-001 | Done |
| 46 | REQ-F-EAPOL-003 | EAPOL Frame Reception | `eapol-supp` | EAPOL-001 | Done |
| 13 | REQ-F-PAE-003 | Supplicant PAE Client Interface | `eapol-supp` | PAE-001 | Done |
| 17 | REQ-F-PAE-007 | Supplicant PAE Retry Control | `eapol-supp` | PAE-001 | Done |
| 16 | REQ-F-PAE-006 | EAPOL-Logoff Transmission | `eapol-supp` | PAE-001, EAPOL-001 | Done |
| 18 | REQ-F-PAE-008 | Supplicant PAE Counters | `eapol-supp` | PAE-001 | Done |

## P2 — MKA Protocol (pae crate, depends on pae foundation)

| # | REQ-F | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 20 | REQ-F-MKA-002 | MKA Transport (MKPDU) | `pae` | MKA-001, MKA-009 | Done |
| 21 | REQ-F-MKA-003 | MKA Peer List Management | `pae` | MKA-009 | Done |
| 22 | REQ-F-MKA-004 | Key Server Election | `pae` | MKA-003 | Done |
| 24 | REQ-F-MKA-006 | SAK Reception/Installation | `pae` | MKA-001, MKA-002 | Done |
| 25 | REQ-F-MKA-007 | MKA Participant Timer Values | `pae` | MKA-002 | Done |
| 26 | REQ-F-MKA-008 | MKA Participant Creation/Deletion | `pae` | MKA-001–007 | Done |
| 47 | REQ-F-EAPOL-004 | MKPDU Format | `pae` | MKA-002 | Done |

## P3 — CP Interface (pae crate, depends on pae MKA)

| # | REQ-F | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 30 | REQ-F-CP-002 | CP State Machine Interface | `pae` | CP-001 | Done |
| 31 | REQ-F-CP-003 | Secure Channel/SA Management | `pae` | CP-001, MKA-006 | Done |
| 32 | REQ-F-CP-004 | MACsec Cipher Suite Support | `pae` | CP-001, MKA-005 | Done |

## P4 — EAP Authentication (eap-peer crate, depends on pae)

| # | REQ-F | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 38 | REQ-F-EAP-001 | EAP Peer Framework | `eap-peer` | — | Done |
| 39 | REQ-F-EAP-002 | EAP-TLS | `eap-peer` | EAP-001 | Done |
| 43 | REQ-F-EAP-006 | EAP Method Key Derivation for MKA | `eap-peer` | EAP-001 | Done |
| 42 | REQ-F-EAP-005 | EAP Method Mutual Authentication | `eap-peer` | EAP-002 | Done |
| 40 | REQ-F-EAP-003 | PEAP | `eap-peer` | EAP-001 | Done |
| 41 | REQ-F-EAP-004 | TEAP | `eap-peer` | EAP-001 | Done |

## P5 — Logon Process (logon crate, depends on pae + eapol-supp)

| # | REQ-F | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 33 | REQ-F-LOGON-001 | Logon Process State Machine | `logon` | PAE-001, CP-001 | Done |
| 34 | REQ-F-LOGON-002 | NID Selection | `logon` | LOGON-001 | Done |
| 35 | REQ-F-LOGON-003 | EAPOL-Announcement Reception | `logon` | LOGON-001, EAPOL-001 | — |
| 36 | REQ-F-LOGON-004 | NID in EAPOL-Start | `logon` | LOGON-002, PAE-005 | — |
| 37 | REQ-F-LOGON-005 | CAK Cache Management | `logon` | MKA-001, MKA-009 | — |

## Usage with /tdd-compile

```
/tdd-compile <issue-number>
```

Start with P0 items first. Recommended first issue: `#19` (REQ-F-MKA-001: MKA Key Hierarchy).
