# ADR-FF-006: Feature Flag Strategy for 802.1X-2020 Extensions

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #78

**Status**: Accepted
**Date**: 2026-05-17

## Context

Optional protocol features need conditional compilation: MACsec/MKA, Logon Process, EAP-PEAP/TEAP, `no_std` capability.

## Decision

Feature flags per crate:

| Crate | Feature | Default | Enables |
|---|---|---|---|
| `pae` | `macsec` | yes | MKA key agreement, CP state machine |
| `pae` | `std` | yes | `std` library; disable for `no_std` |
| `eap-peer` | `eap-tls` | yes | EAP-TLS method |
| `eap-peer` | `eap-peap` | no | EAP-PEAP method |
| `eap-peer` | `eap-teap` | no | EAP-TEAP method |
| `eapol-supp` | `std` | yes | `std` library |
| `logon` | `std` | yes | `std` library |

Rules: `std` feature disables `std`; features are additive; EAP methods individually gated.

## Consequences

### Positive
- Embedded builds with `--no-default-features`
- Reduced attack surface
- `no_std` for `pae` core

### Negative
- Feature combinations must be CI-tested
- Feature-gated code harder to reason about

## Requirements Satisfied

- #61 (REQ-NF-PORT-002), #40 (REQ-F-EAP-003), #41 (REQ-F-EAP-004)

## Traceability

- **Traces to**: StR-009 (#9), StR-004 (#4)
