# Business Case

ISO/IEC/IEEE 29148:2018 — Phase 01: Business Context
Project: IEEE 802.1X-2020 Rust Supplicant (Production)

## Problem Statement

No production-grade IEEE 802.1X-2020 supplicant implementation exists in Rust. The reference C implementation (wpa_supplicant) supports 802.1X-2010 but lacks complete 802.1X-2020 supplicant conformance — specifically MKA Hello protocol, Controlled Port state machine, and Logon Process NID selection.

Security and compliance stakeholders require:

1. A supplicant whose protocol behavior is demonstrably traceable to IEEE 802.1X-2020 clauses
2. Memory-safe implementation eliminating classes of vulnerabilities (buffer overflows, use-after-free) present in C implementations
3. A full audit trail from standard clause to test case, suitable for third-party conformance review

## Scope

### In Scope (MVP)

| Protocol Area | IEEE 802.1X-2020 Clause | Rust Crate |
|---|---|---|
| Supplicant PAE state machine | Clause 8 | `eapol-supp` |
| MKA supplicant behavior | Clause 9 | `pae` |
| Controlled Port (supplicant) | Clause 10 | `pae` |
| Logon Process (NID selection) | Clause 12 | `logon` |
| EAP peer methods (TLS, PEAP, TEAP) | EAP RFCs | `eap-peer` |
| EAPOL supplicant transport | Clause 8 | `eapol-supp` |
| Library crate + daemon binary | — | `wpa-supplicant` |

### Out of Scope

- Authenticator PAE state machine (Clause 8 authenticator role)
- AP-side or switch-side logic
- MKA Key Server role (authenticator side)
- EAP server methods
- Windows, macOS, or bare-metal platforms (MVP)

## Constraints

| Constraint | Value | Rationale |
|---|---|---|
| Language | Rust (latest stable edition) | Memory safety, zero-cost abstractions, trait-based DI |
| Build system | Cargo workspace | Crate isolation, dependency management |
| Scope | Supplicant role only | Project boundary; no authenticator logic |
| Implementation source | Clean-room from IEEE 802.1X-2020 standard only | Copyright compliance, audit purity |
| Copyright | Reference standard by clause number only; no reproduction of text, tables, or figures | IEEE copyright compliance |
| Target platform | Linux (x86_64, ARM64) | Production deployment target |
| Architecture | Library crate + optional daemon binary | Integration flexibility |
| Conformance level | Full audit trail (self-certified + interop + third-party audit ready) | Security/compliance stakeholder requirement |

## Success Criteria

### Functional

- All REQ-F requirements verified by automated tests
- Each IEEE 802.1X-2020 clause (8, 9, 10, 12) has corresponding test coverage
- EAP peer methods (TLS, PEAP, TEAP) authenticate successfully against reference authenticators

### Non-Functional

| Criterion | Threshold | Measurement |
|---|---|---|
| MKA Hello interval | ≤ 2000 ms | Timer measurement in test |
| MKA Life timeout | ≤ 6000 ms | Timer measurement in test |
| SAK Retire time | ≤ 3000 ms | Timer measurement in test |
| Test coverage | ≥ 80% | `cargo llvm-cov` |
| Unsafe code | Zero without safety justification | `cargo geiger` audit |
| Unwrap in production | Zero | `grep -r "\.unwrap()"` CI check |
| Clippy warnings | Zero | `cargo clippy -- -D warnings` |
| Format compliance | Pass | `cargo fmt --all -- --check` |

### Conformance

- Bidirectional traceability: every StR → REQ → ADR → Code → TEST linked via GitHub Issues
- Interop test suite validates against at least one reference authenticator
- Audit package produces clause-by-clause conformance evidence

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| IEEE 802.1X-2020 ambiguity in clause interpretation | Incorrect protocol behavior | Spike solutions validated against reference authenticator; document interpretation decisions as ADRs |
| MKA timing constraints on non-realtime Linux | Missed Hello/Life deadlines | Time-frame architecture with bounded execution; empirical timing validation |
| EAP method complexity (TEAP) | Implementation delay | Phase EAP methods: TLS first, then PEAP, then TEAP |
| Clean-room purity vs. interop needs | Subtle protocol divergences from real-world authenticators | Interop test suite catches divergences early; document any clarifications as ADRs |
| Rust async vs. synchronous state machine design | Architecture lock-in | Spike both approaches; decide via ADR before Phase 03 |

## Next Steps

Phase 02: Requirements Analysis & Specification — transform StR issues into system requirements (REQ-F, REQ-NF) with acceptance criteria and verification methods.
