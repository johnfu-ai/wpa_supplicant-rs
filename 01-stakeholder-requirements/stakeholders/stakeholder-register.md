# Stakeholder Register

ISO/IEC/IEEE 29148:2018 — Phase 01: Stakeholder Identification
Project: IEEE 802.1X-2020 Rust Supplicant (Production)

## Stakeholder Classes

### SH-01: Security Auditors

| Attribute | Detail |
|---|---|
| **Class** | Security Auditors |
| **Role** | Verify 802.1X-2020 supplicant conformance, audit code for vulnerabilities, certify deployment readiness |
| **Concerns** | Protocol correctness, no undefined behavior, no unsafe without justification, timing constraint compliance, cryptographic key handling safety |
| **IEEE Clause Mapping** | Clauses 8, 9, 10, 12 — all supplicant protocol behavior |
| **Priority** | P0 — Primary stakeholder |
| **Influence** | High — audit pass/fail gates release |

### SH-02: Compliance Officers

| Attribute | Detail |
|---|---|
| **Class** | Compliance Officers |
| **Role** | Ensure traceability from IEEE 802.1X-2020 clauses to implementation and tests; maintain certification evidence |
| **Concerns** | Bidirectional traceability (StR → REQ → ADR → Code → TEST), audit trail completeness, conformance test coverage per clause |
| **IEEE Clause Mapping** | All clauses — traceability coverage |
| **Priority** | P0 — Primary stakeholder |
| **Influence** | High — conformance evidence gates deployment approval |

### SH-03: Network Operators

| Attribute | Detail |
|---|---|
| **Class** | Network Operators |
| **Role** | Deploy and operate the supplicant in production networks alongside existing authenticators |
| **Concerns** | Interoperability with deployed authenticators (hostapd, commercial switches), stable D-Bus/control API, reliable reconnection, logging for troubleshooting |
| **IEEE Clause Mapping** | Clauses 8, 9 — EAPOL and MKA interoperability |
| **Priority** | P1 — Direct user |
| **Influence** | Medium — field failures block adoption |

### SH-04: System Integrators

| Attribute | Detail |
|---|---|
| **Class** | System Integrators |
| **Role** | Integrate the supplicant library crate into networking products, firmware, or orchestration frameworks |
| **Concerns** | Clean library API, trait-based dependency injection for testing, no global state, minimal dependencies, cross-compilation support |
| **IEEE Clause Mapping** | All clauses — API surface |
| **Priority** | P1 — Direct user |
| **Influence** | Medium — API ergonomics drive adoption |

### SH-05: Open-Source Maintainers

| Attribute | Detail |
|---|---|
| **Class** | Open-Source Maintainers |
| **Role** | Contribute to, review, and extend the codebase; add EAP methods, port to new platforms |
| **Concerns** | Idiomatic Rust, comprehensive documentation, test coverage, contribution guidelines, no technical debt accumulation |
| **IEEE Clause Mapping** | All clauses — code quality |
| **Priority** | P2 — Indirect stakeholder |
| **Influence** | Low-Medium — codebase health affects velocity |

## Concern-to-Clause Mapping

| Concern | Stakeholders | IEEE 802.1X-2020 Clauses | StR Reference |
|---|---|---|---|
| Supplicant PAE conformance | SH-01, SH-02, SH-03 | Clause 8 | [StR-001 #1](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/1) |
| MKA supplicant conformance | SH-01, SH-02, SH-03 | Clause 9 | [StR-002 #2](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/2) |
| Controlled Port conformance | SH-01, SH-02 | Clause 10 | [StR-003 #3](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/3) |
| EAP peer method support | SH-01, SH-03 | EAP TLS, PEAP, TEAP | [StR-004 #4](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/4) |
| Logon Process NID selection | SH-01, SH-02 | Clause 12 | [StR-005 #5](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/5) |
| Full audit trail and traceability | SH-02 | All | [StR-006 #6](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/6) |
| Production Linux deployment | SH-03, SH-04 | All | [StR-007 #7](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/7) |
| Clean-room implementation | SH-01, SH-02 | All | [StR-008 #8](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/8) |
| Library + daemon architecture | SH-04, SH-03 | All | [StR-009 #9](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/9) |
| Authenticator interoperability | SH-03 | Clauses 8, 9 | [StR-010 #10](https://github.com/johnfu-ai/wpa_supplicant-rs/issues/10) |

## Conflict Resolution

| Conflict | Stakeholders | Resolution |
|---|---|---|
| Performance vs. audit verbosity | SH-01 (full logging) vs. SH-03 (low overhead) | Structured logging with runtime level control; audit mode captures everything, production mode filters |
| API stability vs. iterative refinement | SH-04 (stable API) vs. SH-05 (evolve freely) | Semantic versioning; public API documented and versioned; internal traits may evolve |
| Clean-room purity vs. interop pragmatism | SH-02 (strict clean-room) vs. SH-03 (must work with real authenticators) | Implement from standard; validate against real authenticators in interop test suite; never copy C code |
