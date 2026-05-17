---
description: "Phase 02 guidance for requirements analysis and specification following ISO/IEC/IEEE 29148:2018. Covers functional/non-functional requirements, user stories, and traceability for the IEEE 802.1X-2020 Rust supplicant."
applyTo: "02-requirements/**"
---

# Phase 02: Requirements Analysis & Specification

**Standards**: ISO/IEC/IEEE 29148:2018 (System Requirements), ISO/IEC/IEEE 12207:2017
**XP Integration**: User Stories, Acceptance Tests, YAGNI Principle
**DDD Focus**: Ubiquitous Language, Domain Model, Bounded Context identification

## Phase Objectives

1. Transform stakeholder requirements into system requirements
2. Define functional and non-functional requirements
3. Create detailed use cases and user stories
4. Establish requirements traceability
5. Define testable acceptance criteria

## Supplicant-Only Requirements Scope

Requirements must map to supplicant-side protocol entities:

| Clause | Protocol Entity | REQ-F Domain Prefix |
|---|---|---|
| 8 | Supplicant PAE state machine | `REQ-F-PAE-*` |
| 9 | MKA (supplicant perspective) | `REQ-F-MKA-*` |
| 10 | CP (supplicant-controlled port) | `REQ-F-CP-*` |
| 12 | Logon Process | `REQ-F-LOGON-*` |
| — | EAP peer methods | `REQ-F-EAP-*` |
| — | EAPOL transport | `REQ-F-EAPOL-*` |

Do not create requirements for authenticator-side logic.

## DDD: Ubiquitous Language

Use IEEE 802.1X-2020 terminology exactly:

| Standard Term | Do NOT Say |
|---|---|
| Supplicant PAE | "client" |
| Authenticator PAE | "server" (reference only, not implemented) |
| Controlled Port | "authenticated port" |
| MKA | "MACsec key exchange" |
| NID | "network ID" |
| EAPOL | "EAP over LAN" (use abbreviation) |

## Deliverables

- **GitHub Issues**:
  - Functional: `REQ-F-XXX-YYY` (e.g., `REQ-F-PAE-001`)
  - Non-Functional: `REQ-NF-XXX-YYY` (e.g., `REQ-NF-PERF-001`)
- **Files**:
  - `02-requirements/functional/*.md`
  - `02-requirements/non-functional/*.md`
  - `02-requirements/user-stories/*.md`
  - `02-requirements/use-cases/*.md`

## Non-Functional Requirement Categories

- **Performance**: MKA Hello < 2000ms, SAK Retire < 3000ms, EAPOL response 95th percentile < 100ms
- **Security**: No `unsafe` without justification, secret zeroization, no `unwrap()` in production
- **Reliability**: No panics in library crates, graceful error propagation
- **Portability**: `no_std` capability for embedded targets (feature-gated)
- **Maintainability**: >80% test coverage, all public API documented

## Phase Exit Criteria

- All REQ-F issues trace to parent StR issue
- All REQ-NF issues trace to parent StR issue
- Acceptance criteria defined for every requirement
- Verification methods specified
- Ubiquitous language glossary started
- Traceability validated

## Next Phase

Phase 03: Architecture Design (`03-architecture/`)
