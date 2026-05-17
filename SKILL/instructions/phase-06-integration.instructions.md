---
description: "Phase 06 guidance for integration following ISO/IEC/IEEE 12207:2017. Covers component integration, interface testing, and continuous integration for the IEEE 802.1X-2020 Rust supplicant."
applyTo: "06-integration/**"
---

# Phase 06: Integration

**Standards**: ISO/IEC/IEEE 12207:2017 (Integration Process)

## Phase Objectives

1. Integrate workspace crates incrementally
2. Verify inter-crate interfaces
3. Run continuous integration across the workspace
4. Document integration evidence

## Integration Strategy

### Bottom-Up Integration Order

1. `pae` — Core PAE types and state machines (no internal crate deps)
2. `eap-peer` — EAP methods (depends on `pae`)
3. `eapol-supp` — Supplicant EAPOL (depends on `pae`)
4. `logon` — Logon Process (depends on `pae`, `eapol-supp`)
5. `wpa-supplicant` — Binary integration (depends on all crates)

### Integration Verification

For each integration step:
1. `cargo build --workspace` compiles
2. `cargo test --workspace` passes
3. `cargo clippy --workspace -- -D warnings` passes
4. Inter-crate trait implementations work correctly

## Deliverables

- Integration test results
- Interface verification evidence
- CI pipeline configuration

## Phase Exit Criteria

- All workspace crates integrate successfully
- All integration tests pass
- CI pipeline runs green
- Integration evidence documented

## Next Phase

Phase 07: Verification & Validation (`07-verification-validation/`)
