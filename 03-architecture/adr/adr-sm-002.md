# ADR-SM-002: Trait-Based State Machine Design

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #74

**Status**: Accepted
**Date**: 2026-05-17

## Context

All five protocol areas are state-machine driven. State machines must be testable in isolation without hardware (REQ-NF-REL-001, REQ-NF-MNT-001) and must interact — the Logon Process drives PAE and CP transitions.

## Decision

Implement each state machine as a struct with an explicit state enum, using trait-based dependency injection for external interactions:

```rust
pub trait SupplicantPaeContext {
    fn tx_eapol(&mut self, frame: &EapolFrame) -> Result<(), EapolError>;
    fn held_while(&self) -> Duration;
    fn eap_start(&mut self);
}

pub struct SupplicantPae<C: SupplicantPaeContext> {
    state: PaeState,
    retry_count: u32,
    retry_max: u32,
    ctx: C,
}
```

Pattern: state enum + `step(&mut self, event) -> Result<Vec<PaeEvent>, Error>` + context trait for I/O.

## Consequences

### Positive
- Fully testable without hardware via mock context injection
- Type-safe state transitions
- No global mutable state
- All transitions return `Result` (no panics)

### Negative
- Slightly more boilerplate than simpler patterns
- Context traits must evolve with state machine interfaces

## Requirements Satisfied

- #11 (REQ-F-PAE-001), #19 (REQ-F-MKA-001), #29 (REQ-F-CP-001), #33 (REQ-F-LOGON-001)
- #57 (REQ-NF-REL-001), #62 (REQ-NF-MNT-001), #67 (REQ-NF-TRC-002)

## Traceability

- **Traces to**: StR-001 (#1), StR-002 (#2), StR-003 (#3), StR-005 (#5), StR-006 (#6)
