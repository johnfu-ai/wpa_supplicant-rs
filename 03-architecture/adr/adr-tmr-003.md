# ADR-TMR-003: Deterministic Timer Wheel for Protocol Timers

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #75

**Status**: Accepted
**Date**: 2026-05-17

## Context

Multiple real-time timer requirements: MKA Hello 2.0s, Bounded Hello 0.5s, Life Time 6.0s, heldWhile 60s, SAK Retire 3.0s, EAPOL response <100ms. Must be deterministic and `no_std`-compatible.

## Decision

Implement a `BTreeMap`-based timer wheel in `pae` crate with virtual clock for testing. No async/await in timer path. Tick-driven: state machines call `timer_wheel.tick(now)` in event loop.

Timer IDs: `MkaHello`, `MkaBoundedHello`, `MkaLife`, `HeldWhile`, `SakRetire`.

Not using `tokio::time` because `pae` must be `no_std`-compatible.

## Consequences

### Positive
- Deterministic timer firing, no unbounded operations
- Testable with virtual clock
- `no_std`-compatible

### Negative
- Custom timer code vs. proven async runtime
- Requires disciplined tick-driven event loop

## Requirements Satisfied

- #48 (REQ-NF-PERF-001), #49 (REQ-NF-PERF-002), #51 (REQ-NF-PERF-004)
- #25 (REQ-F-MKA-007), #61 (REQ-NF-PORT-002)

## Traceability

- **Traces to**: StR-001 (#1), StR-002 (#2)
