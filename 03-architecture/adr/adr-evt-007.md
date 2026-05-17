# ADR-EVT-007: Event-Driven Inter-Crate Communication

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #79

**Status**: Accepted
**Date**: 2026-05-17

## Context

State machines in different crates must communicate. Direct calls create tight coupling. The Logon Process orchestrates PAE and CP. The event loop must coordinate all state machines.

## Decision

Typed events dispatched through a central event loop in `wpa-supplicant`. State machines return `Vec<PaeEvent>` from `step()`. Library crates are event producers/consumers — they don't own the event loop. Events are owned values (no lifetimes).

Event flow: EAPOL frame → decode → emit PaeEvent → dispatch to handler → state machine step → may emit new events → loop.

## Consequences

### Positive
- Loose coupling between state machines
- Testable in isolation
- Event log provides audit trail
- Natural fit for Logon Process orchestration

### Negative
- Event dispatch centralized in binary crate
- Event enum must grow as features are added

## Requirements Satisfied

- #33 (REQ-F-LOGON-001), #15 (REQ-F-PAE-005), #11 (REQ-F-PAE-001), #29 (REQ-F-CP-001)
- #66 (REQ-NF-TRC-001)

## Traceability

- **Traces to**: StR-001 (#1), StR-002 (#2), StR-003 (#3), StR-005 (#5), StR-006 (#6)
