# ADR-ERR-005: Crate-Local Error Types with thiserror

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #77

**Status**: Accepted
**Date**: 2026-05-17

## Context

Each crate performs fallible operations. Library crates must not panic (REQ-NF-REL-001). Errors must propagate via `Result` (REQ-NF-REL-002). No `unwrap()` in production (REQ-NF-SEC-002).

## Decision

Each crate defines its own `thiserror`-derived error enum. Cross-crate propagation uses `#[from]` impls. No `anyhow` in library crates (only in `wpa-supplicant` binary). `expect()` with reason string permitted for programmer invariants.

## Consequences

### Positive
- Typed errors enable pattern matching
- `?` operator works across crate boundaries
- No panics in library crates

### Negative
- `From` chains can obscure original error source
- New error variants are semver-breaking

## Requirements Satisfied

- #57 (REQ-NF-REL-001), #58 (REQ-NF-REL-002), #52 (REQ-NF-SEC-002)

## Traceability

- **Traces to**: StR-008 (#8), StR-009 (#9)
