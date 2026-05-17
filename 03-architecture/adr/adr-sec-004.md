# ADR-SEC-004: Cryptographic Key Zeroization Strategy

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #76

**Status**: Accepted
**Date**: 2026-05-17

## Context

Key material (CAK, ICK, KEK, SAK, MSK) must be zeroized when no longer needed (REQ-NF-SEC-003). Compiler must not optimize away the overwrite. No `unsafe` without justification (REQ-NF-SEC-001).

## Decision

Use `zeroize` crate with `ZeroizeOnDrop` derive for all key types. No `Clone` on key types by default. `Debug` impls show `[REDACTED]`. No manual `unsafe` volatile write — delegated to `zeroize`.

## Consequences

### Positive
- Automatic zeroization on scope exit
- No `unsafe` in our code
- `Debug` prevents accidental key logging

### Negative
- Additional dependency
- Slight performance cost from volatile writes
- `Clone` restriction requires careful SAK design

## Requirements Satisfied

- #54 (REQ-NF-SEC-003), #52 (REQ-NF-SEC-001), #19 (REQ-F-MKA-001)

## Traceability

- **Traces to**: StR-002 (#2), StR-008 (#8)
