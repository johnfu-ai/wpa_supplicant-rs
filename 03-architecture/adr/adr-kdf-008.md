# ADR-KDF-008: KDF and Cipher Suite Abstraction

Per ISO/IEC/IEEE 42010:2011 — Phase 03
Issue: #80

**Status**: Accepted
**Date**: 2026-05-17

## Context

MKA key derivation uses AES-CMAC KDF (Cl.6.2). SAK distribution uses AES Key Wrap. CP supports multiple cipher suites. Crypto must be testable with known test vectors. No `unsafe` in our crypto code.

## Decision

Trait-based crypto abstractions in `pae` crate: `Kdf`, `KeyWrap`, `Rng`. Concrete implementations via feature flags. Default: `aes` + `cmac` (pure Rust). Test: mock KDF with known vectors. `CipherSuite` enum: `GcmAes128`, `GcmAes256`, `GcmAesXpn256`, `Null`.

## Consequences

### Positive
- Crypto testable with mock implementations
- Cipher suite support extensible
- `no_std` compatible via trait injection
- No `unsafe` in our code

### Negative
- Trait indirection adds minimal overhead
- Multiple crypto backends increase CI matrix

## Requirements Satisfied

- #19 (REQ-F-MKA-001), #28 (REQ-F-MKA-010), #29 (REQ-F-CP-001), #32 (REQ-F-CP-004)
- #52 (REQ-NF-SEC-001)

## Traceability

- **Traces to**: StR-002 (#2), StR-003 (#3), StR-008 (#8)
