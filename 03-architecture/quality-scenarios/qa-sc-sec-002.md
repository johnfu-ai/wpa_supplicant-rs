# QA-SC-SEC-002: Secret Key Exposure Prevention

Per ATAM — Phase 03
Issue: #87

## Quality Attribute

Security

## Scenario

| Element | Value |
|---|---|
| Stimulus | CAK/ICK/KEK/SAK goes out of scope after MKA session termination or key rollover |
| Source | MKA participant deletion, SAK retirement |
| Environment | Normal operation |
| Artifact | Key types in `pae` crate |
| Response | Key material zeroized; never in logs/debug |
| Response Measure | Zero bytes after drop; `[REDACTED]` in Debug; zero `unsafe` in our code |

## Supporting ADRs

- ADR-SEC-004 (#76): ZeroizeOnDrop, `[REDACTED]` Debug
- ADR-KDF-008 (#80): Trait-based crypto
- ADR-ERR-005 (#77): Errors never include key material

## Requirements

- #54 (REQ-NF-SEC-003), #52 (REQ-NF-SEC-001), #56 (REQ-NF-SEC-005)
