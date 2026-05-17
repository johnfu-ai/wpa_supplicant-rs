# QA-SC-PERF-001: MKA Hello Timing Under Load

Per ATAM — Phase 03
Issue: #86

## Quality Attribute

Performance

## Scenario

| Element | Value |
|---|---|
| Stimulus | MKA Hello Time timer expires while processing 10 concurrent peer MKPDUs and EAP-TLS reauthentication |
| Source | Internal timer wheel |
| Environment | Normal operation, Linux x86_64 |
| Artifact | MKA participant timer path in `pae` crate |
| Response | MKPDU transmitted within MKA Hello Time |
| Response Measure | ≤2.0s at 95th percentile; ≤0.5s for bounded hello |

## Supporting ADRs

- ADR-TMR-003 (#75): Deterministic timer wheel
- ADR-SM-002 (#74): Bounded step() execution
- ADR-EVT-007 (#79): Event-driven dispatch

## Requirements

- #48 (REQ-NF-PERF-001), #49 (REQ-NF-PERF-002)
