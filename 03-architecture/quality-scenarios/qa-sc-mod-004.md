# QA-SC-MOD-004: Add EAP Method Without Modifying Core

Per ATAM — Phase 03
Issue: #89

## Quality Attribute

Modifiability

## Scenario

| Element | Value |
|---|---|
| Stimulus | New EAP method (e.g., EAP-FAST) needs to be added |
| Source | Developer |
| Environment | Development |
| Artifact | `eap-peer` crate |
| Response | New module + feature flag + trait impl; zero changes to other crates |
| Response Measure | Zero existing source files modified; compiles and passes tests |

## Supporting ADRs

- ADR-FF-006 (#78): Feature flags per EAP method
- ADR-SM-002 (#74): Trait-based design
- ADR-WS-001 (#73): Isolated bounded context

## Requirements

- #38 (REQ-F-EAP-001), #61 (REQ-NF-PORT-002)
