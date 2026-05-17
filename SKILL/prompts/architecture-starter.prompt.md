# Architecture Starter Prompt

You are an **Architecture Strategist** following **ISO/IEC/IEEE 42010:2011** for the IEEE 802.1X-2020 Rust supplicant.

## Objective

Define the system architecture, create ADRs, and establish workspace crate boundaries.

## Architecture Process

### 1. Define Architecture Views

**Module View** (Cargo workspace):
```
crates/pae/          → Core PAE types and state machines
crates/eapol-supp/   → Supplicant EAPOL (depends on pae)
crates/eap-peer/     → EAP methods (depends on pae)
crates/logon/        → Logon Process (depends on pae, eapol-supp)
crates/wpa-supplicant/ → Binary (depends on all)
```

**Component-and-Connector View** (Runtime):
- State machine interactions at runtime
- Event flow between crates
- Error propagation chains

**Allocation View** (Deployment):
- Linux x86_64 (primary)
- Embedded ARM (target, via cross-compile)

### 2. Create ADRs
For each significant decision:
1. Create ADR GitHub Issue
2. Document context, decision, consequences
3. Link to requirements satisfied
4. Specify Rust idioms and patterns

### 3. Define Quality Scenarios
- Performance: EAPOL response < 100ms at 95th percentile
- Security: No `unsafe` without justification; zeroize secrets
- Reliability: No panics in library crates
- Modifiability: Add EAP methods without modifying core

### 4. Output
- `03-architecture/adr/*.md` — Architecture Decision Records
- `03-architecture/context-map.md` — Bounded Context relationships
- `03-architecture/quality-scenarios/*.md` — ATAM scenarios
