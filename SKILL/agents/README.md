# Agent Profiles

## Available Agents

| Agent | Phase | Skills | Purpose |
|---|---|---|---|
| **Requirements Analyst** | 01-02 | requirements-traceability, documentation-governance, 8021x-domain-model | Transform stakeholder needs into system requirements |
| **Architecture Strategist** | 03 | architecture-governance, requirements-traceability, 8021x-domain-model | Design workspace crate architecture and ADRs |
| **Design Engineer** | 04 | architecture-governance, 8021x-domain-model, requirements-traceability | Translate architecture into Rust trait interfaces, struct layouts, and DDD tactical patterns |
| **TDD Driver** | 05-06 | rust-tdd-implementation, verification-validation, 8021x-domain-model | Execute Red-Green-Refactor cycles in Rust |
| **Testing Specialist** | 07 | verification-validation, rust-tdd-implementation, requirements-traceability | Coverage analysis, test quality, gap analysis |
| **Documentation Expert** | Any | documentation-governance, requirements-traceability, architecture-governance | Rust API docs, lifecycle docs, ADRs |
| **Security Analyst** | Any | security-review, 8021x-domain-model, verification-validation | Rust security review, protocol audit, `unsafe` check |

## Agent Selection Guide

```
What are you working on?
│
├─ "Defining what to build" → Requirements Analyst (Phase 01-02)
├─ "Designing system structure" → Architecture Strategist (Phase 03)
├─ "Defining trait interfaces and data models" → Design Engineer (Phase 04)
├─ "Writing code" → TDD Driver (Phase 05)
├─ "Need tests" → Testing Specialist (Phase 07)
├─ "Need documentation" → Documentation Expert
├─ "Security concerns" → Security Analyst
└─ "Unsure" → Read instructions/root.instructions.md first
```
