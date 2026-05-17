# Skills

## Design Goal

Agents are broad working roles. Skills are narrower capabilities that can be composed by different agents.

## Skill Map

| Skill | Focus | Primary Agents |
|---|---|---|
| `8021x-domain-model` | IEEE 802.1X-2020 clauses, YANG, crate-map, copyright-safe references | All agents |
| `requirements-traceability` | StR/REQ/ADR/ARC-C/TEST links, issue-driven development | RequirementsAnalyst |
| `architecture-governance` | ADRs, quality scenarios, workspace crate boundaries | ArchitectureStrategist |
| `rust-tdd-implementation` | Test-first Rust changes in Cargo workspace | TDDDriver |
| `verification-validation` | Test planning, coverage, requirement verification | TestingSpecialist |
| `security-review` | Protocol security review, Rust `unsafe` audit, secret hygiene | SecurityAnalyst |
| `documentation-governance` | Standards-aligned docs, Rust API docs, repository consistency | DocumentationExpert |

## Agent-to-Skill Mapping

- `RequirementsAnalyst`: requirements-traceability, documentation-governance, 8021x-domain-model
- `ArchitectureStrategist`: architecture-governance, requirements-traceability, 8021x-domain-model
- `TDDDriver`: rust-tdd-implementation, verification-validation, 8021x-domain-model
- `TestingSpecialist`: verification-validation, rust-tdd-implementation, requirements-traceability
- `DocumentationExpert`: documentation-governance, requirements-traceability, architecture-governance
- `SecurityAnalyst`: security-review, 8021x-domain-model, verification-validation
