# Skill: Architecture Governance

## Purpose

Produce architecture decisions and design guidance that stay aligned with ISO/IEC/IEEE 42010, IEEE 1016, and the Cargo workspace model.

## Use When

- Writing ADRs and ARC-C artifacts
- Evaluating component boundaries between workspace crates
- Describing quality attributes and trade-offs
- Preventing accidental drift from idiomatic Rust architecture

## Inputs

- `03-architecture/`
- `04-design/`
- Root repository constraints
- Workspace crate dependency graph

## Expected Output

- Clear architectural rationale
- Explicit constraints and trade-offs
- Crate boundaries that preserve separation of concerns
- Quality scenario coverage

## Guardrails

- Each workspace crate has a single bounded context — do not create circular dependencies
- Architecture text must reflect actual crate placement and dependency model
- No monolithic crate — use the workspace structure

## Workspace Crate Boundaries

```
crates/eapol-supp/   depends on  crates/pae/ (PAE types)
crates/eap-peer/     depends on  crates/pae/ (PAE types)
crates/pae/          standalone (core PAE/MKA/CP types and state machines)
crates/logon/        depends on  crates/pae/, crates/eapol-supp/
crates/wpa-supplicant/ depends on all crates (top-level binary)
```
