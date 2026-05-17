# Skill: Detailed Design

## Purpose

Translate architecture decisions and requirements into precise Rust component designs using DDD tactical patterns and IEEE 1016-2009 design descriptions.

## Use When

- Defining Rust trait interfaces for a bounded context
- Specifying struct layouts, enum variants, and field-level details
- Classifying domain concepts as Entity, Value Object, Aggregate, Repository, Factory, or Domain Service
- Designing crate-level error types
- Creating component design documents that trace to requirements

## Inputs

- `02-requirements/` (REQ-F issues, ubiquitous language)
- `03-architecture/` (ADRs, ARC-C issues, context map, quality scenarios)
- `04-design/` (existing component designs)
- `SKILL/instructions/root.instructions.md` (workspace layout, constraints)
- IEEE 802.1X-2020 standard (clause references only)

## Expected Output

- Component design specifications with full Rust type signatures
- DDD pattern classification tables with rationale
- Trait interface specifications with method signatures and return types
- Error type definitions per crate
- Bidirectional traceability links (REQ-F → design → ARC-C)

## DDD Tactical Patterns in Rust

| DDD Pattern | Rust Idiom | Identifying Characteristic |
|---|---|---|
| Entity | `struct` with mutable fields | Has identity that persists across state changes |
| Value Object | `struct` with `#[derive(Clone, PartialEq)]` | Defined by attributes; no identity; immutable |
| Aggregate | `struct` owning child entities | Enforces invariants; transactional consistency boundary |
| Repository | `trait` for data access | Abstracts persistence; `dyn Trait` for implementation |
| Factory | `impl From<T>` or `fn new()` | Encapsulates complex construction logic |
| Domain Service | Free functions or `impl` on service struct | Cross-aggregate logic; stateless operations |
| Domain Event | `enum Event` with variants | State machine transitions; inter-component signaling |

## Component Design Template

Each component design document should include:

1. **Component name** and crate location (`crates/<name>/`)
2. **Architectural parent** (ARC-C issue reference)
3. **Requirements satisfied** (REQ-F issue references)
4. **DDD pattern classification** (Entity, Value Object, Aggregate, etc.)
5. **Trait interfaces** (full Rust signatures)
6. **Struct/enum definitions** (field-level detail with types and visibility)
7. **Error types** (crate-level `thiserror` enum)
8. **Invariants and constraints** (what must always be true)
9. **Dependencies** (other components this one depends on)

## Guardrails

- Every design artifact must trace to at least one REQ-F issue
- Every component must reference its parent ARC-C issue
- Trait interfaces must be testable via mock implementation (trait-based dependency injection)
- Error types must cover all fallible operations; no `unwrap()` in production
- Do not reproduce copyrighted IEEE standard text; reference by clause number only
- This project is supplicant-only; do not design authenticator-side components
- Feature-gate designs for optional 802.1X-2020 features (`#[cfg(feature = "xxx")]`)
- No circular dependencies between crate designs
- All struct/enum definitions must include the IEEE 802.1X-2020 clause they implement
