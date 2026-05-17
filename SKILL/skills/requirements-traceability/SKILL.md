# Skill: Requirements Traceability

## Purpose

Maintain end-to-end traceability from stakeholder needs through requirements, architecture, implementation evidence, and tests.

## Use When

- Creating or refining StR, REQ-F, REQ-NF, ADR, ARC-C, QA-SC, and TEST artifacts
- Checking bidirectional issue links
- Reviewing acceptance criteria and verification methods
- Auditing orphaned requirements or tests

## Inputs

- `01-stakeholder-requirements/`
- `02-requirements/`
- `03-architecture/`
- `07-verification-validation/`
- Repository issue workflow guidance

## Expected Output

- Traceable identifiers (StR-NNN, REQ-F-XXX-NNN, REQ-NF-XXX-NNN, ADR-XXX-NNN, ARC-C-XXX-NNN, TEST-XXX-NNN)
- Clear parent/child relationships
- Verifiable acceptance criteria
- Explicit coverage gaps

## Guardrails

- No implementation work without a linked requirement or issue
- Distinguish definitions from references
- Prefer stable identifiers over prose-only linkage

## Traceability Chain

```
StR Issue (#N) → REQ-F Issue (#N) → ADR Issue (#N) → Rust code (PR) → TEST Issue (#N)
```

All work begins with a GitHub Issue. All Rust functions reference the issue number and the IEEE 802.1X-2020 clause they implement.

## Rust Code Traceability

```rust
/// Supplicant PAE state machine initialization.
///
/// Implements IEEE 802.1X-2020 Clause 8.3 Supplicant PAE state machine.
///
/// Implements: #REQ-F-PAE-001
/// See: IEEE 802.1X-2020, Clause 8.3
pub fn supplicant_pae_init(ctx: &dyn SupplicantPaeContext) -> Result<SupplicantPae, PaeError> {
    // ...
}
```
