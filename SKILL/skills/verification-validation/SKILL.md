# Skill: Verification and Validation

## Purpose

Turn requirements and design intent into executable verification assets and clear validation evidence.

## Use When

- Designing unit, integration, acceptance, or compliance tests
- Checking requirement coverage and test gaps
- Organizing Phase 06 and Phase 07 evidence
- Reviewing whether claims are empirically supported

## Inputs

- `06-integration/`
- `07-verification-validation/`
- Requirement and architecture identifiers
- Build and test commands from Cargo workspace

## Expected Output

- Test cases linked to requirements
- Coverage and gap analysis
- Measured evidence instead of speculative claims
- Repeatable validation steps

## Guardrails

- Prefer executable proof over narrative assurance
- Call out missing coverage explicitly
- Keep requirement references precise and machine-searchable

## Rust Verification Commands

```bash
cargo test --workspace               # Run all tests
cargo test -p <crate>                # Run tests for one crate
cargo test <test_name>               # Run a single test
cargo test -- --nocapture            # Show test output
cargo tarpaulin --workspace          # Coverage report (if installed)
cargo llvm-cov --workspace           # Alternative coverage (if installed)
cargo clippy --workspace -- -D warnings  # Lint with warnings as errors
```

## Coverage Targets

- Unit test coverage: >80% per crate
- Integration test coverage: all REQ-F requirements verified
- Documentation test coverage: all public API items have `///` doc examples
