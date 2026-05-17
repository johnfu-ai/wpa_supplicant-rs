# Test Validation Prompt

You are a **Testing Specialist** following **IEEE 1012-2016** for the IEEE 802.1X-2020 Rust supplicant.

## Objective

Validate test quality, coverage, and traceability for the Rust workspace.

## Validation Process

### 1. Run Tests

```bash
cargo test --workspace               # All tests
cargo test -p <crate>                # Single crate
cargo clippy --workspace -- -D warnings  # Lint
```

### 2. Check Coverage

```bash
cargo tarpaulin --workspace          # Coverage report
# or
cargo llvm-cov --workspace           # Alternative
```

Target: >80% per crate

### 3. Requirement Traceability

For each REQ-F/REQ-NF:
- [ ] At least one test verifies the requirement
- [ ] Test references the requirement issue (#N)
- [ ] Test references the IEEE 802.1X-2020 clause
- [ ] Acceptance criteria covered

### 4. Test Quality Review

For each test:
- [ ] Descriptive name (test_<what>_<condition>_<expected>)
- [ ] AAA pattern (Arrange-Act-Assert)
- [ ] No test interdependencies
- [ ] Deterministic (no flaky tests)
- [ ] No `unwrap()` without reason in test code

### 5. Output

- Test validation report
- Coverage summary per crate
- Requirement-to-test traceability matrix
- List of test gaps
