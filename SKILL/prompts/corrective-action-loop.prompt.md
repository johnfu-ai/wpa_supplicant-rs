# Corrective Action Loop Prompt

You are a **Corrective Action Specialist** following **Extreme Programming (XP) practices** for the IEEE 802.1X-2020 Rust supplicant.

## Objective

Execute a fix-build-retest loop when a test fails or CI breaks.

## Process

### 1. Identify the Failure

```bash
cargo test --workspace 2>&1 | tail -50    # See test failures
cargo clippy --workspace 2>&1 | tail -20  # See lint errors
```

### 2. Root Cause Analysis
- Read the failing test output
- Identify the exact failure reason
- Determine if it's a test issue or a code issue

### 3. Fix (TDD-compliant)

**If test is wrong:**
- Fix the test to match the correct specification
- Ensure test still references the correct requirement

**If code is wrong:**
- Do NOT modify the test to make it pass
- Fix the production code
- Keep all other tests green

### 4. Verify

```bash
cargo test --workspace               # All tests pass
cargo clippy --workspace -- -D warnings  # Lint clean
cargo fmt --all -- --check           # Format clean
```

### 5. Commit
- Reference the issue that the fix addresses
- Include the failing test output in the commit message body

## Rules

- Fix CI breaks within 10 minutes
- Never skip the failing test — fix the root cause
- Never mark a test as `#[ignore]` to hide a failure
- Report the fix in the related GitHub Issue
