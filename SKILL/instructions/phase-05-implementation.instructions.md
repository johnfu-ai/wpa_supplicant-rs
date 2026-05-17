---
description: "Phase 05 guidance for implementation following ISO/IEC/IEEE 12207:2017. Core XP practices: Test-Driven Development (TDD), pair programming, continuous integration, and refactoring in Rust."
applyTo: "05-implementation/**"
---

# Phase 05: Implementation (Construction)

**Standards**: ISO/IEC/IEEE 12207:2017 (Implementation Process)
**XP Focus**: TDD (Red-Green-Refactor), Empirical Validation, Continuous Integration

## PROJECT-SPECIFIC RULES

### Code Location — Rust code goes in `crates/`

This directory (`05-implementation/`) holds **only documentation evidence** for Phase 05:
- `05-implementation/docs/` — Implementation notes, decisions, evidence of TDD cycles
- `05-implementation/tests/` — Links to test results, coverage reports

**Rust implementation code lives in the workspace crates.**

### Where to Write Rust Code

| What to implement | Target crate |
|---|---|
| Supplicant PAE state machine (Clause 8) | `crates/eapol-supp/src/` |
| EAP peer methods (TLS, PEAP, TEAP) | `crates/eap-peer/src/` |
| PAE, MKA, CP state machines (Clauses 9-10) | `crates/pae/src/` |
| Logon Process state machine (Clause 12) | `crates/logon/src/` |
| Top-level supplicant binary | `crates/wpa-supplicant/src/` |

### Where to Write Test Code

| Test type | Target location |
|---|---|
| Unit tests | `#[cfg(test)] mod tests` in source files |
| Integration tests | `crates/<crate>/tests/*.rs` |
| Doc tests | `/// ``` ` blocks in doc comments |
| Workspace integration | `tests/` at workspace root |

### Build Commands (Cargo)

```bash
cargo build --workspace              # Build all crates
cargo build -p eapol-supp            # Build single crate
cargo test --workspace               # Run all tests
cargo test -p pae                    # Run tests for single crate
cargo test test_pae_connecting       # Run a single test
cargo clippy --workspace -- -D warnings  # Lint with warnings as errors
cargo fmt --all -- --check           # Check formatting
cargo doc --workspace --no-deps      # Build API docs
```

### Adding a New Feature Crate

1. Create `crates/<name>/` with `Cargo.toml` and `src/lib.rs`
2. Add to workspace `members` in root `Cargo.toml`
3. Add dependencies in dependent crates' `Cargo.toml`

### Rust Traceability Header

```rust
//! Supplicant EAPOL state machine.
//!
//! Implements IEEE 802.1X-2020 Clause 8 — Supplicant PAE.
//!
//! Implements: #REQ-F-PAE-001
//! Architecture: #ADR-PAE-001 (Trait-based state machine)
//! Verified by: #TEST-PAE-001
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.
```

### Rust Unit Test Pattern (Trait-Based Mock Injection)

```rust
/// Trait for Supplicant PAE I/O context.
pub trait SupplicantPaeContext {
    fn send_eapol(&self, dest: &[u8], frame: &[u8]) -> Result<(), EapolError>;
    fn get_port_state(&self) -> PortState;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockContext {
        sent_frames: RefCell<Vec<Vec<u8>>>,
        port_state: PortState,
    }

    impl SupplicantPaeContext for MockContext {
        fn send_eapol(&self, dest: &[u8], frame: &[u8]) -> Result<(), EapolError> {
            self.sent_frames.borrow_mut().push(frame.to_vec());
            Ok(())
        }
        fn get_port_state(&self) -> PortState {
            self.port_state
        }
    }

    /// Verifies: #TEST-PAE-001
    /// See: IEEE 802.1X-2020, Clause 8.3
    #[test]
    fn test_pae_disconnected_to_connecting() {
        let ctx = MockContext {
            sent_frames: RefCell::new(vec![]),
            port_state: PortState::Disconnected,
        };
        let mut pae = SupplicantPae::new(&ctx);
        pae.on_eapol_start();
        assert_eq!(pae.state(), PaeState::Connecting);
    }
}
```

### TDD Red-Green-Refactor Cycle

```
1. Red:    Write a failing test (cargo test fails)
2. Green:  Write minimal code to pass (cargo test passes)
3. Refactor: Improve design while keeping tests green
4. Commit: Link to requirement issue
```

### Critical Rules

- Write new code ONLY if an automated test has failed
- No `unwrap()` in production code — use `Result`, `Option`, or `expect("reason")`
- No `unsafe` without a safety comment
- Feature-gate new 802.1X-2020 code with `#[cfg(feature = "xxx")]`
- Reference IEEE 802.1X-2020 clause numbers in doc comments

## Phase Exit Criteria

- All requirement issues (REQ-F) have passing tests
- `cargo test --workspace` passes with 100% success
- `cargo clippy --workspace -- -D warnings` passes
- Coverage >80% per crate
- All code linked to requirement issues
- Implementation evidence documented in `05-implementation/`

## Next Phase

Phase 06: Integration (`06-integration/`)
