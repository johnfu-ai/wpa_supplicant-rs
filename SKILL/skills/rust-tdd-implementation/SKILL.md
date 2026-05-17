# Skill: Rust TDD Implementation

## Purpose

Drive test-first implementation work in the Cargo workspace using idiomatic Rust patterns.

## Use When

- Planning Red-Green-Refactor loops
- Locating target Rust files in workspace crates
- Deciding where tests belong (unit vs integration)
- Reviewing Cargo-based build expectations

## Inputs

- `SKILL/instructions/root.instructions.md` (workspace layout)
- `05-implementation/`
- `06-integration/`
- `07-verification-validation/`

## Expected Output

- Failing tests first
- Minimal Rust code changes in workspace crates
- Evidence links recorded in phase documentation
- Narrow validation commands

## TDD Workflow

```
1. Red:    Write a failing test (cargo test fails)
2. Green:  Write minimal code to make it pass (cargo test passes)
3. Refactor: Improve design while keeping tests green
```

## Build & Test Commands

```bash
cargo build --workspace              # Build all crates
cargo build -p eapol-supp            # Build single crate
cargo test --workspace               # Run all tests
cargo test -p pae                    # Run tests for single crate
cargo test test_pae_connecting       # Run a single test
cargo clippy --workspace             # Lint all crates
cargo fmt --all -- --check           # Check formatting
```

## Where to Write Rust Code

| What to implement | Target crate |
|---|---|
| Supplicant PAE state machine (Clause 8) | `crates/eapol-supp/src/` |
| EAP peer methods (TLS, PEAP, TEAP) | `crates/eap-peer/src/` |
| PAE, MKA, CP state machines (Clauses 9-10) | `crates/pae/src/` |
| Logon Process state machine (Clause 12) | `crates/logon/src/` |
| Top-level supplicant binary | `crates/wpa-supplicant/src/` |

## Where to Write Tests

| Test type | Target location |
|---|---|
| Unit tests | `crates/<crate>/src/**/*.rs` in `#[cfg(test)] mod tests` |
| Integration tests | `crates/<crate>/tests/*.rs` |
| Documentation tests | Inline in `///` doc comments |
| Workspace-level integration | `tests/` at workspace root |

## Rust Test Pattern (Trait-Based Mock Injection)

```rust
/// Trait for Supplicant PAE context (injectable for testing).
pub trait SupplicantPaeContext {
    fn send_eapol(&self, dest: &[u8], frame: &[u8]) -> Result<(), EapolError>;
    fn get_port_state(&self) -> PortState;
}

// --- Production implementation ---
pub struct LiveSupplicantContext { /* ... */ }

impl SupplicantPaeContext for LiveSupplicantContext {
    fn send_eapol(&self, dest: &[u8], frame: &[u8]) -> Result<(), EapolError> {
        // real implementation
    }
    fn get_port_state(&self) -> PortState {
        // real implementation
    }
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    struct MockContext {
        sent_frames: Vec<Vec<u8>>,
        port_state: PortState,
    }

    impl SupplicantPaeContext for MockContext {
        fn send_eapol(&self, dest: &[u8], frame: &[u8]) -> Result<(), EapolError> {
            // mock: record frame, return Ok
            Ok(())
        }
        fn get_port_state(&self) -> PortState {
            self.port_state
        }
    }

    #[test]
    fn test_pae_disconnected_to_connecting() {
        let ctx = MockContext { sent_frames: vec![], port_state: PortState::Disconnected };
        let mut pae = SupplicantPae::new(&ctx);
        pae.on_eapol_start();
        assert_eq!(pae.state(), PaeState::Connecting);
    }
}
```

## Rust Traceability Header

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

## Guardrails

- Do not add Rust implementation code to the `01-09` phase directories
- Use `cargo test` for all test execution — no custom test harness
- Prefer trait-based mock injection over mocking libraries
- No `unwrap()` in production code — use `Result`, `Option`, or `expect("reason")`
- Feature-gate new 802.1X-2020 code with `#[cfg(feature = "xxx")]` and Cargo features
