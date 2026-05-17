# wpa_supplicant-rs

IEEE 802.1X-2020 supplicant implementation in Rust (supplicant role only).

## Scope

This project implements the **supplicant role only** per IEEE 802.1X-2020 — Port-Based Network Access Control:

- **Clause 8**: Supplicant PAE state machine
- **Clause 9**: MKA (supplicant perspective)
- **Clause 10**: CP (supplicant-controlled port)
- **Clause 12**: Logon Process (supplicant-side NID selection)
- **EAP methods**: TLS, PEAP, TEAP
- **EAPOL**: Supplicant EAPOL transport

## Workspace Structure

```
crates/eapol-supp/     Supplicant EAPOL state machine (Clause 8)
crates/eap-peer/       EAP peer methods (TLS, PEAP, TEAP)
crates/pae/            PAE, MKA, CP state machines (Clauses 9-10)
crates/logon/          Logon Process (Clause 12)
crates/wpa-supplicant/ Top-level binary crate
```

## Build & Test

```bash
cargo build --workspace                # Build all crates
cargo build -p eapol-supp              # Build single crate
cargo test --workspace                 # Run all tests
cargo test -p pae                      # Run tests for single crate
cargo test test_pae_connecting         # Run a single test
cargo clippy --workspace -- -D warnings # Lint
cargo fmt --all -- --check             # Check formatting
cargo doc --workspace --no-deps        # Build API docs
```

## Development Methodology

This project follows a 7-pillar methodology with a 9-phase IEEE/ISO/IEC lifecycle. See `SKILL/` for the complete AI development skill system:

- `SKILL/instructions/` — Root and phase-specific instructions
- `SKILL/agents/` — Role-oriented agent profiles
- `SKILL/skills/` — Focused, composable capabilities
- `SKILL/prompts/` — Actionable workflow prompts

Phase directories (`01-stakeholder-requirements/` through `09-operation-maintenance/`) contain lifecycle documentation and evidence.

## Copyright

Reference IEEE 802.1X-2020 clauses by number only. Do not reproduce standard text verbatim.
