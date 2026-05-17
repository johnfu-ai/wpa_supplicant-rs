# wpa_supplicant-rs

An IEEE 802.1X-2020 supplicant implementation in Rust, covering the supplicant role only per the Port-Based Network Access Control standard.

## Overview

This project provides a Rust implementation of the **supplicant-side** protocol entities defined in IEEE 802.1X-2020:

| Clause | Protocol Entity | Description |
|--------|----------------|-------------|
| 8 | Supplicant PAE | EAPOL state machine for port-based authentication |
| 9 | MKA | MACsec Key Agreement (supplicant perspective) |
| 10 | CP | Controlled Port state machine |
| 12 | Logon Process | NID selection and logon negotiation |
| — | EAP Peer | Extensible Authentication Protocol methods (TLS, PEAP, TEAP) |
| — | EAPOL | Supplicant EAPOL frame transport |

## Workspace Crates

```
crates/
├── eapol-supp/       Supplicant EAPOL state machine (Clause 8)
├── eap-peer/         EAP peer methods (TLS, PEAP, TEAP)
├── pae/              PAE, MKA, CP state machines (Clauses 9-10)
├── logon/            Logon Process state machine (Clause 12)
└── wpa-supplicant/   Top-level supplicant binary
```

## Build & Test

```bash
cargo build --workspace                # Build all crates
cargo build -p eapol-supp              # Build a single crate
cargo test --workspace                 # Run all tests
cargo test -p pae                      # Run tests for a single crate
cargo test test_pae_connecting         # Run a single test
cargo clippy --workspace -- -D warnings # Lint
cargo fmt --all -- --check             # Check formatting
cargo doc --workspace --no-deps        # Build API docs
```

## Development

This project follows a test-driven, IEEE-lifecycle methodology with AI-assisted development skills. See the [`SKILL/`](SKILL/) directory for the complete development skill system:

- `SKILL/instructions/` — Root and phase-specific instructions
- `SKILL/agents/` — Role-oriented agent profiles
- `SKILL/skills/` — Composable development capabilities
- `SKILL/prompts/` — Actionable workflow prompts

Phase directories (`01-stakeholder-requirements/` through `09-operation-maintenance/`) contain lifecycle documentation and traceability evidence.

### Copyright Notice

IEEE 802.1X-2020 clauses are referenced by number only. No standard text is reproduced verbatim in this codebase.

## License

This project is licensed under the [MIT License](LICENSE).
