# wpa_supplicant-rs

[![CI](https://github.com/johnfu-ai/wpa_supplicant-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/johnfu-ai/wpa_supplicant-rs/actions/workflows/ci.yml)

An IEEE 802.1X-2020 supplicant implementation in Rust, covering the supplicant role only per the Port-Based Network Access Control standard.

**Status:** lifecycle phases 01–08 gate-approved (requirements → architecture → design → implementation → integration → V&V → transition); Phase 09 (Operation & Maintenance) is active. 428 passing unit/integration tests + 12 wall-clock perf tests across 5 crates; per-crate coverage ≥ 80 %; clippy / fmt / `cargo audit` / `cargo deny` / aarch64 cross-build all gated in CI.

## Overview

This project provides a Rust implementation of the **supplicant-side** protocol entities defined in IEEE 802.1X-2020:

| Clause | Protocol Entity | Description |
|--------|----------------|-------------|
| 8 | Supplicant PAE | EAPOL state machine for port-based authentication |
| 9 | MKA | MACsec Key Agreement (supplicant perspective) |
| 10 | CP | Controlled Port state machine |
| 12 | Logon Process | NID selection and logon negotiation |
| — | EAP Peer | EAP methods (TLS, PEAP, TEAP) with a PEM-loaded rustls engine |
| — | EAPOL | Supplicant EAPOL frame transport |

Highlights:

- **EAP methods** — EAP-TLS / PEAP / TEAP behind a runtime factory (`eap-tls-rustls` feature): PEM cert chain + private key loaded at startup, real TLS handshake via rustls, MSK derivation per RFC 5216 §2.3, EAP Session-Id per RFC 5216 §1.4 / RFC 9190 §2.3, and RFC 5216 §3.1 TLS fragmentation/reassembly in both directions.
- **MACsec key path** — MKA with canonical timer constants, RFC 3394 AES Key Wrap for SAK unwrap, SAK/CAK/KEK/ICK zeroization.
- **Operability** — TOML config, systemd socket activation, a control-socket text protocol (`GET_STATE` / `REAUTHENTICATE` / `LOGOFF` / `SET_LOG_LEVEL` / `SHUTDOWN`), structured `tracing` logs with runtime level reload.
- **Portability** — `pae` builds `no_std` (REQ-NF-PORT-002); aarch64 cross-build gated in CI.

## Workspace Crates

```
crates/
├── eapol-supp/       Supplicant EAPOL state machine (Clause 8)
├── eap-peer/         EAP peer methods (TLS, PEAP, TEAP)
├── pae/              PAE, MKA, CP state machines (Clauses 9–10) — no_std-capable
├── logon/            Logon Process state machine (Clause 12)
└── wpa-supplicant/   Top-level supplicant binary
```

## Quick Start

```sh
cargo build --release -p wpa-supplicant
sudo install -m 755 target/release/wpa-supplicant /usr/local/bin/
```

Minimal config (TOML):

```toml
[interface]
name = "eth0"

[eap]
identity = "alice@example.com"

[eap.tls]
ca_cert = "/etc/wpa-supplicant/certs/ca.pem"
client_cert = "/etc/wpa-supplicant/certs/client.pem"
private_key = "/etc/wpa-supplicant/certs/client.key"
verify_server = true                # MUST stay true in production

[control]
socket_path = "/run/wpa-supplicant/control.sock"

[logging]
level = "info"
```

```sh
sudo wpa-supplicant --config /etc/wpa_supplicant-rs.toml
```

The full schema, systemd units, and daily-operations guide live in the [operator runbook](09-operation-maintenance/runbook.md).

## Build & Test

```bash
cargo build --workspace                                # Build all crates
cargo test  --workspace                                # Run all tests
cargo test  -p pae                                     # Run tests for a single crate
cargo test  -p wpa-supplicant --features eap-tls-rustls,eap-peap-rustls,eap-teap-rustls  # EAP factory + rustls engine
cargo test  --workspace -- --ignored                   # Wall-clock perf tests
cargo clippy --workspace --all-targets -- -D warnings  # Lint (incl. unwrap/expect discipline)
cargo fmt   --all -- --check                           # Check formatting
cargo doc   --workspace --no-deps                      # Build API docs
cargo deny  check                                      # Supply-chain gate (advisories, licenses, bans, sources)
```

CI also runs an `unsafe`-discipline gate (`cargo geiger` + `// SAFETY:` comment adjacency) and a per-crate ≥ 80 % coverage job (`cargo llvm-cov`). See [`docs/TESTING.md`](docs/TESTING.md) for the full gate inventory.

## Documentation

- [`docs/TODO.md`](docs/TODO.md) — live backlog (read first)
- [`docs/PROGRESS.md`](docs/PROGRESS.md) — phase + per-domain status roll-up
- [`docs/IMPROVEMENTS.md`](docs/IMPROVEMENTS.md) — deep-study findings register (F-NNN)
- [`docs/TESTING.md`](docs/TESTING.md) — gate inventory + coverage baselines
- [`docs/SECURITY.md`](docs/SECURITY.md) — security posture + reporting
- [`09-operation-maintenance/runbook.md`](09-operation-maintenance/runbook.md) — operator entry point
- [`02-requirements/traceability-matrix.md`](02-requirements/traceability-matrix.md) — REQ-by-REQ traceability

## Development

This project follows a test-driven, IEEE-lifecycle methodology with AI-assisted development skills. See the [`CLAUDE.md`](CLAUDE.md) companion guide and the [`SKILL/`](SKILL/) directory for the complete development skill system:

- `SKILL/instructions/` — Root and phase-specific instructions
- `SKILL/agents/` — Role-oriented agent profiles
- `SKILL/skills/` — Composable development capabilities
- `SKILL/prompts/` — Actionable workflow prompts

Phase directories (`01-stakeholder-requirements/` through `09-operation-maintenance/`) contain lifecycle documentation and traceability evidence.

### Copyright Notice

IEEE 802.1X-2020 clauses are referenced by number only. No standard text is reproduced verbatim in this codebase.

## License

This project is licensed under the [MIT License](LICENSE).
