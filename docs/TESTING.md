# Testing

Testing policy for the `wpa_supplicant-rs` workspace. Covers the coverage
gate (REQ-NF-MNT-001 / #139) and points at the other CI gates.

## Coverage gate

CI runs a `Coverage (llvm-cov >= 80% per crate)` job on every push to
`main` and on every PR (`.github/workflows/ci.yml`). It:

1. Collects line coverage over the **default-feature** test suite with
   `cargo llvm-cov --workspace --lcov --output-path lcov.info`.
2. Runs `scripts/check_coverage.py lcov.info`, which aggregates line
   coverage **per crate** and fails if any crate is below its floor.
3. Uploads an HTML report (`coverage/html/index.html`) + `lcov.info` as a
   `coverage-report` artifact for reviewer diffing.

Per-crate line-coverage floors (default 80% per REQ-NF-MNT-001) are
configured in `scripts/check_coverage.py:THRESHOLDS`.

### Baseline (refreshed 2026-08-14, default features, 428 tests)

| Crate | Lines | Covered | % | Floor |
|---|---|---|---|---|
| `pae` | 3853 | 3395 | 88.11% | 80% |
| `eapol-supp` | 1315 | 1158 | 88.06% | 80% |
| `eap-peer` | 1110 | 961 | 86.58% | 80% |
| `logon` | 655 | 618 | 94.35% | 80% |
| `wpa-supplicant` | 1460 | 1234 | 84.52% | 80% |

`wpa-supplicant` is the tightest (dragged by `main.rs` — the binary entry
point is exercised as a subprocess by the `main_smoke` integration test,
so its lines are not instrumented). All crates clear the 80% floor with
≥4.5% headroom.

### Scope and exceptions

- The gate measures **default-feature** code. Feature-gated code
  (`crates/wpa-supplicant/src/raw_socket.rs` under `raw-socket`,
  MACsec AES Key Wrap under `pae`'s `macsec`) is covered by
  feature-specific tests and is out of scope for this gate.
- The 12 `#[ignore]`-gated wall-clock perf tests are not run by the
  coverage job (they are not run by `cargo test` either); coverage
  reflects the 428 non-ignored tests.
- A temporary lower floor for a crate under active build-out (e.g. one
  waiting on a follow-up such as F-INT-1) is an explicit, reviewable
  entry in `THRESHOLDS` — not a silent slackening. (The #133
  `eap-tls-rustls` feature code is covered by dedicated feature-gated
  tests and is exercised by the CI `Test (EAP method-factory
  features)` step; it is out of scope for the default-feature gate.)

## Other CI gates

| Gate | Job | REQ / issue |
|---|---|---|
| Format | `Test (x86_64)` → `cargo fmt --all -- --check` | — |
| Clippy (incl. `unwrap_used` / `expect_used`) | `Test (x86_64)` → `cargo clippy --workspace --all-features --all-targets -- -D warnings` | REQ-NF-SEC-002 / #144 |
| Tests | `Test (x86_64)` → `cargo test --workspace` | — |
| Cross-build aarch64 | `Cross-build (aarch64)` | REQ-NF-PORT-001 |
| `no_std` build | `No-std (pae)` → `cargo build -p pae --no-default-features` (+ `--features macsec`) | REQ-NF-PORT-002 / #142 |
| Fuzz decoders | `Fuzz decoders` → `cargo fuzz run` 1 min/target on `EapolFrame::decode`, `EapPacket::decode`, `Mkpdu::decode` (nightly + libFuzzer) | REQ-NF-REL-001/002 / #143 |
| Supply chain | `Supply-chain` → `cargo audit` + `cargo deny` | REQ-NF-SEC-003/005 / #140 |
| `unsafe` discipline | `Unsafe discipline` → `scripts/check_unsafe_safety.py` + `cargo geiger` | REQ-NF-SEC-001 / #141 |
| Coverage | `Coverage` → `scripts/check_coverage.py` | REQ-NF-MNT-001 / #139 |

## Wall-clock perf tests

The 12 `#[ignore]`-gated perf tests (REQ-NF-PERF-001/002/003/004) run
with `cargo test --workspace -- --ignored` and are confirmed green on a
representative host; they are not part of routine CI.
