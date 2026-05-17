# Non-Functional Requirements

Per ISO/IEC/IEEE 29148:2018 — Phase 02
Traceability: StR-006 (#6), StR-007 (#7), StR-008 (#8), StR-009 (#9)

## Performance

### REQ-NF-PERF-001: MKA Hello Interval

The supplicant shall transmit MKPDUs within MKA Hello Time (2.0s) for active participants, and MKA Bounded Hello Time (0.5s) when bounded receive delay is required.

**Traces to**: StR-002 (#2)
**Verification**: Timer architecture validated by code review (deterministic timer wheel, no unbounded operations in timer path). Empirical timing validated on target hardware (not under CI scheduler load). 95th percentile ≤ 2.0s / 0.5s on dedicated test runner.

### REQ-NF-PERF-002: MKA Life Time

Peer list entries shall be removed within MKA Life Time (6.0s) + MKA Hello Time of last confirmed liveness.

**Traces to**: StR-002 (#2)
**Verification**: Timer measurement in unit test

### REQ-NF-PERF-003: EAPOL Response Latency

The supplicant shall respond to received EAPOL-EAP frames within 100ms at the 95th percentile.

**Traces to**: StR-001 (#1)
**Verification**: Latency measurement in integration test

### REQ-NF-PERF-004: State Machine Transition Latency

PACP state machine transitions shall complete within 10ms of trigger condition becoming true.

**Traces to**: StR-001 (#1)
**Verification**: State transition timing in unit test

## Security

### REQ-NF-SEC-001: No Unsafe Without Justification

The supplicant shall contain zero `unsafe` blocks in production code without a safety comment documenting the invariant maintained and the reason `unsafe` is required.

**Traces to**: StR-008 (#8)
**Verification**: `cargo geiger` audit; CI gate fails on undocumented `unsafe`

### REQ-NF-SEC-002: No Unwrap in Production

The supplicant shall contain zero `.unwrap()` calls in library crate production code. `expect()` is permitted with a reason string.

**Traces to**: StR-008 (#8)
**Verification**: CI grep check for `.unwrap()`

### REQ-NF-SEC-003: Secret Zeroization

Cryptographic key material (CAK, ICK, KEK, SAK, MSK) shall be zeroized when no longer needed, using a mechanism that prevents compiler optimization from removing the overwrite.

**Traces to**: StR-008 (#8)
**Verification**: Code review: zeroization of key material on scope exit and explicit clear

### REQ-NF-SEC-004: Clean-Room Compliance

No code in the repository shall be a translation, port, or adaptation of wpa_supplicant C source code. All protocol logic shall be derived from understanding of the IEEE 802.1X-2020 standard.

**Traces to**: StR-008 (#8)
**Verification**: Code review audit; no C-to-Rust structural correspondence

### REQ-NF-SEC-005: No Copyright Reproduction

No copyrighted text, tables, or figures from IEEE 802.1X-2020 shall appear in source code or documentation. Standard references use clause numbers only.

**Traces to**: StR-008 (#8)
**Verification**: CI grep check for verbatim standard text patterns

## Reliability

### REQ-NF-REL-001: No Panics in Library Crates

Library crates shall not panic under any input. All fallible operations return `Result<T, E>`.

**Traces to**: StR-009 (#9)
**Verification**: Code review + `RUST_BACKTRACE=1` fuzz testing

### REQ-NF-REL-002: Graceful Error Propagation

State machine errors shall be propagated via `Result` types and logged at appropriate severity, never causing silent state corruption.

**Traces to**: StR-009 (#9)
**Verification**: Code review: all state machine operations return Result

### REQ-NF-REL-003: Reconnection After Link Flap

The supplicant shall re-establish EAP authentication and MKA session within 10 seconds of link restoration, assuming the authenticator is available.

**Traces to**: StR-010 (#10)
**Verification**: Integration test in Linux network namespace with veth pair; link flap simulated via `ip link set down/up`; timing measured from link-up to Controlled Port SECURE

## Portability

### REQ-NF-PORT-001: Linux x86_64 and ARM64

The supplicant shall build and pass all tests on Linux x86_64 and ARM64 targets.

**Traces to**: StR-007 (#7)
**Verification**: CI build matrix: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`

### REQ-NF-PORT-002: no_std Capability (Feature-Gated)

Core protocol logic (state machines, key derivation) shall be compilable with `#![no_std]` when the `std` feature is disabled, enabling future embedded targets.

**Traces to**: StR-009 (#9)
**Verification**: `cargo build -p pae --no-default-features` succeeds

## Deployment

### REQ-NF-DEPLOY-001: Structured Logging

The supplicant daemon shall use the `tracing` crate for structured logging with runtime level control (trace/debug/info/warn/error) configurable without restart.

**Traces to**: StR-007 (#7)
**Verification**: Integration test: change log level at runtime and verify output

### REQ-NF-DEPLOY-002: Graceful Shutdown

The supplicant daemon shall handle SIGTERM and SIGINT by completing in-flight operations, closing connections, and exiting within 5 seconds.

**Traces to**: StR-007 (#7)
**Verification**: Integration test: send SIGTERM, verify clean exit within 5s

### REQ-NF-DEPLOY-003: Configuration File Support

The supplicant daemon shall load configuration from a TOML file, supporting network profiles, EAP credentials, and MKA parameters.

**Traces to**: StR-007 (#7)
**Verification**: Integration test: load config file, verify parameters applied

### REQ-NF-DEPLOY-004: systemd Integration

The supplicant daemon shall provide a systemd unit file and support socket activation for on-demand startup.

**Traces to**: StR-007 (#7)
**Verification**: Integration test: systemd-run with unit file, verify startup

### REQ-NF-DEPLOY-005: Control Interface

The supplicant daemon shall expose a D-Bus or Unix domain socket control interface for runtime management, operable without root privileges.

**Traces to**: StR-007 (#7)
**Verification**: Integration test: connect to control interface as non-root user, issue commands

## Maintainability

### REQ-NF-MNT-001: Test Coverage ≥ 80%

The supplicant shall maintain ≥ 80% line coverage across all workspace crates as measured by `cargo llvm-cov`.

**Traces to**: StR-006 (#6)
**Verification**: CI coverage gate

### REQ-NF-MNT-002: Public API Documentation

All public API items in library crates shall have `///` doc comments with at least a summary line and an IEEE 802.1X-2020 clause reference where applicable.

**Traces to**: StR-006 (#6)
**Verification**: `cargo doc --workspace --no-deps` builds without warnings

### REQ-NF-MNT-003: Clippy Clean

The workspace shall pass `cargo clippy --workspace -- -D warnings` with zero warnings.

**Traces to**: StR-006 (#6)
**Verification**: CI clippy gate

### REQ-NF-MNT-004: Format Compliant

The workspace shall pass `cargo fmt --all -- --check`.

**Traces to**: StR-006 (#6)
**Verification**: CI format gate

## Traceability

### REQ-NF-TRC-001: Bidirectional Traceability

Every REQ-F/REQ-NF issue shall trace to a parent StR issue. Every ADR shall link to requirements it satisfies. Every TEST issue shall link to requirements being verified. No orphaned or dangling links.

**Traces to**: StR-006 (#6)
**Verification**: CI traceability validation script

### REQ-NF-TRC-002: Clause Reference in Doc Comments

All protocol implementation code shall reference the applicable IEEE 802.1X-2020 clause number in module-level (`//!`) and function-level (`///`) doc comments.

**Traces to**: StR-006 (#6), StR-008 (#8)
**Verification**: Code review: grep for clause references in protocol crates
