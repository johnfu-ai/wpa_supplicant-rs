# REQ-NF Implementation Priority

Phase 05+ — TDD implementation order for remaining non-functional requirements.
Extends `implementation-priority.md` (which covers REQ-F P0–P5, all Done).

## Priority Rules

1. **Crate dependency order**: Foundation traits and types in `wpa-supplicant` first, then features that depend on them
2. **Core path before features**: Config + event loop before logging, shutdown, control interface
3. **Integration before measurement**: Wire crates together before benchmarking performance
4. **Deployment readiness**: Features needed to run as a daemon come last

## Dependency Graph

```
P6: Config → Event Loop → Structured Logging → Graceful Shutdown
P7: Control Interface → systemd
P8: Performance benchmarks (PERF-001–004, QA-SC-PERF-001)
P9: Portability (PORT-001, PORT-002)
P10: Reliability (REL-003: reconnection after link flap)
```

## P6 — wpa-supplicant Core (depends on all REQ-F crates)

These items build the `wpa-supplicant` crate into a runnable application,
wiring together the library crates via the event loop per ADR-EVT-007 (#79).

| # | REQ-NF | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 70 | REQ-NF-DEPLOY-003 | Configuration File Support (TOML) | `wpa-supplicant` | — | Done |
| — | — | Supplicant Assembly + Event Loop | `wpa-supplicant` | DEPLOY-003 | Done |
| 68 | REQ-NF-DEPLOY-001 | Structured Logging | `wpa-supplicant` | Event Loop | Done |
| 69 | REQ-NF-DEPLOY-002 | Graceful Shutdown | `wpa-supplicant` | Event Loop | Done |

### Notes

- **DEPLOY-003 first**: Config is the foundation — everything else reads from it.
  Design: `Config` struct with `serde::Deserialize`, `Config::load()` and `Config::from_toml()`.
  Per `04-design/components/wpa-supplicant.md`.
- **Supplicant + Event Loop** (untracked): Not a standalone REQ-NF but required scaffolding.
  `Supplicant` struct owns all state machines, `tick()` dispatches `PaeEvent`s.
  This is the integration point for ARC-C-WPA-005 (#85).
- **DEPLOY-001**: Replace placeholder `tracing_subscriber` with runtime-level control
  (reload filter without restart). Uses `tracing-subscriber` `reload` layer.
- **DEPLOY-002**: `ShutdownHandler` with SIGTERM/SIGINT via `signal-hook` or `tokio::signal`.
  5-second deadline. Must complete in-flight operations before exit.

## P7 — Control Interface and systemd (depends on P6)

| # | REQ-NF | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 72 | REQ-NF-DEPLOY-005 | Control Interface (Unix socket) | `wpa-supplicant` | P6 | Done |
| 71 | REQ-NF-DEPLOY-004 | systemd Integration | `wpa-supplicant` | DEPLOY-005 | Done |

### Notes

- **DEPLOY-005 first**: Unix domain socket control interface is the simpler and
  more portable option. D-Bus is feature-gated behind `dbus-control`.
  Design: `ControlInterface` trait + `UnixControl` impl, `ControlCommand` enum.
- **DEPLOY-004**: systemd unit file + socket activation. Feature-gated behind
  `systemd` feature flag. Depends on control interface for socket handoff.

## P8 — Performance Validation (depends on P6)

| # | REQ-NF | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 48 | REQ-NF-PERF-001 | MKA Hello Interval (2.0s / 0.5s) | `pae` | — | Done |
| 49 | REQ-NF-PERF-002 | MKA Life Time (6.0s) | `pae` | — | Done |
| 50 | REQ-NF-PERF-003 | EAPOL Response Latency (100ms) | `eapol-supp` | P6 | Done |
| 51 | REQ-NF-PERF-004 | State Machine Transition Latency (10ms) | `pae` | — | Done |
| 86 | QA-SC-PERF-001 | MKA Hello Timing Under Load | `pae` | PERF-001 | Done |

### Notes

- **PERF-001 and PERF-002** can be validated with virtual-clock unit tests in `pae`
  — no hardware needed. Timer wheel fires MKPDU at correct interval; peer list
  expires entries after correct timeout.
- **PERF-003** requires the event loop (P6) to measure end-to-end EAPOL-EAP
  response latency. 95th percentile ≤ 100ms.
- **PERF-004** measures `step()` call duration per state machine. Should be
  sub-microsecond in practice; 10ms budget is generous. `criterion` benchmarks.
- **QA-SC-PERF-001** is the ATAM scenario: 10 concurrent peers + EAP-TLS
  reauthentication while MKA Hello timer expires. Measures 95th percentile
  MKPDU transmission latency.

## P9 — Portability (independent of P6–P8)

| # | REQ-NF | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 60 | REQ-NF-PORT-001 | Linux x86_64 and ARM64 | workspace | — | Done |
| 61 | REQ-NF-PORT-002 | no_std Capability (Feature-Gated) | `pae` | — | Todo |

### Notes

- **PORT-001**: Add CI build matrix for `aarch64-unknown-linux-gnu` cross-compilation.
  May need `cross` tool or QEMU for test execution. No code changes expected.
- **PORT-002**: Add `std` feature flag to `pae` crate. Gate `std::time`, `HashMap`,
  etc. behind `#[cfg(feature = "std")]`. Core crypto and state machine logic
  must compile with `#![no_std]`. Significant refactoring effort.

## P10 — Reliability (depends on P6)

| # | REQ-NF | Title | Crate | Depends On | Status |
|---|---|---|---|---|---|
| 59 | REQ-NF-REL-003 | Reconnection After Link Flap (10s) | `wpa-supplicant` | P6 | Todo |

### Notes

- Integration test in Linux network namespace with `veth` pair.
- `ip link set down/up` simulates link flap.
- Timing from link-up to Controlled Port SECURE must be ≤ 10s.
- Requires event loop, PAE, MKA, and CP all wired together.

## Summary

| Phase | Items | Crate | Key Dependency |
|---|---|---|---|
| P6 | 3 REQ-NF + 1 scaffolding | `wpa-supplicant` | All REQ-F crates (Done) |
| P7 | 2 REQ-NF | `wpa-supplicant` | P6 |
| P8 | 4 REQ-NF + 1 QA-SC | `pae`, `eapol-supp`, `wpa-supplicant` | P6 (for PERF-003) |
| P9 | 2 REQ-NF | workspace, `pae` | None |
| P10 | 1 REQ-NF | `wpa-supplicant` | P6 |

**Recommended first issue**: #70 (REQ-NF-DEPLOY-003: Configuration File Support) — foundation for the entire `wpa-supplicant` crate.

## Usage with /tdd-compile

```
/tdd-compile <issue-number>
```

Start with P6 items first. Recommended first issue: `#70` (REQ-NF-DEPLOY-003: Configuration File Support).
