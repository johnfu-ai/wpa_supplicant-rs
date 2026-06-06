# Project Progress — wpa_supplicant-rs

**Generated:** 2026-06-06
**Source basis:** GitHub Issues (`gh issue list`), `git log --oneline --all`, `02-requirements/traceability-matrix.md` (2026-06-06 refresh, PR #108), `crates/*/src/**/*.rs` (`Implements:` / `Verifies:` doc-comment anchors), per-crate `cargo test` counts.

This file is a **living snapshot** of where the project stands across the 9-phase lifecycle and the five workspace crates. It is the operator-facing companion to `02-requirements/traceability-matrix.md` (the auditor-facing artifact) and `docs/TODO.md` (the action-item backlog).

> **Update cadence.** Refresh this file whenever a phase-gate report lands, whenever a new domain reaches "Implemented", or whenever the per-domain test count materially changes. The format mirrors `04-design/phase-gate-report.md` — exit criteria → status table → evidence → recommendation — so reviewers can scan it the same way as any phase gate.

---

## Phase Status at a Glance

| Phase | State | Closing Evidence | Open Work |
|---|---|---|---|
| 01 Stakeholder Requirements | ✅ Approved | 10 StR issues (#1–#10), `phase:01-approved` label, `01-stakeholder-requirements/phase-gate-report.md` | — |
| 02 Requirements | ✅ Approved | 37 REQ-F + 25 REQ-NF closed-approved; matrix at `02-requirements/traceability-matrix.md` (refreshed 2026-06-06, PR #108) | — |
| 03 Architecture | ✅ Approved | 8 ADR (#73–#80) + 5 ARC-C (#81–#85) + 4 QA-SC (#86–#89) closed-approved | — |
| 04 Detailed Design | ✅ Approved | `04-design/phase-gate-report.md` dated 2026-05-17 | — |
| 05 Implementation | 🟡 In progress | 66 issues with `phase:05-approved`; 393 tests / 16 065 LoC across 5 crates | All REQ-F + REQ-NF implemented; phase-gate report pending (`docs/TODO.md` P2.3) |
| 06 Integration | ⬜ Not started | `06-integration/README.md` only | 12 `TODO:` markers in `crates/wpa-supplicant/` → enumerated as INT-001..INT-009 (`docs/TODO.md` P2.1) |
| 07 V&V | ⬜ Not started | `07-verification-validation/README.md` only | FreeRADIUS interop harness; TEST-XXX issues; clean-room review record (`docs/TODO.md` P3.1–P3.5) |
| 08 Transition | ⬜ Not started | `08-transition/README.md` only | Release plan + cargo publish strategy (`docs/TODO.md` P4.1) |
| 09 Operation & Maintenance | ⬜ Not started | `09-operation-maintenance/README.md` only | Operator runbook + systemd examples (`docs/TODO.md` P4.2) |

---

## Per-Domain Implementation Status

The five workspace crates map onto the IEEE 802.1X-2020 protocol entities as follows. Each row reports current implementation depth, supporting evidence, and the open items that block the *next* phase (06 Integration) from closing.

### 1. PAE (Clause 8 — Supplicant PAE) — `crates/eapol-supp`

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | ✅ Complete | `supplicant_pae.rs` implements the full PACP state machine; `transmitter.rs` and `receiver.rs` handle EAPOL frames; `frame.rs` does encode/decode; `announcement.rs` consumes EAPOL-Announcement |
| REQ-F coverage | 8 / 8 | REQ-F-PAE-001..008 — see traceability matrix, PAE section |
| REQ-NF coverage | 2 / 2 | REQ-NF-PERF-003 (EAPOL response latency) |
| Closing commits | `0f18bc3`, `cb54179`, `3a7cd14`, `06c35bf`, `ebf6322` | One commit per REQ-F + one perf commit |
| Tests | 68 unit tests (4 `#[ignore]` perf) | `cargo test -p eapol-supp` |
| Open gaps | Integration only | The PACP state machine is not yet driven from the binary's event loop — INT-001..INT-003 (`docs/TODO.md` P2.1) |

### 2. MKA (Clause 9 — MKA Supplicant Participant) — `crates/pae` (mka, mkpdu, timer)

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | ✅ Complete | `mka.rs` implements MkaParticipant + peer list + key server election + SAK install; `mkpdu.rs` does wire-format encode/decode; `timer.rs` provides the deterministic timer wheel with canonical MKA timer constants (Hello 2 000 ms / Life 6 000 ms / SAK-Retire 3 000 ms — committed in `83bca6f`) |
| REQ-F coverage | 10 / 10 | REQ-F-MKA-001..010 + REQ-F-EAPOL-004 (MKPDU) — see traceability matrix, MKA / EAPOL sections |
| REQ-NF coverage | 2 / 2 | REQ-NF-PERF-001 (Hello), REQ-NF-PERF-002 (Life Time) |
| Closing commits | `d12487a`, `2bb4179`, `2141dfd`, `7f478a4`, `7c2f118`, `b1b6b99`, `83bca6f` | |
| Tests | 172 unit tests (8 `#[ignore]` perf) — largest crate by test count | `cargo test -p pae` |
| Open gaps | Integration only | MKA session establishment / SAK forward to CP not yet wired from binary — INT-004, INT-005 (`docs/TODO.md` P2.1) |

### 3. CP (Clause 10 — Controlled Port) — `crates/pae/src/cp.rs`

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | ✅ Complete | `cp.rs` implements the CP state machine, Secure Channel / SA management, MACsec cipher suite selection |
| REQ-F coverage | 4 / 4 | REQ-F-CP-001..004 — see traceability matrix, CP section |
| Closing commits | `f56d9c9`, `9f29dd9`, `76c275a`, `1385adf` | |
| Tests | 36 unit tests (3 `#[ignore]` perf) within `pae` | included in `cargo test -p pae` |
| Open gaps | Integration only | SAK install events not yet forwarded from MKA → CP at the binary level — INT-005 (`docs/TODO.md` P2.1) |

### 4. Logon (Clause 12 — Logon Process) — `crates/logon`, `crates/eapol-supp/src/announcement.rs`

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | ✅ Complete | `logon_sm.rs` implements the Logon state machine; `nid.rs` does NID selection; `cak_cache.rs` is the CAK cache with HashMap + expiry; EAPOL-Announcement consumer lives in `eapol-supp/src/announcement.rs`; NID-in-EAPOL-Start in `eapol-supp/src/frame.rs` |
| REQ-F coverage | 5 / 5 | REQ-F-LOGON-001..005 — see traceability matrix, Logon section |
| Closing commits | `f8adce4`, `32da118`, `2701499`, `0c7a844`, `cbad4f3` | |
| Tests | 28 unit tests in `logon`, 6 in `eapol-supp/announcement.rs` | `cargo test -p logon` + announcement suite |
| Open gaps | None at crate level; integration scope only |

### 5. EAP Peer — `crates/eap-peer`

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | ✅ Unit-complete | `peer.rs` implements the EAP peer framework; `eap_tls.rs`, `eap_peap.rs`, `eap_teap.rs` implement each method (feature-gated per ADR-FF-006 #78); `key_derivation.rs` derives MSK/EMSK/CAK |
| REQ-F coverage | 6 / 6 unit-tested | REQ-F-EAP-001..006 — see traceability matrix, EAP section |
| Closing commits | `3ef5b0b`, `b39c99e`, `ae0d9d2`, `9af95f3`, `9a518d6`, `137f9b1` | |
| Tests | 75 unit tests (0 `#[ignore]`) | `cargo test -p eap-peer` |
| Open gaps | **Interop** — REQ-F-EAP-002/003/004 unit-implemented but cross-implementation interop blocked on FreeRADIUS harness (Phase 07 work; `docs/TODO.md` P3.1) |

### 6. wpa-supplicant Binary — `crates/wpa-supplicant`

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | 🟡 Foundations landed, integration in progress | TOML config + main entry point + structured logging + graceful shutdown + systemd socket activation + Unix-domain control socket + link-flap reconnection all implemented; **cross-crate event loop not yet wired** |
| REQ-NF coverage | 6 / 6 (DEPLOY + REL-003) | REQ-NF-DEPLOY-001..005, REQ-NF-REL-003 |
| Closing commits | `f08c297`, `9092fef`, `(config)`, `51637ad`, `d99d446`, `38e5992` | |
| Tests | 50 unit tests (0 `#[ignore]`) | `cargo test -p wpa-supplicant` |
| Open gaps | **12 `TODO:` markers** in `main.rs` and `supplicant.rs` — these are the entire Phase-06 backlog, enumerated as INT-001..INT-009 in `docs/TODO.md` P2.1 |

---

## Aggregate Implementation Summary

| Crate | LoC | Tests | Ignored (perf) | REQ-F | REQ-NF | State |
|---|---:|---:|---:|---:|---:|---|
| `pae` | 6 517 | 172 | 8 | 15 (MKA+CP+EAPOL-MKPDU) | 4 (PERF + PORT-002 + SEC-003) | Complete |
| `eapol-supp` | 2 546 | 68 | 4 | 14 (PAE + EAPOL + LOGON-003/004) | 1 (PERF-003) | Complete |
| `eap-peer` | 3 663 | 75 | 0 | 6 (EAP) | — | Unit-complete; interop pending |
| `logon` | 1 252 | 28 | 0 | 3 (LOGON-001/002/005) | — | Complete |
| `wpa-supplicant` (bin) | 2 087 | 50 | 0 | — | 6 (DEPLOY + REL-003) | Integration pending |
| **Total** | **16 065** | **393** | **12** | **37 / 37** | **25 / 25** | |

**Implementation completeness:** 37/37 REQ-F + 25/25 REQ-NF = **62/62 (100 %)** unit-implemented or governance-satisfied.

**Outstanding:** **0** REQ in *Stub* state. The remaining work is *integration* (Phase 06) and *V&V interop / coverage gating* (Phase 07) — not implementation.

---

## Architectural Anchor Coverage

| Anchor | Count | Issues | Where implemented |
|---|---:|---|---|
| ADR (Architecture Decision Records) | 8 | #73 ADR-WS-001 (workspace), #74 ADR-SM-002 (state machines), #75 ADR-TMR-003 (timer wheel), #76 ADR-SEC-004 (zeroization), #77 ADR-ERR-005 (errors), #78 ADR-FF-006 (feature flags), #79 ADR-EVT-007 (event-driven), #80 ADR-KDF-008 (KDF abstraction) | Each ADR referenced in the module(s) it shapes |
| ARC-C (Architecture Components) | 5 | #81 pae, #82 eapol-supp, #83 eap-peer, #84 logon, #85 wpa-supplicant | One crate per ARC-C, 1:1 |
| QA-SC (Quality Scenarios) | 4 | #86 PERF (covered by `pae/timer.rs` + `pae/mka.rs` perf suite), #87 SEC (covered by REQ-NF-SEC-001..005 posture), #88 REL (covered by REQ-NF-REL-001..002 posture), #89 MOD (covered by ADR-FF-006 + `eap-peer` feature-gated methods) | Distributed across crates |

---

## Latest Gate Reports

| Phase | Report | Status |
|---|---|---|
| 01 Stakeholder Requirements | `01-stakeholder-requirements/phase-gate-report.md` | Approved |
| 02 Requirements | `02-requirements/` (traceability matrix is the artifact; refreshed 2026-06-06 PR #108) | Approved |
| 03 Architecture | `03-architecture/phase-gate-report.md` | Approved |
| 04 Detailed Design | `04-design/phase-gate-report.md` | Approved 2026-05-17 |
| 05 Implementation | — pending — | Phase-gate report to be written when Phase 06 wiring closes (`docs/TODO.md` P2.3) |
| 06 Integration | — not started — | First INT-NNN PR opens Phase 06 |
| 07 Verification & Validation | — not started — | |
| 08 Transition | — not started — | |
| 09 Operation & Maintenance | — not started — | |

---

## Cross-Cutting Posture

| Concern | Posture | Evidence |
|---|---|---|
| `unsafe` discipline | ✅ 1 documented `unsafe` in `wpa-supplicant/src/systemd.rs:42` with `// SAFETY:` comment at `:40` | `grep -rn 'unsafe' crates/ \| grep -v SAFETY` |
| `.unwrap()` in production | ✅ 3 residual calls in non-test paths, all on demonstrably-infallible constructions | grep audit |
| `no_std` capability | ✅ `crates/pae` builds `--no-default-features` and `--no-default-features --features macsec` (REQ-NF-PORT-002) | `cargo build -p pae --no-default-features` |
| Cross-architecture build | ✅ CI cross-builds every library + binary for `aarch64-unknown-linux-gnu` (REQ-NF-PORT-001) | `.github/workflows/ci.yml` `build-aarch64` job |
| Clippy clean | ✅ `cargo clippy --workspace --all-targets -- -D warnings` passes; CI enforces | `.github/workflows/ci.yml` |
| Format clean | ✅ `cargo fmt --all -- --check` passes; CI enforces | `.github/workflows/ci.yml` |
| Secret zeroization | ✅ `zeroize::Zeroize` applied to CAK / SAK / KEK / ICK in `crates/pae/src/mka.rs` per ADR-SEC-004 (#76) | grep audit |
| Clause-only documentation | ✅ Module-level doc comments cite IEEE 802.1X-2020 clauses by number; no standard text reproduced per REQ-NF-SEC-005 / REQ-NF-TRC-002 | `da61820`, manual review |
| Canonical MKA timer constants | ✅ Hello 2 000 ms / Life 6 000 ms / SAK-Retire 3 000 ms imported from shared constants; redefinitions removed in `83bca6f` | `crates/pae/src/timer.rs` |

---

## Open Gaps (Pointers, not duplicates of `docs/TODO.md`)

| Gap | Severity | TODO ref |
|---|---|---|
| Phase 06 wiring — 12 cross-crate seams in `wpa-supplicant` binary | Active work | P2.1 — P2.3 |
| FreeRADIUS interop harness for REQ-F-EAP-002/003/004 | Blocks Phase 07 close | P3.1 |
| TEST-XXX-NNN issues for uncovered REQs | Blocks Phase 07 close | P3.2 |
| Clean-room verification record (REQ-NF-SEC-004) | Blocks Phase 07 close | P3.3 |
| `cargo llvm-cov` ≥ 80 % CI gate (REQ-NF-MNT-001) | Low | P5.2 |
| `cargo audit` + `cargo deny check` CI gates | Low | P5.2 |
| Security review batch for #37, #50, #51, #59, #68–#72, #86 | Medium | P5.1 |
| YANG management scope decision | Info | P5.3 |

---

## How to Update This File

1. After a feature PR lands that completes a domain: update the **Per-Domain Implementation Status** row for that crate (closing commit, test count, state).
2. After a phase-gate PR lands: flip the **Phase Status at a Glance** row to ✅ Approved, link the new report under **Latest Gate Reports**, and remove the matching items from **Open Gaps**.
3. After a cross-cutting check changes (new `unsafe`, new `.unwrap()`, coverage gate added, etc.): re-run the grep / CI check and update **Cross-Cutting Posture**.
4. Cross-reference `02-requirements/traceability-matrix.md` for the auditor-facing REQ-by-REQ view; this file is the operator-facing roll-up.
