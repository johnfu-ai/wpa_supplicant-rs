# Project Progress — wpa_supplicant-rs

**Generated:** 2026-06-06 (refreshed after Phase 06 close)
**Source basis:** GitHub Issues (`gh issue list`), `git log --oneline --all`, `02-requirements/traceability-matrix.md` (2026-06-06 refresh, PR #108), `06-integration/phase-gate-report.md` (Phase 06 close, 2026-06-06), `crates/*/src/**/*.rs` (`Implements:` / `Verifies:` doc-comment anchors), per-crate `cargo test` counts.

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
| 05 Implementation | ✅ Approved (implicit) | 66 issues with `phase:05-approved`; 353 unit tests / 16 065 LoC across 5 crates. All REQ-F + REQ-NF implemented or governance-satisfied | Per-crate gate report can be retro-fitted; the Phase 06 close subsumes the Phase 05 close for daemon-binary scope |
| 06 Integration | ✅ Approved 2026-06-06 | All 9 INT-NNN landed (#118, #119, #121, #122, #123, #124, #125, #126). 26 new cross-crate integration tests under `crates/wpa-supplicant/tests/`. Gate report: `06-integration/phase-gate-report.md` | Real `RawSocketNetworkIo` (AF_PACKET) deferred to a Phase 07 prerequisite — `NoopNetworkIo` stub used today (see Phase 06 gate report Observation 1) |
| 07 V&V | ⬜ Not started | `07-verification-validation/README.md` only | FreeRADIUS interop harness; TEST-XXX issues; clean-room review record; `RawSocketNetworkIo` prerequisite (`docs/TODO.md` P3.1–P3.5) |
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
| Open gaps | None at crate level | The PACP state machine is wired into the binary's event loop as of Phase 06 close (INT-002 #118 + INT-003 #123); see `06-integration/phase-gate-report.md` |

### 2. MKA (Clause 9 — MKA Supplicant Participant) — `crates/pae` (mka, mkpdu, timer)

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | ✅ Complete | `mka.rs` implements MkaParticipant + peer list + key server election + SAK install; `mkpdu.rs` does wire-format encode/decode; `timer.rs` provides the deterministic timer wheel with canonical MKA timer constants (Hello 2 000 ms / Life 6 000 ms / SAK-Retire 3 000 ms — committed in `83bca6f`) |
| REQ-F coverage | 10 / 10 | REQ-F-MKA-001..010 + REQ-F-EAPOL-004 (MKPDU) — see traceability matrix, MKA / EAPOL sections |
| REQ-NF coverage | 2 / 2 | REQ-NF-PERF-001 (Hello), REQ-NF-PERF-002 (Life Time) |
| Closing commits | `d12487a`, `2bb4179`, `2141dfd`, `7f478a4`, `7c2f118`, `b1b6b99`, `83bca6f` | |
| Tests | 172 unit tests (8 `#[ignore]` perf) — largest crate by test count | `cargo test -p pae` |
| Open gaps | MKA participant not yet constructed on `Supplicant` | The `MkaParticipant` requires a CAK from the EAP exchange, which in turn needs FreeRADIUS interop (Phase 07 work, `docs/TODO.md` P3.1). INT-004 (#124) + INT-005 (#125) leave the construction-site `TODO` markers and the `dispatch_pae_event` test bridge proves the downstream SAK → CP path. |

### 3. CP (Clause 10 — Controlled Port) — `crates/pae/src/cp.rs`

| Aspect | Status | Evidence |
|---|---|---|
| Implementation | ✅ Complete | `cp.rs` implements the CP state machine, Secure Channel / SA management, MACsec cipher suite selection |
| REQ-F coverage | 4 / 4 | REQ-F-CP-001..004 — see traceability matrix, CP section |
| Closing commits | `f56d9c9`, `9f29dd9`, `76c275a`, `1385adf` | |
| Tests | 36 unit tests (3 `#[ignore]` perf) within `pae` | included in `cargo test -p pae` |
| Open gaps | None at crate level | SAK install events flow MKA → `dispatch_event` → CP per INT-005 (#125); test coverage in `tests/sak_install_secures_cp.rs` |

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
| Implementation | ✅ All 9 INT-NNN landed — binary runs end-to-end | Config load + event loop + signal handling (INT-001 #126); EAPOL receive + PAE dispatch (INT-002 #118); `pae.step()` driven from `tick()` (INT-003 #123); round-trip link-flap recovery (INT-004 #124); SAK → CP dispatch (INT-005 #125); live state schema (INT-006 #121); reauth / logoff commands (INT-007/008 #119); log-level reload (INT-009 #122). 26 cross-crate integration tests. |
| REQ-NF coverage | 6 / 6 (DEPLOY + REL-003) | REQ-NF-DEPLOY-001..005, REQ-NF-REL-003 |
| Closing commits | 8 Phase-06 PRs: #118, #119, #121, #122, #123, #124, #125, #126 | See `06-integration/phase-gate-report.md` Per-INT Disposition table for per-PR commit SHAs |
| Tests | 46 unit + **26 integration** = 72 total (0 `#[ignore]`) | `cargo test -p wpa-supplicant` |
| Open gaps | **RawSocketNetworkIo pending** — `NoopNetworkIo` stub in prod path until real AF_PACKET socket lands (Phase 07 prerequisite; per Phase 06 gate report Observation 1) | `MkaParticipant` not yet constructed on `Supplicant` (requires CAK from EAP exchange — Phase 07 work) |

---

## Aggregate Implementation Summary

| Crate | LoC (est.) | Tests | Ignored (perf) | REQ-F | REQ-NF | State |
|---|---:|---:|---:|---:|---:|---|
| `pae` | 6 517 | 164 | 8 | 15 (MKA+CP+EAPOL-MKPDU) | 4 (PERF + PORT-002 + SEC-003) | Complete |
| `eapol-supp` | 2 546 | 64 | 4 | 14 (PAE + EAPOL + LOGON-003/004) | 1 (PERF-003) | Complete |
| `eap-peer` | 3 663 | 51 | 0 | 6 (EAP) | — | Unit-complete; interop pending |
| `logon` | 1 252 | 28 | 0 | 3 (LOGON-001/002/005) | — | Complete |
| `wpa-supplicant` (bin) | 2 087 | 72 | 0 | — | 6 (DEPLOY + REL-003) | ✅ Integration complete |
| **Total** | **16 065** | **379** | **12** | **37 / 37** | **25 / 25** | |

**Implementation completeness:** 37/37 REQ-F + 25/25 REQ-NF = **62/62 (100 %)** unit-implemented or governance-satisfied.

**Outstanding:** **0** REQ in *Stub* state. The remaining work is *Phase 07 V&V* (interop harness → `RawSocketNetworkIo` → FreeRADIUS → EAP-method conformance → coverage gating) — not implementation.

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
| 05 Implementation | Implicitly closed by Phase 06 close | 66 PRs with `phase:05-approved`; daemon now boots end-to-end |
| 06 Integration | `06-integration/phase-gate-report.md` | ✅ Approved 2026-06-06 |
| 07 Verification & Validation | — pending — | FreeRADIUS interop harness is the next prerequisite |
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
| `RawSocketNetworkIo` (AF_PACKET) — `NoopNetworkIo` stub still in the binary's prod path | Blocks Phase 07 interop | Phase 06 gate report Observation 1; Phase 07 prerequisite — fresh issue to be opened |
| `MkaParticipant` construction on `Supplicant` — gated on CAK from EAP exchange | Blocks Phase 07 end-to-end | Phase 06 gate report Observation 2; Phase 07 prerequisite |
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
