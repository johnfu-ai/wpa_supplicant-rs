# Project TODO — wpa_supplicant-rs

**Generated:** 2026-06-06
**Source of truth basis:** GitHub Issues (23 open, 121 closed at last count), `git log`, lifecycle phase directories under `wpa_supplicant-rs/`, and `02-requirements/traceability-matrix.md`.

This file is a **living todo list** that combines (a) GitHub issue state, (b) gaps identified by reading recent commits and the lifecycle docs, and (c) the project's own SKILL workflow.

> **Living-document rule:** when an item lands a PR, mark it `[x]` and move the entry to the *Done* section at the bottom (do **not** delete — the trail is part of the audit evidence per `StR-006: Full Audit Trail and Traceability`).

---

## Phase Status at a Glance

| Phase | State | Evidence |
|---|---|---|
| 01 Stakeholder Requirements | ✅ Approved | 10 StR issues `phase:01` closed-approved |
| 02 Requirements | ✅ Approved | 37 REQ-F + 25 REQ-NF closed-approved; matrix at `02-requirements/traceability-matrix.md` (refreshed 2026-06-07) |
| 03 Architecture | ✅ Approved | 8 ADR + 5 ARC-C + 4 QA-SC closed-approved |
| 04 Detailed Design | ✅ Approved | `04-design/phase-gate-report.md` dated 2026-05-17 |
| 05 Implementation | ✅ Approved (implicit) | 66 issues carry `phase:05-approved`; Phase 06 close subsumes this for daemon-binary scope |
| 06 Integration | ✅ Approved 2026-06-06 | Gate report at `06-integration/phase-gate-report.md`. All 9 INT-NNN landed: INT-002 (#118), INT-007 + INT-008 (#119), INT-006 (#121), INT-009 (#122), INT-003 (#123), INT-004 (#124), INT-005 (#125), INT-001 (#126). 26 cross-crate integration tests. |
| 07 V&V | ✅ Approved 2026-06-07 | Gate report at `07-verification-validation/phase-gate-report.md`. All 3 Phase 06 prerequisites landed: #128 (PR #132 RawSocketNetworkIo), #130 (PR #134 EAP bridge), #129 (PR #136 MkaParticipant). P3.1 FreeRADIUS interop harness landed (PR #137). P3.3 clean-room verification record landed (this PR). 6 TEST-VV gap issues filed (#139–#144). 387 passing tests (+8 from Phase 06). Three conditional re-arms (#133, #135, #138) carried forward to Phase 08; #135 (AES Key Wrap) closed by PR #146 (2026-06-09). |
| 08 Transition | ⬜ Not started | `08-transition/` has README only |
| 09 Operation & Maintenance | ⬜ Not started | `09-operation-maintenance/` has README only |

---

## Priority 1 — Refresh stale tracking artifacts (do first)

Foundation work. Everything else assumes accurate status.

- [x] **P1.1 Refresh `02-requirements/traceability-matrix.md`** — landed in #108 (commit `fa77b7f`, 2026-06-06).
  - Replaced the single six-row "REQ → Code → TEST Chain" summary with seven per-domain tables (PAE / MKA / CP / Logon / EAP / EAPOL / NF) listing per REQ: issue → closing commit → implementing source files → dedicated tests → status.
  - Added Implementation Summary (16 065 LoC / 393 tests / 12 ignored perf across five crates).
  - Added four new bidirectional validation checks; rewrote Gap Analysis (5 Phase-02 gaps closed, 6 open gaps tracked 1:1 in this file).
- [x] **P1.2 Create `docs/PROGRESS.md`** — landed in #108 (2026-06-06).
  - Mirrors the *Phase Status at a Glance* table with closing-evidence and open-work columns.
  - Per-domain implementation status for PAE / MKA / CP / Logon / EAP / wpa-supplicant binary with closing commits + test counts + open-gap pointers.
  - Aggregate implementation summary (62/62 REQ unit-implemented or governance-satisfied; 0 in *Stub* state).
  - Architectural anchor coverage (8 ADR / 5 ARC-C / 4 QA-SC).
  - Cross-cutting posture snapshot (`unsafe`, `.unwrap()`, `no_std`, ARM64 build, clippy, fmt, zeroization, clause-only docs, MKA timer constants).
  - Open-gaps table cross-references this TODO file rather than duplicating it.
  - "How to update this file" footer for future maintainers.

---

## Priority 2 — Phase 06 Integration (the active frontier)

The per-crate state machines are done. Phase 06 wires them inside the `wpa-supplicant` binary. Twelve concrete code-level `TODO:` markers remain — they are the integration backlog.

### P2.1 — Open Phase 06 integration issues
- [x] **P2.1.0 Create the `phase:06-integration` GitHub label** (color follows the `1D76DB` blue used by other `phase:0X-…` labels). — done 2026-06-06; also added `type:integration-task` (`BFD4F2`).
- [x] **P2.1.1 INT-001: Wire config-load → Supplicant construction → event loop in `main.rs`** — landed in **#126** (issue **#109**), 2026-06-06. `main.rs` parses `--config`, calls `Config::load`, constructs `Supplicant::with_logging` against a `NoopNetworkIo` stub, runs the tick loop, exits cleanly on SIGTERM/SIGINT. Smoke-verified end-to-end; `tracing-subscriber` `fmt` feature added so the binary emits to stderr.
- [x] **P2.1.2 INT-002: Dispatch inbound EAPOL frames to `SupplicantPae::handle_eapol()`** — landed in **#118** (issue **#110**), 2026-06-06. EAPOL receive path now parses via `EapolFrame::decode` and dispatches into `SupplicantPae::handle_eapol`. New `SupplicantPaeAdapter<N>` module; `wpa-supplicant` split into `lib.rs` + `main.rs`; blanket `impl NetworkIo for Arc<T>`; integration test under `crates/wpa-supplicant/tests/eapol_dispatch.rs`.
- [x] **P2.1.3 INT-003: Drive `step()` on active state machines and dispatch the returned `PaeEvent`s** — landed in **#123** (issue **#111**), 2026-06-06. `tick()` now drives `pae.step()`; `pae_step()` shim removed; INT-005 cross-reference TODO stakes out the MKA tick.
- [x] **P2.1.4 INT-004: Tear down MKA session and reset Supplicant PAE on disconnect** — landed in **#124** (issue **#112**), 2026-06-06. Link-down resets PAE via `link_changed(false)`; link-up notifies PAE via `link_changed(true)`; `tick()` skips `pae.step()` while link down to avoid bouncing the teardown. MKA-drop / SAK-zeroize deferred (no `MkaParticipant` constructed yet — separate follow-up).
- [x] **P2.1.5 INT-005: Forward MKA-derived SAK install events to the CP state machine** — landed in **#125** (issue **#113**), 2026-06-06. `dispatch_event` rebuilds the SAK from `(sak_key, sak_an)` and forwards `CpEvent::SakAvailable` to the CP; all error paths (malformed SAK, CP wrong-state) downgrade to `warn!`. New public `Supplicant::dispatch_pae_event` test bridge.
- [x] **P2.1.6 INT-006: Expose live state in control-socket status response** — landed in **#121** (issue **#114**), 2026-06-06. Per-field provenance table on `Supplicant::state()`; `pae_state`/`cp_state` already live (INT-002); Logon/MKA fields stay `None`/`false`/`0` until their constructors land (cross-reference comments on #109 + #113). Integration test `tests/control_status.rs` fences the JSON schema.
- [x] **P2.1.7 INT-007: Implement control-socket `reauthenticate` command** — landed in **#119** (issue **#115**), 2026-06-06. `ControlCommand::Reauthenticate` now calls `SupplicantPae::reauthenticate()`; invalid-state requests downgrade to `warn!` per ADR-EVT-007 (#79).
- [x] **P2.1.8 INT-008: Implement control-socket `logoff` command** — landed in **#119** (issue **#116**), 2026-06-06. `ControlCommand::Logoff` now calls `SupplicantPae::logoff()`; MACsec-secured suppression test path deferred to INT-005 (#113); MKA teardown deferred to INT-004 (#112).
- [x] **P2.1.9 INT-009: Runtime log-level reload via `tracing-subscriber`** — landed in **#122** (issue **#117**), 2026-06-06. `ControlCommand::SetLogLevel` now drives `Logging::set_level`; new `Supplicant::with_logging` constructor; `Logging::from_test_handle` extension point; integration test `tests/log_level_reload.rs`.

### P2.2 — Implement against the new issues (TDD)
- [ ] **P2.2 For each INT-NNN, follow `SKILL/prompts/tdd-compile.prompt.md`**: write a cross-crate integration test in `tests/` first (Red), then add the wiring in `supplicant.rs`/`main.rs` (Green), then refactor.
  - Place integration tests under `crates/wpa-supplicant/tests/` (the binary crate is the natural home for cross-crate seams).
  - Each PR title format: `feat(integration): <thing> per INT-NNN (#issue)`.

### P2.3 — Close out Phase 06
- [x] **P2.3.1 Add `06-integration/phase-gate-report.md`** — done 2026-06-06. Follows the structure of `04-design/phase-gate-report.md`: 9 exit criteria (all met), per-INT disposition, integration quality checks, test inventory, architectural anchor coverage, APPROVED recommendation, 5 non-blocking observations, post-approval action list.
- [x] **P2.3.2 Run `SKILL/prompts/phase-gate-check.prompt.md`** — done 2026-06-06; `phase:06-approved` label applied to all 9 INT-NNN issues (#109, #110, #111, #112, #113, #114, #115, #116, #117). Comment posted on ARC-C-WPA-005 (#85).

---

## Priority 3 — Phase 07 Verification & Validation

Phase closed 2026-06-07 — gate report at `07-verification-validation/phase-gate-report.md`.

- [x] **P3.1 FreeRADIUS-in-Docker interop harness** — landed in **PR #137** under `07-verification-validation/interop/`. Docker compose stack (FreeRADIUS `latest-3.2-alpine` + hostapd wired-mode Authenticator), cert-gen script, veth + netns runner, teardown script, `#[ignore]`-gated cargo runner at `crates/wpa-supplicant/tests/interop_freeradius.rs`, dedicated CI workflow at `.github/workflows/interop.yml` (workflow_dispatch-only pending #138 CI debug). Covers REQ-F-EAP-002/003/004 *infrastructure*; full handshake assertions defer to #133 (EAP method factory) and #135 (AES Key Wrap).
- [x] **P3.2 TEST-XXX-NNN gap issues** — filed **6 TEST-VV issues**: #139 (cargo llvm-cov gate), #140 (cargo audit+deny gates), #141 (cargo geiger + // SAFETY: adjacency), #142 (no_std CI gate), #143 (fuzz harness for decoders), #144 (clippy::unwrap_used workspace lint). Each tied to a specific REQ row in the traceability matrix.
- [x] **P3.3 Clean-room verification artifact for REQ-NF-SEC-004** — landed at `07-verification-validation/clean-room-review.md` (this PR). 35/35 production source files now carry the disclaimer (8 utility files patched). Verdict PASS.
- [x] **P3.4 Traceability sweep** — `02-requirements/traceability-matrix.md` refreshed (2026-06-07 edition) with closing PRs for #128/#129/#130, REQ-NF-SEC-004 verification record reference, and 6 TEST-VV gap rows. Bidirectional validation: 10/10 StR → REQ links intact; 62/62 REQ → parent links intact; no orphans.
- [x] **P3.5 Phase 07 gate report + `phase:07-approved`** — landed at `07-verification-validation/phase-gate-report.md`. Label applied to #128, #129, #130 and to the P3.x tracking refs.

---

## Priority 4 — Phase 08 Transition & Phase 09 O&M

Empty today. Plan, do not yet execute, until Phase 07 closes.

- [ ] **P4.1 Release packaging plan** in `08-transition/release-plan.md` (cargo publish strategy, version pinning policy, `cargo-deny` baseline, deb/rpm scope).
- [ ] **P4.2 Operator runbook** in `09-operation-maintenance/runbook.md` (systemd unit examples, log-level tuning, control-socket usage, troubleshooting matrix).
- [ ] **P4.3 Phase 08 gate report**, then Phase 09 entry.

---

## Priority 5 — Cross-cutting hygiene (do whenever it fits)

- [ ] **P5.1 Run `SKILL/prompts/security-review.prompt.md`** over the recent feature batch (#37, #50, #51, #59, #68, #69, #70, #71, #72, #86) — overdue per `CLAUDE.md` workflow rule *"After implementing features, perform a security review."*
- [ ] **P5.2 Add `cargo audit` + `cargo deny check` to CI** (`.github/workflows/ci.yml`).
- [ ] **P5.3 Decide YANG management scope** — the `8021X-2020.YANG/` sibling repo is checked in but no Rust code consumes it. Either:
  - (a) Open `ADR-MGMT-009: NETCONF/YANG management surface` via `SKILL/prompts/architecture-starter.prompt.md`, or
  - (b) Add an explicit deferral note to `8021X-2020.YANG/README.md` so the scope decision is documented.
- [x] **P5.4 Sweep remaining `TODO:`/`FIXME:` markers** in `crates/wpa-supplicant/` after Phase 06 closes; convert any survivors into tracked issues. — done 2026-06-06. Sweep ran after Phase 06 close: three survivors found, all in `supplicant.rs`. Two `TODO(INT-005 / #113)` markers (lines 208, 258) re-pointed at the new `#129` (MKA participant construction). One doc-comment cross-reference to `docs/TODO.md` P5.3 (line 548) left as-is — not a code TODO. The `pae_eap_success` shim doc updated to reference `#130` (EAP-peer-to-PAE bridge) instead of "a future INT-NNN". Three fresh tracking issues filed for the Phase 07 prerequisites surfaced by the Phase 06 gate report: #128 (RawSocketNetworkIo), #129 (MkaParticipant construction), #130 (eap-peer-to-PAE bridge).
- [x] **P5.5 Confirm `cargo test --workspace -- --ignored`** still passes on a representative host (wall-clock perf checks marked `#[ignore]` per commit `a90c033`) — confirmed 2026-06-13. **All 12 ignored perf tests pass** on x86_64 Linux (WSL2): 4 in `eapol-supp` (`supplicant_pae::tests::test_perf_eapol_response_latency_single`, `…_95th_percentile`, `…_step_bounded_execution`, `…_handle_eapol_bounded_execution`) + 8 in `pae` (`cp::tests::test_perf_cp_transition_latency`, `…_95th_percentile`, `…_cp_recompute_latency`, `mka::tests::test_perf_mka_transition_latency`, `…_95th_percentile`, `…_expire_bounded_execution`, `…_hello_latency_under_load_bounded`, `timer::tests::test_perf_advance_bounded_execution`).

---

## Done

- [x] *(2026-06-13)* **P5.5 — `cargo test --workspace -- --ignored` passes** Verified 2026-06-13 on x86_64 Linux (WSL2). All **12 ignored wall-clock perf tests** green: 4 in `eapol-supp::supplicant_pae::tests` (EAPOL response latency single + 95th percentile, step-bounded execution, handle-eapol-bounded execution), 8 in `pae` (CP transition latency + 95th + recompute, MKA transition latency + 95th + expire-bounded + hello-under-load, timer advance-bounded). REQ-NF-PERF-001 / 002 / 003 / 004 perf invariants hold; the `#[ignore]`-gated suite remains the canonical perf check (per commit `a90c033`).

- [x] *(2026-06-13)* **#135 / verification of AES Key Wrap close-out** Confirmed PR #146 / commit `4c17b2e` already implemented RFC 3394 AES Key Wrap in `crates/pae/src/crypto.rs` and wired `MkaParticipantAdapter::unwrap_sak` to it. Issue **#135** auto-closed by `Fixes #135` keyword on the PR. Refreshed live references to the previously-stubbed state: `crates/wpa-supplicant/tests/interop_freeradius.rs` doc-comments + TODO marker; `07-verification-validation/interop/scripts/run-supplicant.sh` acceptance comment; `07-verification-validation/interop/README.md` "current status" + traceability bullets; `docs/PROGRESS.md` MKA + wpa-supplicant "Open gaps" rows + Open Gaps table; `02-requirements/traceability-matrix.md` MKA SAK install gap row flipped to Closed. Historical artifacts (Phase 07 gate report, Done section, traceability "Closed Gaps" header context) intentionally left as-is per audit-trail rules. AES Key Wrap test counts: `cargo test -p pae --lib` → 178 passed / 8 ignored; `cargo test -p wpa-supplicant --test aes_key_wrap_sak` → 3 passed.

- [x] *(2026-06-07)* **Phase 07 V&V close — P3.1 through P3.5** Three Phase 06 prerequisites all landed: **#128** RawSocketNetworkIo (PR #132, commit `6140c01`), **#130** eap-peer→PAE bridge (PR #134, commit `a915ded`), **#129** MkaParticipant construction on Supplicant (PR #136, commit `628c39e`). **P3.1** FreeRADIUS-in-Docker interop harness landed (PR #137, commit `09d8547`) under `07-verification-validation/interop/` — docker-compose + hostapd wired-mode + cert-gen + veth runner + CI workflow (workflow_dispatch-only until **#138** debug). **P3.2** filed 6 TEST-VV gap issues: **#139** (cargo llvm-cov coverage gate), **#140** (cargo audit/deny gates), **#141** (cargo geiger + // SAFETY: adjacency), **#142** (no_std CI gate), **#143** (fuzz harness for EAPOL/EAP/MKPDU decoders), **#144** (clippy::unwrap_used workspace lint). **P3.3** clean-room verification record landed at `07-verification-validation/clean-room-review.md` with 35/35 production source files now carrying the disclaimer (8 utility files patched). **P3.4** traceability matrix refresh — 2026-06-07 edition includes new "Phase 07 V&V update" header notes, refreshed Closed Gaps (#128/#129/#130/P3.1/P3.3 all rolled in), refreshed Open Gaps (#133/#135/#138/#139–#144). **P3.5** Phase 07 gate report at `07-verification-validation/phase-gate-report.md` (APPROVED) with `phase:07-approved` label applied. 387 passing tests workspace-wide (was 379 at Phase 06 close). Two follow-ups (#133 EAP method factory, #135 AES Key Wrap) deferred to Phase 08 backlog so the harness can grow from "infrastructure ready" to "full handshake validation".

- [x] *(2026-06-06)* **P5.4 — TODO sweep + Phase 07 prerequisite issues filed** Sweep ran after Phase 06 close. Three TODO survivors in `crates/wpa-supplicant/src/supplicant.rs`: two `TODO(INT-005 / #113)` markers re-pointed at the new **#129** (MKA participant construction); the `pae_eap_success` shim docstring re-pointed at the new **#130** (eap-peer-to-PAE bridge). Three fresh tracking issues filed for the Phase 07 prerequisites surfaced by the Phase 06 gate report: **#128** (RawSocketNetworkIo / AF_PACKET), **#129** (MkaParticipant construction on `Supplicant`), **#130** (eap-peer-to-PAE bridge — removes the last shim). All three labeled `phase:06-integration` + `type:integration-task` so the Phase 07 V&V harness work has explicit upstream dependencies.
- [x] *(2026-06-06)* **P2.3.1 + P2.3.2 — Phase 06 close-out** Phase-gate report written at `06-integration/phase-gate-report.md` (APPROVED); `phase:06-approved` label applied to all 9 INT-NNN issues (#109, #110, #111, #112, #113, #114, #115, #116, #117); close-out comment posted on ARC-C-WPA-005 (#85). Phase Status row flipped to ✅ Approved. `docs/PROGRESS.md` refreshed: per-domain "Open gaps" cleared for PAE / MKA / CP / Logon; wpa-supplicant binary marked integration-complete; aggregate test count refreshed to 379 (353 unit + 26 integration); Latest Gate Reports table linked to the new report.
- [x] *(2026-06-06)* **P2.1.1 / INT-001** Wire config-load → Supplicant construction → event loop in `main.rs` — landed in **#126** (issue **#109**). `main.rs` parses `--config <path>`, calls `Config::load`, constructs `Supplicant::with_logging` against `NoopNetworkIo`, runs the tick loop with 100ms cadence, exits cleanly on SIGTERM/SIGINT. Adds `tracing-subscriber` `fmt` feature so the binary emits to stderr. Smoke-verified: startup log → config loaded → event loop → shutdown complete.
- [x] *(2026-06-06)* **P2.1.5 / INT-005** Forward MKA-derived SAK install events to CP — landed in **#125** (issue **#113**). `dispatch_event` rebuilds SAK from `(sak_key, sak_an)` and forwards `CpEvent::SakAvailable` per Cl.9.13 / Cl.10; all error paths downgrade to `warn!`. New `dispatch_pae_event` public test bridge.
- [x] *(2026-06-06)* **P2.1.4 / INT-004** Reset Supplicant PAE on link-down — landed in **#124** (issue **#112**). Link-down: `pae.link_changed(false)` → PAE Disconnected + timers cancelled. Link-up: `pae.link_changed(true)` → PAE re-connects + EAPOL-Start. Skip `pae.step()` while link down. MKA-drop deferred to #113.
- [x] *(2026-06-06)* **P2.1.3 / INT-003** Drive `pae.step()` from `tick()` — landed in **#123** (issue **#111**). `pae_step()` shim removed; `tick()` now advances PAE through timer-driven Cl.8.3 transitions. INT-005 TODO stakes out MKA tick.
- [x] *(2026-06-06)* **P2.1.9 / INT-009** Runtime log-level reload — landed in **#122** (issue **#117**). `ControlCommand::SetLogLevel` drives `Logging::set_level`; new `with_logging` constructor; `from_test_handle` extension point.
- [x] *(2026-06-06)* **P2.1.6 / INT-006** Document and test live status schema — landed in **#121** (issue **#114**). Per-field provenance table on `Supplicant::state()`. Schema fenced by integration test `control_status.rs`; Logon/MKA fields cross-referenced to INT-001/INT-005.
- [x] *(2026-06-06)* **P2.1.7 / INT-007 + P2.1.8 / INT-008** Wire control-socket `reauthenticate` and `logoff` commands into `SupplicantPae` — landed in **#119** (issues **#115**, **#116**). Both commands now drive the Cl.8.3 / Cl.8.5 paths; invalid-state requests downgrade to `warn!` per ADR-EVT-007 so the daemon cannot be crashed via the control socket. Added two thin integration-shim accessors (`pae_step`, `pae_eap_success`) doc-marked for removal under INT-003 (#111); cleanup hook recorded on that issue. New `tests/control_reauth_logoff.rs` with 4 cases. `SetLogLevel` TODO tightened to reference INT-009 (#117). PASS-WITH-WARNINGS from `ieee-traceability-reviewer`; warning addressed in-PR.
- [x] *(2026-06-06)* **P2.1.2 / INT-002** Dispatch inbound EAPOL frames to `SupplicantPae::handle_eapol()` — landed in **#118** (issue **#110**). Splits `wpa-supplicant` into `lib.rs` + `main.rs`; adds `SupplicantPaeAdapter<N>` (`pae_adapter.rs`); blanket `impl NetworkIo for Arc<T>` so the adapter and event loop share one network handle; new accessors `pae_state()`, `pae_set_authenticate()`, `pae_counters()`; integration test `tests/eapol_dispatch.rs` covers well-formed and malformed frames. `state()` now reports the live PAE state. PASS-WITH-WARNINGS from `ieee-traceability-reviewer`; warnings addressed in-PR.
- [x] *(2026-06-06)* **P2.1.0** Create `phase:06-integration` and `type:integration-task` GitHub labels.
- [x] *(2026-06-06)* **P2.1.1, P2.1.3–P2.1.9** Opened all nine INT-NNN Phase 06 tracking issues (#109–#117) with detailed scope, acceptance criteria, dependency notes, and IEEE clause references — sets up the rest of Phase 06 as discrete TDD slices.
- [x] *(2026-06-06)* **P1.2** Create `docs/PROGRESS.md` — landed in **#108**. Operator-facing roll-up: phase status, per-domain (PAE / MKA / CP / Logon / EAP / wpa-supplicant) implementation depth, aggregate summary (62/62 REQ unit-implemented or governance-satisfied), architectural anchor coverage, cross-cutting posture snapshot, open-gap pointers, maintainer footer.
- [x] *(2026-06-06)* **P1.1** Refresh `02-requirements/traceability-matrix.md` to reflect Phase-05 implementation — landed in **#108** (commit `fa77b7f`). Per-REQ closing-commit + implementing-file + test-fn tables added across PAE / MKA / CP / Logon / EAPOL / NF; 5 Phase-02 gaps closed; 6 open gaps tracked 1:1 in this file.

*(Move further completed items here with PR link, in reverse-chronological order.)*

---

## Notes for AI agents reading this file

- Open GitHub Issues today are **tracking anchors** (StR / ADR / ARC-C), not work tickets. Do not interpret an "open" issue as "todo" — check this file plus `git log` for actual work state.
- The project's workflow is described in `SKILL/WORKFLOW-GUIDE.md`. Every item above maps to a step in that guide.
- When in doubt about an item's status, run `gh issue list --state closed --search "<REQ-ID>"` and read the closing PR diff before re-doing work.
