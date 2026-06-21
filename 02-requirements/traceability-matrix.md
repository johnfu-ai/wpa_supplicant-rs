# Traceability Matrix

ISO/IEC/IEEE 29148:2018 — Bidirectional Traceability Report
Project: IEEE 802.1X-2020 Rust Supplicant
Date: 2026-06-07 (Phase 07 V&V close — interop harness + clean-room review record landed)
Previous editions: 2026-06-06 (Phase 05 implementation refresh per `docs/TODO.md` P1.1), 2026-05-17 (Phase 02 close).

> **What changed in this edition.**
> - Three Phase 07 prerequisites filed at Phase 06 close are now landed:
>   #128 `RawSocketNetworkIo` (PR #132), #130 eap-peer→PAE bridge (PR #134),
>   #129 `MkaParticipant` construction (PR #136).
> - FreeRADIUS-in-Docker interop harness P3.1 landed (PR #137) under
>   `07-verification-validation/interop/`.
> - REQ-NF-SEC-004 clean-room verification record written
>   (`07-verification-validation/clean-room-review.md`, this PR).
> - 6 TEST-VV-NNN gap issues filed (#139–#144) covering CI-level
>   verification gaps for REQ-NF-MNT-001, REQ-NF-SEC-001/002, REQ-NF-REL-001/002,
>   REQ-NF-PORT-002, and supply-chain hygiene.
> - 3 follow-up issues filed: #133 (EAP method factory), #135 (AES Key Wrap
>   RFC 3394), #138 (FreeRADIUS CI debug). These do not block the Phase 07
>   gate — see `07-verification-validation/phase-gate-report.md` for the
>   APPROVED rationale and conditional re-arms.

## StR → REQ-F/REQ-NF Matrix

| StR | REQ-F Children | REQ-NF Children | Total |
|---|---|---|---|
| StR-001 (#1) Supplicant PAE | #11 PAE-001, #12 PAE-002, #13 PAE-003, #14 PAE-004, #15 PAE-005, #16 PAE-006, #17 PAE-007, #18 PAE-008, #44 EAPOL-001, #45 EAPOL-002, #46 EAPOL-003 | #50 PERF-003, #51 PERF-004 | 13 |
| StR-002 (#2) MKA | #19 MKA-001, #20 MKA-002, #21 MKA-003, #22 MKA-004, #23 MKA-005, #24 MKA-006, #25 MKA-007, #26 MKA-008, #27 MKA-009, #28 MKA-010, #37 LOGON-005, #43 EAP-006, #47 EAPOL-004 | #48 PERF-001, #49 PERF-002 | 15 |
| StR-003 (#3) CP | #23 MKA-005*, #24 MKA-006*, #29 CP-001, #30 CP-002, #31 CP-003, #32 CP-004 | — | 6 |
| StR-004 (#4) EAP | #38 EAP-001, #39 EAP-002, #40 EAP-003, #41 EAP-004, #42 EAP-005, #43 EAP-006* | — | 6 |
| StR-005 (#5) Logon | #33 LOGON-001, #34 LOGON-002, #35 LOGON-003, #36 LOGON-004, #37 LOGON-005* | — | 5 |
| StR-006 (#6) Traceability | — | #62 MNT-001, #63 MNT-002, #64 MNT-003, #65 MNT-004, #66 TRC-001, #67 TRC-002 | 6 |
| StR-007 (#7) Linux Deploy | — | #60 PORT-001, #68 DEPLOY-001, #69 DEPLOY-002, #70 DEPLOY-003, #71 DEPLOY-004, #72 DEPLOY-005 | 6 |
| StR-008 (#8) Clean-Room | — | #52 SEC-001, #53 SEC-002, #54 SEC-003, #55 SEC-004, #56 SEC-005 | 5 |
| StR-009 (#9) Lib+Daemon | — | #57 REL-001, #58 REL-002, #61 PORT-002 | 3 |
| StR-010 (#10) Interop | #15 PAE-005*, #45 EAPOL-002* | #59 REL-003 | 3 |

\* Shared REQ — traces to multiple parent StR issues.

**Grand Total**: 10 StR → 62 REQ (37 REQ-F + 25 REQ-NF)

## Cross-Domain REQ Map (REQ tracing to multiple StR)

| REQ | Primary StR | Secondary StR | Rationale |
|---|---|---|---|
| REQ-F-PAE-005 (#15) | StR-001 (#1) | StR-010 (#10) | EAPOL-Start is both a PAE mechanism and an interop observable |
| REQ-F-EAPOL-002 (#45) | StR-001 (#1) | StR-010 (#10) | EAPOL transmission is both a PAE mechanism and interop observable |
| REQ-F-MKA-005 (#23) | StR-002 (#2) | StR-003 (#3) | Cipher suite selection affects both MKA and CP behavior |
| REQ-F-MKA-006 (#24) | StR-002 (#2) | StR-003 (#3) | SAK installation serves both MKA and CP |
| REQ-F-CP-003 (#31) | StR-002 (#2) | StR-003 (#3) | SC/SA management spans MKA and CP |
| REQ-F-LOGON-005 (#37) | StR-002 (#2) | StR-005 (#5) | CAK cache serves both MKA and Logon |
| REQ-F-EAP-006 (#43) | StR-002 (#2) | StR-004 (#4) | EAP key derivation bridges EAP and MKA |
| REQ-NF-TRC-002 (#67) | StR-006 (#6) | StR-008 (#8) | Clause references serve both traceability and clean-room |

## REQ → Code → TEST Chain (Current State, Phase 05 Implementation)

### REQ-F-PAE (Clause 8 — Supplicant PAE)

| REQ | Issue | Closing Commit | Code (file: anchor) | Tests | Status |
|---|---|---|---|---|---|
| REQ-F-PAE-001 PACP State Machine | #11 | `0f18bc3` | `crates/eapol-supp/src/lib.rs`, `crates/eapol-supp/src/supplicant_pae.rs` | 12 unit tests in `supplicant_pae.rs` | Implemented |
| REQ-F-PAE-002 Higher Layer Interface | #12 | `cb54179` | `crates/eapol-supp/src/supplicant_pae.rs` | covered by PACP suite | Implemented |
| REQ-F-PAE-003 Client Interface | #13 | `cb54179` | `crates/eapol-supp/src/supplicant_pae.rs` | covered by PACP suite | Implemented |
| REQ-F-PAE-004 Timers | #14 | `cb54179` | `crates/eapol-supp/src/supplicant_pae.rs` | covered by PACP suite | Implemented |
| REQ-F-PAE-005 EAPOL-Start Tx | #15 | `cb54179` | `crates/eapol-supp/src/supplicant_pae.rs`, `…/transmitter.rs` | covered by PACP + transmitter suites | Implemented |
| REQ-F-PAE-006 EAPOL-Logoff Tx | #16 | `cb54179` | `crates/eapol-supp/src/supplicant_pae.rs`, `…/transmitter.rs` | covered by PACP + transmitter suites | Implemented |
| REQ-F-PAE-007 Retry Control | #17 | `cb54179` | `crates/eapol-supp/src/supplicant_pae.rs` | covered by PACP suite | Implemented |
| REQ-F-PAE-008 PAE Counters | #18 | `cb54179` | `crates/eapol-supp/src/supplicant_pae.rs` | covered by PACP suite | Implemented |

### REQ-F-MKA (Clause 9 — MKA Supplicant Participant)

| REQ | Issue | Closing Commit | Code | Tests | Status |
|---|---|---|---|---|---|
| REQ-F-MKA-001 Key Hierarchy | #19 | `d12487a` | `crates/pae/src/mka.rs`, `crates/pae/src/lib.rs` | 12 tests in `mka.rs` | Implemented |
| REQ-F-MKA-002 MKA Transport (MKPDU) | #20 | `2bb4179`, `cb54179` | `crates/pae/src/mka.rs`, `crates/pae/src/mkpdu.rs` | 12 tests in `mka.rs`, 16 in `mkpdu.rs` | Implemented |
| REQ-F-MKA-003 Peer List Mgmt | #21 | `2bb4179` | `crates/pae/src/mka.rs` | 2 dedicated tests | Implemented |
| REQ-F-MKA-004 Key Server Election | #22 | `2bb4179` | `crates/pae/src/mka.rs` | 1 dedicated test + integration | Implemented |
| REQ-F-MKA-005 Cipher Suite Selection | #23 | `d12487a` | `crates/pae/src/mka.rs` | 2 dedicated tests | Implemented |
| REQ-F-MKA-006 SAK Reception/Install | #24 | `2bb4179` | `crates/pae/src/mka.rs` | 1 dedicated test | Implemented |
| REQ-F-MKA-007 Participant Timer Values | #25 | `2bb4179`, `83bca6f` | `crates/pae/src/timer.rs`, `crates/pae/src/mka.rs` | 8 tests in `timer.rs` | Implemented (canonical-timer fix `83bca6f`) |
| REQ-F-MKA-008 Participant Create/Delete | #26 | `2bb4179` | `crates/pae/src/mka.rs` | 2 dedicated tests | Implemented |
| REQ-F-MKA-009 CAK Identification | #27 | `2141dfd` | `crates/pae/src/mka.rs` | 2 dedicated tests | Implemented |
| REQ-F-MKA-010 Random Number Gen | #28 | `d12487a` | `crates/pae/src/mka.rs` | 1 dedicated test | Implemented |

### REQ-F-CP (Clause 10 — Controlled Port)

| REQ | Issue | Closing Commit | Code | Tests | Status |
|---|---|---|---|---|---|
| REQ-F-CP-001 CP State Machine | #29 | `f56d9c9` | `crates/pae/src/cp.rs` | 15 tests in `cp.rs` | Implemented |
| REQ-F-CP-002 CP Interface | #30 | `9f29dd9` | `crates/pae/src/cp.rs` | 13 tests in `cp.rs` | Implemented |
| REQ-F-CP-003 SC/SA Mgmt | #31 | `76c275a` | `crates/pae/src/cp.rs` | 7 tests in `cp.rs` | Implemented |
| REQ-F-CP-004 MACsec Cipher Suites | #32 | `1385adf` | `crates/pae/src/cp.rs` | 1 dedicated test | Implemented |

### REQ-F-LOGON (Clause 12 — Logon Process)

| REQ | Issue | Closing Commit | Code | Tests | Status |
|---|---|---|---|---|---|
| REQ-F-LOGON-001 Logon State Machine | #33 | `f8adce4` | `crates/logon/src/logon_sm.rs`, `…/lib.rs` | 10 tests in `logon_sm.rs` | Implemented |
| REQ-F-LOGON-002 NID Selection | #34 | `32da118` | `crates/logon/src/nid.rs`, `…/logon_sm.rs` | 4 dedicated tests | Implemented |
| REQ-F-LOGON-003 EAPOL-Announcement Rx | #35 | `2701499`, `cb54179` | `crates/eapol-supp/src/announcement.rs` | 6 tests in `announcement.rs` | Implemented |
| REQ-F-LOGON-004 NID in EAPOL-Start | #36 | `0c7a844` | `crates/eapol-supp/src/frame.rs` | 1 dedicated test | Implemented |
| REQ-F-LOGON-005 CAK Cache | #37 | `cbad4f3` | `crates/logon/src/cak_cache.rs` | 7 tests in `cak_cache.rs` | Implemented |

### REQ-F-EAP (EAP Peer)

| REQ | Issue | Closing Commit | Code | Tests | Status |
|---|---|---|---|---|---|
| REQ-F-EAP-001 EAP Peer Framework | #38 | `3ef5b0b` | `crates/eap-peer/src/peer.rs`, `…/lib.rs` | 26 tests in `peer.rs` | Implemented |
| REQ-F-EAP-002 EAP-TLS | #39 | `b39c99e` | `crates/eap-peer/src/eap_tls.rs` | 12 dedicated tests | Implemented unit + bridge wired (#130 PR #134); **full interop pending #133** (EAP method factory from `EapMethodConfig` + PEM) |
| REQ-F-EAP-003 PEAP | #40 | `ae0d9d2` | `crates/eap-peer/src/eap_peap.rs` | 11 dedicated tests | Implemented unit + bridge wired (#130 PR #134); **full interop pending #133** |
| REQ-F-EAP-004 TEAP | #41 | `9af95f3` | `crates/eap-peer/src/eap_teap.rs` | 12 dedicated tests | Implemented unit + bridge wired (#130 PR #134); **full interop pending #133** |
| REQ-F-EAP-005 Mutual Authentication | #42 | `9a518d6` | `crates/eap-peer/src/peer.rs` | 4 dedicated tests | Implemented |
| REQ-F-EAP-006 Key Derivation for MKA | #43 | `137f9b1`, `628c39e` | `crates/eap-peer/src/key_derivation.rs`, `crates/wpa-supplicant/src/supplicant.rs::try_construct_mka` | 7 dedicated tests + integration in `tests/mka_participant.rs` | Implemented + wired end-to-end (#129 PR #136) |

### REQ-F-EAPOL (Clause 11 — EAPOL Transport)

| REQ | Issue | Closing Commit | Code | Tests | Status |
|---|---|---|---|---|---|
| REQ-F-EAPOL-001 Frame Encode/Decode | #44 | `0f18bc3` | `crates/eapol-supp/src/frame.rs` | dedicated round-trip suite | Implemented |
| REQ-F-EAPOL-002 Frame Tx | #45 | `3a7cd14` | `crates/eapol-supp/src/transmitter.rs` | 6 dedicated tests | Implemented |
| REQ-F-EAPOL-003 Frame Rx | #46 | `06c35bf` | `crates/eapol-supp/src/receiver.rs` | 8 dedicated tests | Implemented |
| REQ-F-EAPOL-004 MKPDU Format | #47 | `7f478a4` | `crates/pae/src/mkpdu.rs` | 16 dedicated tests | Implemented |

### REQ-NF (Performance)

| REQ | Issue | Closing Commit | Code | Tests | Status |
|---|---|---|---|---|---|
| REQ-NF-PERF-001 MKA Hello Interval (2 s) | #48 | `7c2f118`, `83bca6f` | `crates/pae/src/timer.rs`, `crates/pae/src/mka.rs` | 4 perf tests in `timer.rs` (1 `#[ignore]`) | Implemented + perf-validated |
| REQ-NF-PERF-002 MKA Life Time (6 s) | #49 | `b1b6b99` | `crates/pae/src/timer.rs`, `crates/pae/src/mka.rs` | 4 dedicated tests (1 `#[ignore]`) | Implemented + perf-validated |
| REQ-NF-PERF-003 EAPOL Response Latency | #50 | `ebf6322` | `crates/eapol-supp/src/supplicant_pae.rs` | 4 perf tests (4 `#[ignore]`) | Implemented + perf-validated |
| REQ-NF-PERF-004 State Machine Transition Latency | #51 | `470a222` | `crates/pae/src/cp.rs`, `crates/pae/src/mka.rs` | 4 perf tests (3 `#[ignore]`) | Implemented + perf-validated |
| QA-SC-PERF-001 MKA Hello Under Load | #86 | `54c88cb` | `crates/pae/src/mka.rs` | covered by PERF-001 perf suite | Implemented |

### REQ-NF (Security — Governance, satisfied by code-base posture + CI)

| REQ | Issue | Closing Commit | Evidence | Tests / Gates | Status |
|---|---|---|---|---|---|
| REQ-NF-SEC-001 No Unsafe w/o Justification | #52 | (governance) | 19 `unsafe` blocks, all in the documented allowlist (`systemd.rs`, `raw_socket.rs`), each with a `// SAFETY:` comment | `unsafe-discipline` CI job: `scripts/check_unsafe_safety.py` (allowlist + SAFETY-adjacency hard gate) + `cargo geiger` totals (#141) | Implemented + CI-gated (#141) |
| REQ-NF-SEC-002 No `unwrap()` in production | #53 | (governance) | 0 un-justified `.unwrap()`/`.expect()` in production. Each crate root enables `clippy::unwrap_used` + `clippy::expect_used` at `warn`; CI fails on any new occurrence (`cargo clippy --workspace --all-features --all-targets -- -D warnings`). Test modules exempt via `#![cfg_attr(test, allow(...))]`. 2 fatal-init `.expect()` in `main.rs` allow-listed with justification (#144). | clippy `-D warnings` gate (CI) | Implemented + CI-gated (#144) |
| REQ-NF-SEC-003 Secret Zeroization | #54 | (governance) | `zeroize::Zeroize` applied to CAK/SAK/KEK/ICK material in `crates/pae/src/mka.rs`; `Zeroizing<Vec<u8>>` on `TlsClientConfig::private_key` in `crates/eap-peer/src/peer.rs` (#152); `Psk` newtype with `Zeroizing<String>` + redacting `Debug` on `MacsecConfig::psk` in `crates/wpa-supplicant/src/config.rs` (#151) | review gate | Implemented |
| REQ-NF-SEC-004 Clean-Room Compliance | #55 | (governance) | No copyrighted text reproduced; clause references only. **Phase 07 verification record landed at `07-verification-validation/clean-room-review.md` (this PR)** with 35/35 production source files carrying the explicit clean-room disclaimer. | manual code review | Implemented + V&V record landed |
| REQ-NF-SEC-005 No Copyright Reproduction | #56 | (governance) | `CLAUDE.md` rule; clause-number-only doc comments verified across all 16 k LoC | manual review + grep | Implemented |

### REQ-NF (Reliability)

| REQ | Issue | Closing Commit | Code / Evidence | Tests | Status |
|---|---|---|---|---|---|
| REQ-NF-REL-001 No Panics in Library Crates | #57 | (governance) | Library crates return `Result<T,E>` throughout; no `panic!` in `pae`, `eapol-supp`, `eap-peer`, `logon` library paths | covered by full unit suite + fuzz (Phase 07) | Implemented |
| REQ-NF-REL-002 Graceful Error Propagation | #58 | (governance) | `Result` plumbed through all state machine APIs (`SupplicantPae`, `MkaParticipant`, `CpStateMachine`, `LogonProcess`, `EapPeer`) | covered by error-path tests across crates | Implemented |
| REQ-NF-REL-003 Reconnection After Link Flap | #59 | `38e5992` | `crates/wpa-supplicant/src/supplicant.rs` reconnection logic | 5 dedicated tests in `supplicant.rs` | Implemented |

### REQ-NF (Portability)

| REQ | Issue | Closing Commit | Code / Evidence | Gates | Status |
|---|---|---|---|---|---|
| REQ-NF-PORT-001 Linux x86_64 + ARM64 | #60 | `f1ad186` | `.github/workflows/ci.yml` `build-aarch64` job cross-compiles every library + binary | CI gate | Implemented |
| REQ-NF-PORT-002 `no_std` Capability | #61 | `89991dd` | `crates/pae` builds `--no-default-features` and `--no-default-features --features macsec`; `Error` type avoids `thiserror` under `no_std` | CI gate (recommended addition) | Implemented |

### REQ-NF (Maintainability — Governance via tooling)

| REQ | Issue | Closing Commit | Evidence | Gates | Status |
|---|---|---|---|---|---|
| REQ-NF-MNT-001 Test Coverage ≥ 80% | #62 | (governance) | 418 tests; per-crate line coverage all ≥ 80% (pae 88.1%, eapol-supp 88.1%, eap-peer 86.6%, logon 94.4%, wpa-supplicant 84.5%) — see `docs/TESTING.md` | `coverage` CI job: `cargo llvm-cov` + `scripts/check_coverage.py` per-crate gate (#139) | Implemented + CI-gated (#139) |
| REQ-NF-MNT-002 Public API Documentation | #63 | (governance) | All public items carry `///` doc comments; `cargo doc --workspace --no-deps` clean | manual review | Implemented |
| REQ-NF-MNT-003 Clippy Clean | #64 | (governance) `20ac334`, `826ad8a` | `cargo clippy --workspace --all-targets -- -D warnings` passes; CI enforces | CI gate | Implemented |
| REQ-NF-MNT-004 Format Compliant | #65 | (governance) | `cargo fmt --all -- --check` passes; CI enforces | CI gate | Implemented |

### REQ-NF (Traceability — Governance)

| REQ | Issue | Closing Commit | Evidence | Status |
|---|---|---|---|---|
| REQ-NF-TRC-001 Bidirectional Traceability | #66 | (governance) | This matrix; `Implements:` / `Verifies:` doc-comment anchors throughout the workspace | Implemented (this document is the artifact) |
| REQ-NF-TRC-002 Clause Reference in Doc Comments | #67 | (governance) `da61820` | Module-level doc comments cite IEEE 802.1X-2020 clauses by number across `pae`, `eapol-supp`, `eap-peer`, `logon` | Implemented |

### REQ-NF (Deployment — wpa-supplicant binary)

| REQ | Issue | Closing Commit | Code | Tests | Status |
|---|---|---|---|---|---|
| REQ-NF-DEPLOY-001 Structured Logging | #68 | `f08c297` | `crates/wpa-supplicant/src/logging.rs` | 3 dedicated tests | Implemented |
| REQ-NF-DEPLOY-002 Graceful Shutdown | #69 | `9092fef` | `crates/wpa-supplicant/src/shutdown.rs` | 6 dedicated tests | Implemented |
| REQ-NF-DEPLOY-003 TOML Configuration | #70 | (config landing commit) | `crates/wpa-supplicant/src/config.rs`, `…/main.rs` | 12 tests in `config.rs` | Implemented |
| REQ-NF-DEPLOY-004 systemd Integration | #71 | `51637ad` (impl); #154 (security hardening — LISTEN_PID validation + bounds-check) | `crates/wpa-supplicant/src/systemd.rs` (feature-gated) | 9 dedicated tests | Implemented |
| REQ-NF-DEPLOY-005 Unix Domain Socket Control | #72 | `d99d446` (impl); #150 (security hardening) | `crates/wpa-supplicant/src/control.rs` | 17 dedicated tests | Implemented |

## Implementation Summary

| Crate | LoC | Tests | Ignored (perf) | REQs satisfied (in part or whole) |
|---|---:|---:|---:|---|
| `pae` | 6 517 | 172 | 8 | 10 REQ-F-MKA, 4 REQ-F-CP, 1 REQ-F-EAPOL, 4 REQ-NF-PERF, REQ-NF-PORT-002, REQ-NF-SEC-003 |
| `eapol-supp` | 2 546 | 68 | 4 | 8 REQ-F-PAE, 4 REQ-F-EAPOL, REQ-F-LOGON-003, REQ-F-LOGON-004, REQ-NF-PERF-003 |
| `eap-peer` | 3 663 | 75 | 0 | 6 REQ-F-EAP |
| `logon` | 1 252 | 28 | 0 | REQ-F-LOGON-001/002/005 |
| `wpa-supplicant` (bin) | 2 087 | 50 | 0 | 5 REQ-NF-DEPLOY, REQ-NF-REL-003 |
| **Total** | **16 065** | **393** | **12** | 37 REQ-F + 25 REQ-NF |

## Bidirectional Validation Results

| Check | Result |
|---|---|
| All 62 REQ issues trace upward to parent StR | PASS — 62/62 `Traces to` links intact |
| All 10 StR issues trace downward to child REQ | PASS — 10/10 `Refined by` links intact |
| Upward and downward links are consistent | PASS — all 10 StR sets match exactly |
| No orphaned REQ (no parent StR) | PASS — 0 orphans |
| No empty StR (no child REQ) | PASS — 0 empty |
| Cross-domain REQ multi-parent consistency | PASS — 8 cross-domain REQs correctly link to all parents |
| Every REQ-F has at least one `#[test]` verifying it | PASS — see per-domain tables above |
| Every closed REQ-F maps to at least one closing commit | PASS — 37/37 |
| Every closed REQ-NF has either a closing commit or a documented governance gate | PASS — 25/25 |
| No code module without an `Implements:` anchor for the REQ it satisfies | PASS for `pae`, `eapol-supp`, `eap-peer`, `logon`, `wpa-supplicant` modules listed above |
| No `unsafe` block without `// SAFETY:` comment | PASS — 1 documented `unsafe` (`crates/wpa-supplicant/src/systemd.rs:40-42`) |

## Gap Analysis

### Closed Gaps (resolved since 2026-05-17 edition)

| Item | Resolution |
|---|---|
| All 6 domain rows showed *Code Status: Stub* | Per-REQ status now reflects Phase 05 implementation (see tables above) |
| 0 PRs / commits linked from matrix | Closing commit hashes now embedded per REQ |
| 0 `Implements:` doc comments recorded | 200+ `Implements:` anchors enumerated by grep, summarized per file |
| 0 `Verifies:` doc comments recorded | 90+ `Verifies:` anchors enumerated by grep, summarized per file |
| StR-007 child REQ coverage low | Resolved in prior edition; 5 REQ-NF-DEPLOY (#68–#72) all implemented |
| Phase 06 integration TODO markers in `wpa-supplicant` | All 9 INT-NNN landed (Phase 06 close 2026-06-06); see `06-integration/phase-gate-report.md` |
| RawSocketNetworkIo / `NoopNetworkIo` stub in prod | #128 landed (PR #132) — real `AF_PACKET / SOCK_RAW` backend behind `raw-socket` feature |
| MkaParticipant not constructed on Supplicant | #129 landed (PR #136) — `MkaParticipantAdapter` + lazy construction in `tick()` |
| `pae_eap_success` integration shim still present | #130 landed (PR #134) — EAP-peer→PAE bridge replaces the shim; inbound EAP-Success packets route through `tick()` |
| FreeRADIUS interop harness infrastructure | P3.1 landed (PR #137) — docker-compose + hostapd + cert-gen + CI workflow under `07-verification-validation/interop/` |
| Clean-room verification record (REQ-NF-SEC-004) | This PR — `07-verification-validation/clean-room-review.md` with 35/35 disclaimer coverage |

### Open Gaps (require action)

| Gap | Severity | Description | Action | Tracked in |
|---|---|---|---|---|
| FreeRADIUS interop *handshake* depth | Info | P3.1 harness landed (PR #137) — infra ready; full EAP-TLS / PEAP / TEAP handshake assertions require a method factory loading PEM-based TLS engines from `EapMethodConfig` | Implement #133 (EAP method factory) | #133, `docs/TODO.md` P3.1 |
| MKA SAK install end-to-end | Closed | Adapter wired (#129 PR #136); AES Key Wrap (RFC 3394) for `unwrap_sak` landed in PR #146 (#135). End-to-end wrapped-SAK MKPDU → unwrap → CP→Secured covered by `crates/wpa-supplicant/tests/aes_key_wrap_sak.rs`. | (closed) | #135, PR #146 |
| FreeRADIUS CI auto-trigger | Closed | FreeRADIUS + hostapd now boot cleanly in CI (#138 fixed: `CA_file`→`ca_file`, 2048-bit DH, PEAP `virtual_server`, `radiusd -C` healthcheck, hostapd `eapol_version`/static-IP/arg-order). Workflow stays `workflow_dispatch`-only until #133 enables full handshake assertions | (closed) | #138 |
| CI coverage gate for REQ-NF-MNT-001 | Closed | `coverage` CI job runs `cargo llvm-cov --workspace --lcov` + `scripts/check_coverage.py` per-crate 80% gate; HTML report uploaded as artifact. Baselines in `docs/TESTING.md` | (closed) | #139 (TEST-VV-001) |
| CI `cargo audit` / `cargo deny` gates | Closed | Supply-chain CI gate landed: `supply-chain` job in `.github/workflows/ci.yml` runs `cargo audit --deny warnings` + `cargo deny --all-features check`. Policy at `deny.toml`. Public summary at `docs/SECURITY.md`. | (closed) | #140 (TEST-VV-002), `docs/TODO.md` P5.2 |
| CI `cargo geiger` gate for REQ-NF-SEC-001 | Closed | `unsafe-discipline` CI job runs `scripts/check_unsafe_safety.py` (allowlist + `// SAFETY:` adjacency hard gate) + `cargo geiger` totals (informational) | (closed) | #141 (TEST-VV-003) |
| CI `no_std` build gate for REQ-NF-PORT-002 | Low | `pae --no-default-features` builds locally; no CI step | Add to `.github/workflows/ci.yml` | #142 (TEST-VV-004) |
| Fuzz harness for REQ-NF-REL-001/002 | Medium | Three decoders (`EapolFrame`, `EapPacket`, `Mkpdu`) have no fuzz coverage | Add `cargo fuzz` targets | #143 (TEST-VV-005) |
| `clippy::unwrap_used` not enabled | Closed | `clippy::unwrap_used` + `clippy::expect_used` enabled at `warn` in every crate root; CI `--all-features --all-targets -D warnings` enforces; 3 prior `Mutex::lock().unwrap()` residuals eliminated, `main.rs` fatal-init `.expect()` allow-listed | (closed) | #144 (TEST-VV-006) |
| Security review of recent feature batch | Medium | `/security-review` overdue for #37, #50, #51, #59, #68–#72, #86 | Run `SKILL/prompts/security-review.prompt.md` | `docs/TODO.md` P5.1 |

## IEEE 802.1X-2020 Clause Coverage

| Clause | REQ-F Coverage | Implementation Location |
|---|---|---|
| Clause 8 (Supplicant PAE) | 8 REQ-F-PAE + 3 REQ-F-EAPOL + 2 REQ-NF | `crates/eapol-supp/` |
| Clause 9 (MKA) | 10 REQ-F-MKA + 1 REQ-F-EAPOL (MKPDU) + 2 REQ-NF | `crates/pae/src/mka.rs`, `…/mkpdu.rs`, `…/timer.rs` |
| Clause 10 (CP) | 4 REQ-F-CP | `crates/pae/src/cp.rs` |
| Clause 11 (EAPOL) | 4 REQ-F-EAPOL | `crates/eapol-supp/src/frame.rs`, `…/transmitter.rs`, `…/receiver.rs`, `…/announcement.rs` |
| Clause 12 (Logon) | 5 REQ-F-LOGON | `crates/logon/`, `crates/eapol-supp/src/announcement.rs`, `…/frame.rs` |
| Clause 6.2 (Key Hierarchy) | Covered by REQ-F-MKA-001 + REQ-F-EAP-006 | `crates/pae/src/mka.rs`, `crates/eap-peer/src/key_derivation.rs` |
| EAP RFCs (5216, 7170, etc.) | 6 REQ-F-EAP | `crates/eap-peer/` |

**All in-scope supplicant clauses have at least one implemented crate module. No clause gaps.**
