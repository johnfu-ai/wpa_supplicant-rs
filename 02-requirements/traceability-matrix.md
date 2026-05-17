# Traceability Matrix

ISO/IEC/IEEE 29148:2018 — Bidirectional Traceability Report
Project: IEEE 802.1X-2020 Rust Supplicant
Date: 2026-05-17

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

## REQ → Code → TEST Chain (Current State)

| REQ Domain | REQ-F Count | Code Crate | Code Status | ADR Issues | TEST Issues |
|---|---|---|---|---|---|
| PAE (Clause 8) | 8 | `eapol-supp` | Stub — module docs with Clause refs, no implementation | 0 | 0 |
| MKA (Clause 9) | 10 | `pae` | Stub — module docs with Clause refs, no implementation | 0 | 0 |
| CP (Clause 10) | 4 | `pae` | Stub — module docs with Clause refs, no implementation | 0 | 0 |
| Logon (Clause 12) | 5 | `logon` | Stub — module docs with Clause refs, no implementation | 0 | 0 |
| EAP | 6 | `eap-peer` | Stub — module structure only | 0 | 0 |
| EAPOL (Clause 11) | 4 | `eapol-supp` | Stub — frame module only | 0 | 0 |

## Bidirectional Validation Results

| Check | Result |
|---|---|
| All 62 REQ issues trace upward to parent StR | PASS — 62/62 have `Traces to` links |
| All 10 StR issues trace downward to child REQ | PASS — 10/10 have `Refined by` links |
| Upward and downward links are consistent | PASS — all 10 StR sets match exactly |
| No orphaned REQ (no parent StR) | PASS — 0 orphans |
| No empty StR (no child REQ) | PASS — 0 empty |
| Cross-domain REQ multi-parent consistency | PASS — 8 cross-domain REQs correctly link to all parents |
| Circular references | PASS — no cycles (StR → REQ is a DAG) |

## Gap Analysis

### Current Phase Gaps (Expected — Phase 02 just completed)

| Gap | Status | Expected Resolution |
|---|---|---|
| 0 ADR issues | Expected | Phase 03: Architecture Design will create ADRs linked to REQs |
| 0 TEST issues | Expected | Phase 07: V&V will create TESTs linked to REQs |
| 0 PRs with implementation | Expected | Phase 05: Implementation will create PRs linked to issues |
| 0 `Implements:` doc comments in code | Expected | Phase 05 will add these during implementation |
| 0 `Verifies:` doc comments in tests | Expected | Phase 05/07 will add these during TDD |
| Clause references in code (13 found) | Partial | Existing stubs have clause refs; implementation will expand |

### Structural Gaps (Require Action)

| Gap | Severity | Description | Action |
|---|---|---|---|
| StR-007 (#7) child REQ coverage | ~~Low~~ RESOLVED | ~~Production deployment had only REQ-NF-PORT-001~~ Added 5 REQ-NF-DEPLOY (#68–#72): structured logging, graceful shutdown, TOML config, systemd integration, D-Bus/socket control interface. StR-007 now has 6 child REQs | Done — issues #68–#72 created and linked |
| REQ-F-EAP-002/003/004 verification requires FreeRADIUS | Info | EAP method integration tests need external dependency | Plan interop test infrastructure in Phase 07 |
| REQ-NF-SEC-004 (clean-room) is manual-only | Info | Cannot be fully automated | Acknowledged; code review gate |

## IEEE 802.1X-2020 Clause Coverage

| Clause | REQ-F Coverage | Notes |
|---|---|---|
| Clause 8 (Supplicant PAE) | 8 REQ-F-PAE + 3 REQ-F-EAPOL + 2 REQ-NF | Full supplicant-side coverage |
| Clause 9 (MKA) | 10 REQ-F-MKA + 1 REQ-F-EAPOL + 2 REQ-NF | Full supplicant participant coverage |
| Clause 10 (CP) | 4 REQ-F-CP | Full supplicant-side coverage |
| Clause 11 (EAPOL) | 4 REQ-F-EAPOL | Frame format and transport coverage |
| Clause 12 (Logon) | 5 REQ-F-LOGON | NID selection and CAK cache |
| Clause 6.2 (Key Hierarchy) | Covered by REQ-F-MKA-001 | KDF and key derivation |
| EAP RFCs | 6 REQ-F-EAP | TLS, PEAP, TEAP, framework |

**All relevant supplicant clauses covered. No gaps in clause coverage.**
