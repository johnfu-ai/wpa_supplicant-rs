# SKILL Command Workflow Guide

This guide shows the exact sequence and conditions for invoking each slash command throughout the project lifecycle.

**Where we are today (2026-06-06):** Phases 01–04 are gate-approved. Phase 05 (Implementation) is well underway (66 PRs merged with `phase:05-approved`). Phase 06 (Integration) is the active frontier — the per-crate state machines exist but the `wpa-supplicant` binary still has 12 `TODO:` wiring markers. See [`docs/TODO.md`](../docs/TODO.md) for the live backlog.

---

## Lifecycle Overview

```
Phase 01          Phase 02          Phase 03          Phase 04          Phase 05
Stakeholder  →    System       →   Architecture →   Detailed     →    Implementation
Requirements      Requirements      Design            Design            (TDD)

/project-kickoff  /requirements-    /architecture-    /design-          /tdd-compile
                   elicit            starter           starter
                   /requirements-
                   validate

     ↓                ↓                ↓                ↓                ↓
  /phase-gate-     /phase-gate-     /phase-gate-     /phase-gate-     /phase-gate-
   check             check            check            check            check

Phase 06          Phase 07          Phase 08          Phase 09
Integration   →   V&V          →   Transition    →   Maintenance

/corrective-      /test-validate    (release prep)    /corrective-
 action-loop                                           action-loop
                   /security-                         /security-
                   review                              review
                   /traceability-
                   builder
```

---

## Project Conventions Reflected in the Workflow

These conventions are **enforced by the workflow**; every step below assumes them.

| Convention | What it means in practice |
|---|---|
| **Issue-driven** | No code change without a tracking GitHub Issue. ID prefixes: `StR-NNN`, `REQ-F-XXX-NNN`, `REQ-NF-XXX-NNN`, `ADR-XXX-NNN`, `ARC-C-XXX-NNN`, `QA-SC-XXX-NNN`, `TEST-XXX-NNN`, `INT-NNN` (Phase 06 integration). |
| **Phase labels** | Every issue carries `phase:0X-<name>` + `phase:0X-approved` once its gate passes. Closed issues stay searchable via these labels (`gh issue list --label phase:05-approved`). |
| **Commit message format** | `<type>: <subject> per <REQ-ID> (#<issue>)` — e.g. `feat: MKA Hello timing validation per REQ-NF-PERF-001 (#48)`. The REQ-ID + issue number is what `/traceability-builder` greps for. |
| **Gate report file** | Every phase closes with a `phase-gate-report.md` inside its phase directory (template established by `04-design/phase-gate-report.md`). |
| **Traceability anchors stay open** | StR / ADR / ARC-C issues remain open as living parents for trace links — `state:open` does **not** mean "work to do". Use `docs/TODO.md` + `git log` for actual work state. |
| **TDD is non-negotiable** | Red → Green → Refactor. `cargo test` failing tests are surfaced via `/corrective-action-loop`; the test is never modified to hide the failure. |
| **No standard-text reproduction** | Reference IEEE 802.1X-2020 by clause number only (per `StR-008: Clean-Room Implementation`). |

---

## Detailed Command Sequence

### Phase 01: Stakeholder Requirements ✅ DONE

```
Step 1:  /project-kickoff
         │  Discovery → StR issues in 01-stakeholder-requirements/.
         │
Step 2:  /phase-gate-check  →  APPROVED, proceed to Phase 02
```

Status: 10 StR issues (`#1`–`#10`) closed-approved, all labeled `phase:01-stakeholder-requirements`.

---

### Phase 02: System Requirements ✅ DONE

```
Step 3:  /requirements-elicit       → REQ-F / REQ-NF issues + docs in 02-requirements/
Step 4:  /requirements-validate     → correctness / completeness / testability checks
Step 5:  /traceability-builder      → StR → REQ matrix, find orphans
Step 6:  /phase-gate-check          → APPROVED, proceed to Phase 03
```

Status: 37 REQ-F + 25 REQ-NF closed-approved. Matrix at `02-requirements/traceability-matrix.md` (**marked stale** in [`docs/TODO.md` P1.1](../docs/TODO.md) — needs refresh to reflect Phase 05 implementation).

---

### Phase 03: Architecture Design ✅ DONE

```
Step 7:  /architecture-starter      → ADRs, ARC-C component issues, QA-SC quality scenarios
Step 8:  /phase-gate-check          → APPROVED, proceed to Phase 04
```

Status: 8 ADR (`#73`–`#80`) + 5 ARC-C (`#81`–`#85`) + 4 QA-SC closed-approved. ADR/ARC-C issues remain open as living architectural anchors.

---

### Phase 04: Detailed Design ✅ DONE

```
Step 9:  /design-starter            → 04-design/components/, interfaces/, patterns/
Step 10: /phase-gate-check          → APPROVED 2026-05-17, proceed to Phase 05
```

Status: Gate report at `04-design/phase-gate-report.md`. All 37 REQ-F mapped to component designs; 10 trait interfaces consolidated in `04-design/interfaces/trait-interfaces.md`; 5 crate-level error types defined.

---

### Phase 05: Implementation (TDD) 🟡 IN PROGRESS

```
Step 11: /tdd-compile
         │  Red-Green-Refactor for one REQ-F at a time:
         │   1. Failing test (Red)
         │   2. Minimal code to pass (Green)
         │   3. Refactor while green
         │  Each PR closes one REQ-F issue and applies `phase:05-approved`.
         │
Step 12: /corrective-action-loop
         │  Run ANY TIME cargo test fails or CI breaks.
         │  Root-cause the failure; never modify the test to hide it.
         │
Step 13: /security-review
         │  After implementing security-sensitive code
         │  (MKA, EAP, key derivation, credential handling).
         │  Audit unsafe, unwrap(), secret handling; run cargo audit.
         │
Step 14: /phase-gate-check          → when all REQ-F closed AND no Phase-05 work outstanding
```

Status: 66 PRs landed with `phase:05-approved`. Per-crate state machines complete in `pae`, `eapol-supp`, `eap-peer`, `logon`. The `wpa-supplicant` binary has 12 wiring `TODO:`s remaining — those are **Phase 06 work**, not Phase 05 work.

**Security-review backlog:** see [`docs/TODO.md` P5.1](../docs/TODO.md) — `/security-review` is overdue for the recent feature batch (#37, #50, #51, #59, #68–#72, #86).

---

### Phase 06: Integration ⬜ NEXT

This is the **active frontier**. Integration tests cross crate boundaries and live in `crates/wpa-supplicant/tests/`.

```
Step 15: Open the INT-NNN issues
         │  Create the `phase:06-integration` label (color #1D76DB to match other phase labels).
         │  Open one issue per code-level TODO in crates/wpa-supplicant/
         │  (see docs/TODO.md P2.1.1–P2.1.9 for the enumerated list).
         │
Step 16: /tdd-compile  (per INT-NNN issue)
         │  Write an integration test in crates/wpa-supplicant/tests/ first.
         │  Then add the wiring in supplicant.rs / main.rs to make it pass.
         │  Commit format: `feat(integration): <thing> per INT-NNN (#issue)`.
         │
Step 17: /corrective-action-loop
         │  As needed when cross-crate seams break.
         │
Step 18: /traceability-builder
         │  After integration lands — verify INT-NNN → CODE → TEST chain.
         │
Step 19: Write 06-integration/phase-gate-report.md
         │  Use 04-design/phase-gate-report.md as the template.
         │
Step 20: /phase-gate-check          → apply `phase:06-approved`, proceed to Phase 07
```

---

### Phase 07: Verification & Validation ⬜ NOT STARTED

V&V is where conformance + interop happens. The known blocker is FreeRADIUS interop for EAP-TLS/PEAP/TEAP — flagged in `02-requirements/traceability-matrix.md` and tracked in [`docs/TODO.md` P3.1](../docs/TODO.md).

```
Step 21: Stand up interop infrastructure
         │  07-verification-validation/interop/ — FreeRADIUS-in-Docker compose,
         │  gated CI job (likely `-- --ignored` in unit CI).
         │
Step 22: /test-validate
         │  Run cargo test --workspace, check coverage, find REQ→TEST gaps.
         │  Create TEST-XXX-NNN issues for every uncovered REQ.
         │
Step 23: Clean-room verification record (REQ-NF-SEC-004)
         │  Manual code-review artifact in 07-verification-validation/clean-room-review.md.
         │
Step 24: /traceability-builder
         │  Full StR → REQ → ADR/ARC-C → Code → TEST chain, zero orphans.
         │
Step 25: /security-review
         │  Final security audit before release.
         │
Step 26: Write 07-verification-validation/phase-gate-report.md
Step 27: /phase-gate-check          → apply `phase:07-approved`, proceed to Phase 08
```

---

### Phase 08: Transition ⬜ NOT STARTED

```
Step 28: Release packaging plan      → 08-transition/release-plan.md
         │  cargo publish strategy, version pinning, cargo-deny baseline,
         │  deb/rpm scope, signed releases.
         │
Step 29: cargo build --release && cargo audit && cargo doc
Step 30: Write 08-transition/phase-gate-report.md
Step 31: /phase-gate-check           → proceed to Phase 09
```

---

### Phase 09: Operation & Maintenance ⬜ NOT STARTED

```
Step 32: Operator runbook            → 09-operation-maintenance/runbook.md
         │  systemd unit examples, log-level tuning, control-socket usage,
         │  troubleshooting matrix.
         │
Step 33: Ongoing — these commands run any time during maintenance:
         /corrective-action-loop   → fix bugs
         /security-review          → audit new code and new dependencies
         /tdd-compile              → add features
         /test-validate            → check coverage
         /traceability-builder     → re-verify after refactors
```

---

## Cross-Phase Commands

These can be called at ANY time, in ANY phase:

| Command | When to call it |
|---|---|
| `/security-review` | After writing crypto/key/credential code. Before any release. When adding new dependencies. |
| `/corrective-action-loop` | Whenever `cargo test` fails. Whenever CI breaks. Never skip — always fix root cause; never silence the test. |
| `/traceability-builder` | After creating new issues. Before phase gate checks. When you suspect orphaned requirements. After any code refactor that moves modules. |
| `/phase-gate-check` | At the end of every phase. Before transitioning to the next phase. |

---

## Where to Find Things

| Looking for… | Go to… |
|---|---|
| Live backlog / what to do next | [`docs/TODO.md`](../docs/TODO.md) |
| Project root instructions | `SKILL/instructions/root.instructions.md` |
| Phase-specific instructions | `SKILL/instructions/phase-0N-*.instructions.md` |
| Reusable capabilities | `SKILL/skills/` |
| Role-oriented agent profiles | `SKILL/agents/` |
| Actionable workflow prompts | `SKILL/prompts/` (each `.prompt.md` is invoked as a slash command) |
| Per-phase artifacts (StR, REQ, ADR, designs, tests, …) | `0N-<phase-name>/` |
| Latest gate report | `0N-<phase-name>/phase-gate-report.md` |
| Workspace + crate conventions | `../CLAUDE.md` and `../AGENTS.md` (project root) |
| IEEE 802.1X-2020 standard (reference by clause only) | `../../8021X-2020.md/8021X-2020.md` |
| Official YANG models | `../../8021X-2020.YANG/` |

---

## Quick-Start: Picking Up the Project Today

You are joining a project where Phases 01–04 are closed and Phase 05 implementation is mostly done.

```
1.  Read CLAUDE.md (project root) for conventions
2.  Read docs/TODO.md for current work state
3.  Pick the highest-priority unchecked item in TODO.md
4.  If it's a P1 task → run /traceability-builder
    If it's a P2 task → open INT-NNN issue, then run /tdd-compile
    If it's a P3 task → run /test-validate then /traceability-builder
    If it's a P5.1 task → run /security-review
5.  Land the PR with commit format `<type>: <subject> per <ID> (#issue)`
6.  Mark the item [x] in docs/TODO.md and move to the Done section
7.  When a whole phase completes → write phase-gate-report.md → /phase-gate-check
```

---

## Historical Quick-Start (Starting From Scratch)

Kept for reference; not the current path.

```
1.  /project-kickoff          ← Phase 01
2.  /phase-gate-check
3.  /requirements-elicit      ← Phase 02
4.  /requirements-validate
5.  /traceability-builder
6.  /phase-gate-check
7.  /architecture-starter     ← Phase 03
8.  /phase-gate-check
9.  /design-starter           ← Phase 04
10. /phase-gate-check
11. /tdd-compile (loop)       ← Phase 05
12. /corrective-action-loop (as needed)
13. /security-review (after sensitive features)
14. /phase-gate-check
… continue through Phase 06–09 as in the Detailed Command Sequence above
```
