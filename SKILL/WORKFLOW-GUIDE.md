# SKILL Command Workflow Guide

This guide shows the exact sequence and conditions for invoking each slash command throughout the project lifecycle.

## Lifecycle Overview

```
Phase 01          Phase 02          Phase 03          Phase 04          Phase 05
Stakeholder  →    System       →   Architecture →   Detailed     →    Implementation
Requirements      Requirements      Design            Design            (TDD)

/project-kickoff  /requirements-    /architecture-    (design docs)     /tdd-compile
                   elicit            starter
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

## Detailed Command Sequence

### Phase 01: Stakeholder Requirements

```
Step 1:  /project-kickoff
         │
         │  What happens: I ask discovery questions about stakeholders,
         │  business context, constraints, and success criteria.
         │  You answer. I create StR issues and docs in 01-stakeholder-requirements/.
         │
Step 2:  /phase-gate-check
         │
         │  Condition: When you think Phase 01 is complete.
         │  What happens: I verify all exit criteria are met.
         │
         ├─ If APPROVED → proceed to Phase 02
         └─ If REJECTED → I tell you what's missing, fix it, then re-run
```

### Phase 02: System Requirements

```
Step 3:  /requirements-elicit
         │
         │  What happens: I analyze IEEE 802.1X-2020 clauses (supplicant-only),
         │  identify gaps vs. wpa_supplicant, and create REQ-F/REQ-NF issues
         │  with acceptance criteria. Docs go in 02-requirements/.
         │
Step 4:  /requirements-validate
         │
         │  Condition: After elicitation, before gate check.
         │  What happens: I check correctness, completeness, testability,
         │  traceability, and ubiquitous language compliance.
         │
         │  If issues found → fix them, then re-run /requirements-validate
         │
Step 5:  /traceability-builder
         │
         │  Condition: After validation passes, to verify StR → REQ links.
         │  What happens: I build the traceability matrix, find orphans and gaps.
         │
         │  If gaps found → create missing links, then re-run
         │
Step 6:  /phase-gate-check
         │
         ├─ If APPROVED → proceed to Phase 03
         └─ If REJECTED → fix what's missing, re-run
```

### Phase 03: Architecture Design

```
Step 7:  /architecture-starter
         │
         │  What happens: I define workspace crate architecture, create ADRs,
         │  quality scenarios, and crate boundary docs. Docs go in 03-architecture/.
         │
Step 8:  /phase-gate-check
         │
         ├─ If APPROVED → proceed to Phase 04
         └─ If REJECTED → fix what's missing, re-run
```

### Phase 04: Detailed Design

```
Step 9:  (no slash command — design docs are created directly)
         │
         │  Tell me: "design the <component> component"
         │  I reference the Architecture Strategist agent and Phase 04 instructions.
         │  I create trait interfaces, struct layouts, enum definitions.
         │  Docs go in 04-design/.
         │
Step 10: /phase-gate-check
         │
         ├─ If APPROVED → proceed to Phase 05
         └─ If REJECTED → fix what's missing, re-run
```

### Phase 05: Implementation (TDD)

```
Step 11: /tdd-compile
         │
         │  What happens: I execute a Red-Green-Refactor cycle for one requirement.
         │  1. I write a failing test (Red)
         │  2. I write minimal code to pass (Green)
         │  3. I refactor while tests stay green (Refactor)
         │
         │  Repeat /tdd-compile for each REQ-F requirement.
         │
Step 12: /corrective-action-loop
         │
         │  Condition: When cargo test fails or CI breaks.
         │  What happens: I identify the failure, find root cause, fix it
         │  (without modifying the test to hide the failure), verify green.
         │
         │  Run this ANY TIME tests break — don't skip it.
         │
Step 13: /security-review
         │
         │  Condition: After implementing security-sensitive code (MKA, EAP,
         │  key derivation, credential handling).
         │  What happens: I audit unsafe blocks, unwrap(), secret handling,
         │  run cargo audit, review protocol-level security.
         │
Step 14: /phase-gate-check
         │
         ├─ If APPROVED → proceed to Phase 06
         └─ If REJECTED → fix what's missing, re-run
```

### Phase 06: Integration

```
Step 15: /tdd-compile
         │
         │  Condition: When integrating crates together.
         │  I write integration tests that cross crate boundaries.
         │
Step 16: /corrective-action-loop
         │
         │  Condition: When cross-crate integration breaks.
         │
Step 17: /phase-gate-check
         │
         ├─ If APPROVED → proceed to Phase 07
         └─ If REJECTED → fix what's missing, re-run
```

### Phase 07: Verification & Validation

```
Step 18: /test-validate
         │
         │  What happens: I run cargo test --workspace, check coverage,
         │  validate test-to-requirement traceability, find gaps.
         │
Step 19: /traceability-builder
         │
         │  Condition: After test validation, to verify full StR → REQ → Code → TEST chain.
         │
Step 20: /security-review
         │
         │  Condition: Final security audit before release.
         │
Step 21: /phase-gate-check
         │
         ├─ If APPROVED → proceed to Phase 08
         └─ If REJECTED → fix what's missing, re-run
```

### Phase 08-09: Transition & Maintenance

```
Step 22: (release prep — cargo build --release, cargo audit, cargo doc)

Step 23: /phase-gate-check  (Phase 08 exit)

Step 24: Ongoing — use these commands any time during maintenance:
         /corrective-action-loop  → fix bugs
         /security-review         → audit new code
         /tdd-compile             → add features
         /test-validate           → check coverage
```

## Cross-Phase Commands

These can be called at ANY time, in ANY phase:

| Command | When to call it |
|---|---|
| `/security-review` | After writing crypto/key/credential code. Before release. When adding new dependencies. |
| `/corrective-action-loop` | Whenever `cargo test` fails. Whenever CI breaks. Never skip — always fix root cause. |
| `/traceability-builder` | After creating new issues. Before phase gate checks. When you suspect orphaned requirements. |
| `/phase-gate-check` | At the end of every phase. Before transitioning to the next phase. |

## Quick-Start: Starting the Project Right Now

```
1.  /project-kickoff          ← Start here
2.  /phase-gate-check         ← When discovery feels complete
3.  /requirements-elicit      ← Move to Phase 02
4.  /requirements-validate    ← Check quality
5.  /traceability-builder     ← Verify links
6.  /phase-gate-check         ← When requirements are solid
7.  /architecture-starter     ← Move to Phase 03
8.  ... and so on
```
