# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Companion file:** `AGENTS.md` (Codex / other coding agents — defers to this file).
> **Long-form workflow:** `SKILL/WORKFLOW-GUIDE.md`.
> **Live work state:** `docs/TODO.md` (always read this first), then `docs/PROGRESS.md`.

---

## 1. What this repo is

`wpa_supplicant-rs` is a clean-room **IEEE 802.1X-2020 supplicant** in Rust — supplicant role only, no Authenticator PAE, no AP-side logic. It is a Cargo workspace of five crates plus nine lifecycle-phase directories that hold the ISO/IEC/IEEE 12207 / 29148 / 1016 / 42010 / 1012 evidence. Phases 01–08 are gate-approved (Phase 08 Transition closed 2026-06-13 with `08-transition/phase-gate-report.md`; 418 passing unit/integration tests + 12 `#[ignore]` wall-clock perf tests across 5 crates). **Phase 09 (Operation & Maintenance) is the active frontier** — the security-review hardening batch (#150–#155) landed 2026-06-21; the open backlog is the TEST-VV coverage gaps #139 / #141–#144, carry-forwards #133 (EAP method factory) and #138 (FreeRADIUS CI debug), plus the deferred YANG/NETCONF management-surface ADR. The Phase 06 INT-NNN integration TODOs all landed (#118–#126); the operator-facing entry point for Phase 09 work is `09-operation-maintenance/runbook.md`.

## 2. Build, test, lint

```bash
cargo build --workspace                          # Build all crates
cargo build -p <crate>                           # Build a single crate
cargo test  --workspace                          # Run all tests (418 unit/integration + 12 #[ignore] perf)
cargo test  -p <crate>                           # Run tests for a single crate
cargo test  <test_name>                          # Run a single test by name (substring match)
cargo test  --workspace -- --ignored             # Include wall-clock perf tests (a90c033)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt   --all -- --check
cargo doc   --workspace --no-deps
cargo deny  check                                # Supply-chain gate (advisories, licenses, bans, sources) — CI gates this
```

No-std variants (`pae` only — REQ-NF-PORT-002):
```bash
cargo build -p pae --no-default-features
cargo build -p pae --no-default-features --features macsec
```

Cross-build for aarch64 (REQ-NF-PORT-001; see `.github/workflows/ci.yml`):
```bash
cargo build -p <crate> --target aarch64-unknown-linux-gnu
```

**Local auto-lint hook.** `.claude/settings.json` installs a `PostToolUse` hook on Edit/Write/MultiEdit: every time you touch `crates/<c>/src/**.rs` or `crates/<c>/tests/**.rs`, the hook runs `cargo fmt -p <c>` then `cargo clippy -p <c> --no-deps -- -D warnings`. Per-crate lint will fire on save — design edits so the crate stays clippy-clean.

## 3. Workspace map — crate → IEEE clause → key public types

```
                  ┌────────────────────────────────────────────┐
                  │             wpa-supplicant (bin)           │
                  │  Supplicant · Config · ControlInterface     │
                  │  NetworkIo · SupplicantState                │
                  └───────┬──────────┬──────────┬──────────┬───┘
                          ▼          ▼          ▼          ▼
                     eapol-supp   eap-peer    logon       pae
                          │          │          │          ▲
                          └──────────┴──────────┴──────────┘
                                       depends on
```

| Crate | IEEE / RFC | Key public types | Notes |
|---|---|---|---|
| `pae` | 802.1X-2020 Clauses 9–10 | `MkaParticipant`, `CpStateMachine`, `TimerWheel`, `Sak`, `Sci`, `PaeError`, `Rng` trait | Holds the shared `PaeError` re-exported by upstream crates. `no_std`-capable. Canonical MKA timer constants (Hello 2 000 ms / Life 6 000 ms / SAK-Retire 3 000 ms) — committed `83bca6f`. |
| `eapol-supp` | 802.1X-2020 Clause 8 | `SupplicantPae`, `EapolFrame`, `EapolReceiver`, `EapolTransmitter`, `EapolError` | EAPOL frame encode/decode + EAPOL-Announcement consumer (`announcement.rs`). |
| `eap-peer` | RFC 3748 / 5247 | `EapPeer`, `EapMethod` trait, `eap_tls` / `eap_peap` / `eap_teap` modules | Methods are feature-gated per ADR-FF-006 (#78); `default = ["eap-tls"]`. |
| `logon` | 802.1X-2020 Clause 12 | `LogonProcess`, `NidGroup`, `CakCache` | NID-based network selection; NID-in-EAPOL-Start lives in `eapol-supp/src/frame.rs`. |
| `wpa-supplicant` | — (top-level binary) | `Supplicant`, `Config`, `ControlInterface`, `NetworkIo`, `SupplicantState`, `ControlCommand` | Where the 12 INT-NNN integration TODOs live (`supplicant.rs`, `main.rs`). |

## 4. The SKILL workflow — start every task here

This repo is **issue-driven and standards-traceable**. Every PR title is `<type>: <subject> per <REQ-ID> (#<issue>)`; every PR description carries `Fixes #N` or `Implements #N`. The full sequence is in `SKILL/WORKFLOW-GUIDE.md` — short reference:

| Skill / slash command | When |
|---|---|
| `/project-kickoff` | Phase 01 — only when standing up a new system |
| `/requirements-elicit`, `/requirements-validate` | Phase 02 — new REQ-F / REQ-NF |
| `/architecture-starter` | Phase 03 — new ADR / ARC-C / QA-SC |
| `/design-starter` | Phase 04 — detailed design |
| **`/tdd-compile`** | **Phase 05 / 06 — use this whenever you start any code task** |
| `/test-validate` | Phase 07 — V&V, coverage, find REQ→TEST gaps |
| `/security-review` | Any time after writing crypto / key / credential code |
| `/corrective-action-loop` | Any time `cargo test` fails or CI breaks — root-cause, never silence |
| `/traceability-builder` | After creating issues, before phase gates, after refactors |
| `/phase-gate-check` | End of every phase |

Invoke a skill via the `Skill` tool (`skill: tdd-compile`) — its prompt file lives at `SKILL/prompts/tdd-compile.prompt.md`. The matching role profile lives at `SKILL/agents/tdd-driver.md`.

## 5. TDD is non-negotiable when implementing code

When starting **any** code task — Phase 09 maintenance fix, follow-up to a security tracker, or a TEST-VV coverage backfill — follow the project TDD path:

1. Invoke `Skill` with `skill: tdd-compile` (or read `SKILL/prompts/tdd-compile.prompt.md` directly and follow its body).
2. Adopt the `SKILL/agents/tdd-driver.md` profile.
3. **Red** — write the failing test first (`cargo test` must fail for the right reason).
4. **Green** — write the minimal production code to pass it.
5. **Refactor** — improve design while every test stays green.
6. Integration tests for cross-crate seams (Phase 06) live in `crates/wpa-supplicant/tests/`.

Failing tests are fixed by root-cause via `/corrective-action-loop` — **never modify a test to silence a failure**. See `SKILL/instructions/root.instructions.md:431` ("Never write code BEFORE writing a failing test").

## 6. Per-task close-out ritual

After finishing **any** unit of work, run this checklist before moving on:

1. **Green build locally**
   - `cargo test --workspace`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo fmt --all -- --check`
2. **Commit** with the canonical format: `<type>: <subject> per <REQ-ID> (#<issue>)` (e.g. `feat(integration): wire EAPOL dispatch per INT-002 (#117)`).
3. **Push and open / update the PR** with `gh pr create` / `gh pr edit`. The PR description must include `Fixes #<issue>` (or `Implements #<issue>` if the issue stays open as a tracking anchor). Before opening, invoke the local subagent `ieee-traceability-reviewer` (and, when MKA / CP / PAE timing changed, `mka-timing-auditor`).
4. **Merge the PR yourself — no human round-trip required.** This is a solo-developer repo with no branch protection and no required reviewers (verified 2026-06-06). After opening the PR:
   - Wait for CI to finish: `gh pr checks <NN> --watch` (both `Test (x86_64)` and `Cross-build (aarch64)` must pass).
   - Confirm `gh pr view <NN> --json mergeable,mergeStateStatus` returns `MERGEABLE` / `CLEAN`. If state is `BEHIND`, run `gh pr update-branch <NN>` and re-wait. If state is `DIRTY` (conflicts), **stop and surface to the user** — do not attempt automated conflict resolution.
   - Squash-merge and delete the branch in one shot:
     ```bash
     gh pr merge <NN> --squash --delete-branch --subject "<PR title> (#<NN>)"
     ```
     Squash is the repo's default merge method (`viewerDefaultMergeMethod: SQUASH`); use it unless the PR is a stacked feature branch that should preserve its commit history.
   - Sync local main: `git checkout main && git pull --ff-only && git branch -D <branch>`.
   - **Do not wait for human approval to merge** — the user has explicitly authorized solo auto-merge (2026-06-06). The only blockers are: failing CI, `MERGEABLE != MERGEABLE`, conflicts (`DIRTY`), or a PR explicitly marked as draft / `WIP`. Anything else, merge.
5. **After the PR lands**:
   - Confirm GitHub auto-closed the linked issue. The `Fixes #N` / `Closes #N` / `Resolves #N` keywords auto-close on merge; `Implements #N` and `Relates to #N` **do not** — if you used those, close manually with `gh issue close <N> --comment "Closed by <merge-sha> (PR #<NN>)."`.
   - If a domain row in `docs/PROGRESS.md` changed (new crate complete, test count materially changed, gate status flipped), refresh it.
   - If a REQ chain in `02-requirements/traceability-matrix.md` gained a closing commit / implementing file / test, refresh that row.
   - Doc refreshes can ride the same PR or land as an immediate follow-up doc PR.
6. **Tick `docs/TODO.md`**: mark the item `[x]` and **move** the entry to the *Done* section with the PR number and date — the living-document rule at `docs/TODO.md:8`. Do not delete; the trail is audit evidence per `StR-006: Full Audit Trail and Traceability`.
7. **If the task closed a whole phase**: write `0N-<phase-name>/phase-gate-report.md` using `04-design/phase-gate-report.md` as the template, then run `/phase-gate-check`.
8. **Surface newly-discovered work as fresh GitHub issues** — never leave a bare `TODO:` marker in the code without a tracking issue (and update `docs/TODO.md` to reference the new issue).

### When NOT to auto-merge

Skip step 4's automation and ask the user first when:
- A PR review explicitly requests changes (`gh pr view <NN> --json reviewDecision` returns `CHANGES_REQUESTED`).
- The PR is stacked on another open PR (merging the child before the parent rewrites history awkwardly).
- The diff touches `SKILL/`, `.github/workflows/`, or `.claude/settings*.json` — these change the agent's own operating envelope; human eyes first.
- `mergeStateStatus` is `DIRTY`, `BLOCKED`, or `UNSTABLE`. Surface the reason; do not paper over.
- Any CI check fails — root-cause via `/corrective-action-loop`, never `--admin` over a red build.

## 7. Reference materials — sibling repos (read-only)

Both live one level above this project at `/home/john/wpa_rs/`. They are the **only** permitted on-disk sources for IEEE 802.1X-2020 standard text and YANG models.

### `../8021X-2020.md/` — Markdown copy of the standard

- Entry point: `../8021X-2020.md/8021X-2020.md`.
- **Use for:** looking up clause numbers, state machine semantics, frame layouts, MIB attribute names.
- **Do not** copy verbatim text, paraphrase sentences ≥ ~15 words, or reproduce tables/figures into source files. Per `SKILL/instructions/root.instructions.md:450` and `StR-008: Clean-Room Implementation`.
- Doc comments reference clauses by **number only**: `// Per IEEE 802.1X-2020 Clause 8.3`. The `ieee-traceability-reviewer` subagent will flag verbatim prose.

### `../8021X-2020.YANG/` — Official YANG models

- Modules: `ieee802-dot1x.yang`, `ieee802-dot1x-eapol.yang`, `ieee802-dot1x-types.yang`, `ieee802-types.yang` plus IETF/IANA transitive deps (`ietf-interfaces`, `ietf-system`, `ietf-yang-types`, `ietf-inet-types`, `ietf-netconf-acm`, `iana-if-type`, `iana-crypt-hash`).
- **Use for:** deriving canonical field names, modeling the eventual NETCONF / management surface, sanity-checking attribute spellings against the IEEE / RFC source.
- **Scope of YANG consumption inside Rust code** is still an open architectural question — tracked in `docs/TODO.md` P5.3 (open `ADR-MGMT-009: NETCONF/YANG management surface`). Until that ADR lands, treat the YANG repo as reference-only.

## 8. Cross-cutting non-negotiables

- **No `unwrap()` in production code** — use `?`, `expect("reason")`, or proper error handling (`SKILL/instructions/root.instructions.md:447`). Gated workspace-wide: each crate root enables `clippy::unwrap_used` + `clippy::expect_used` at `warn` (CI `-D warnings` fails on any new occurrence); test modules are exempt via `#![cfg_attr(test, allow(...))]` (#144 / TEST-VV-006). The two `main.rs` fatal-init `.expect()` calls are allow-listed with justification.
- **No `unsafe` without a `// SAFETY:` comment** — `unsafe` blocks are confined to an allowlist (`systemd.rs`, `raw_socket.rs`) and must carry a `// SAFETY:` comment within the preceding 10 lines; enforced in CI by `scripts/check_unsafe_safety.py` (#141 / TEST-VV-003, REQ-NF-SEC-001). `cargo geiger` surfaces usage totals.
- **Trait-based dependency injection** for state machines (mockable for tests). Example: `pae::Rng`, `wpa-supplicant::NetworkIo`.
- **Feature-gate optional 802.1X-2020 surface** — `#[cfg(feature = "…")]`. EAP methods in `eap-peer` and `macsec` in `pae` are the canonical examples.
- **Doc comments** cite IEEE clauses; **tests** cite the REQ they exercise (`Verifies: #REQ-F-PAE-001`). New `pub fn` / `pub struct` / `pub trait` / `pub mod` without traceability is a finding.
- **Secret zeroization** — `zeroize::Zeroize` on CAK / SAK / KEK / ICK per ADR-SEC-004 (#76). Already applied in `crates/pae/src/mka.rs`.
- **Ubiquitous language** — use IEEE terms exactly: *Supplicant PAE* (not "client"), *Controlled Port* (not "authenticated port"), *MKA Hello Time* (not "hello timer"), *SAK* / *MSK* (not "session key"). The `ieee-traceability-reviewer` subagent grep-checks for synonyms.

## 9. Local custom subagents (`.claude/agents/`)

Spawn these via the `Agent` tool whenever the trigger conditions hit:

| Subagent | When |
|---|---|
| `ieee-traceability-reviewer` | After **any** change to `crates/**/*.rs`. **Must run before opening a PR.** Checks traceability anchors, crate routing, domain terminology, copyright safety. |
| `mka-timing-auditor` | After changes that touch MKA, CP, or PAE timing in `crates/pae/` or `crates/eapol-supp/`. Audits for hardcoded timers, drifting constants, test sleeps that mask jitter. |

## 10. Where to find things

| Looking for… | Path |
|---|---|
| Live backlog | `docs/TODO.md` |
| Phase + per-domain status roll-up | `docs/PROGRESS.md` |
| REQ-by-REQ traceability matrix | `02-requirements/traceability-matrix.md` |
| Long-form workflow guide | `SKILL/WORKFLOW-GUIDE.md` |
| Root project rules / standards list | `SKILL/instructions/root.instructions.md` |
| Phase-specific instructions | `SKILL/instructions/phase-0N-*.instructions.md` |
| Slash-command prompt bodies | `SKILL/prompts/*.prompt.md` |
| Role-oriented agent profiles | `SKILL/agents/*.md` |
| Per-phase artifacts (StR, REQ, ADR, designs, tests, …) | `0N-<phase-name>/` |
| Latest phase gate report | `0N-<phase-name>/phase-gate-report.md` |
| Operator-facing runbook (Phase 09 entry point) | `09-operation-maintenance/runbook.md` |
| Supply-chain policy (cargo-deny) | `deny.toml` |
| Companion guide for non-Claude agents | `AGENTS.md` |
| IEEE 802.1X-2020 standard (clause numbers only — clean-room) | `../8021X-2020.md/8021X-2020.md` |
| Official YANG models | `../8021X-2020.YANG/` |
| CI workflow | `.github/workflows/ci.yml` |
| Local hook + claude settings | `.claude/settings.json` |
