# AGENTS.md

Guidance for **non-Claude-Code** coding agents (Codex, Cursor, Aider, JetBrains AI, etc.) operating in `wpa_supplicant-rs`.

> **Read `CLAUDE.md` first.** It is the canonical agent guide for this repository and applies equally to every coding agent. This file only lists the differences that matter when you are *not* running inside Claude Code.

---

## 1. What this repo is (one paragraph)

`wpa_supplicant-rs` is a clean-room **IEEE 802.1X-2020 supplicant** in Rust — supplicant role only, no Authenticator PAE, no AP-side logic. Cargo workspace of five crates (`pae`, `eapol-supp`, `eap-peer`, `logon`, `wpa-supplicant`) plus nine lifecycle-phase directories holding the ISO/IEC/IEEE 12207 / 29148 / 1016 / 42010 / 1012 evidence. Phases 01–04 are gate-approved; Phase 05 is unit-complete; **Phase 06 (Integration) is the active frontier**. For live work state read `docs/TODO.md` then `docs/PROGRESS.md`.

## 2. Non-Claude-Code differences

| Mechanism | Claude Code | Codex / other agents |
|---|---|---|
| `Skill` tool + slash commands (`/tdd-compile`, `/phase-gate-check`, `/security-review`, …) | Native — invoke via the `Skill` tool. | **Not available.** Open the prompt file directly — e.g. read `SKILL/prompts/tdd-compile.prompt.md` — and follow its body as plain instructions. |
| Local custom subagents (`.claude/agents/ieee-traceability-reviewer.md`, `mka-timing-auditor.md`) | Spawn via the `Agent` tool. | Markdown prompt files. **Read and apply them by hand** for diff reviews — they do not require an agent runtime. |
| `.claude/settings.json` PostToolUse hook (auto `cargo fmt -p <c>` + `cargo clippy -p <c> --no-deps -- -D warnings` on every Rust edit) | Fires automatically. | **Does not fire.** You must run `cargo fmt -p <c>` and `cargo clippy -p <c> -- -D warnings` yourself before declaring a task done. |
| Custom slash command registry under `.claude/commands/` | Claude Code resolves them. | Treat each `.md` file as a runbook you read and execute by hand. |

## 3. The four operating rules (re-stated so you do not have to dig)

These hold for every agent — Claude Code, Codex, or otherwise. The full versions live in `CLAUDE.md` §5–§7.

1. **Reference the standard correctly.** The Markdown copy of IEEE 802.1X-2020 lives at `../8021X-2020.md/8021X-2020.md`; the official YANG models live at `../8021X-2020.YANG/`. Use them for clause lookups and canonical naming. **Never** copy verbatim text, paraphrase sentences ≥ ~15 words, or reproduce tables/figures — clean-room rule per `StR-008` and `SKILL/instructions/root.instructions.md:450`. Doc comments reference clauses by number only (`// Per IEEE 802.1X-2020 Clause 8.3`).
2. **Start every code task with TDD.** Read `SKILL/prompts/tdd-compile.prompt.md` and adopt `SKILL/agents/tdd-driver.md`. Red → Green → Refactor; the failing test exists *before* the production code. Never silence a failing test.
3. **Close out every task with the full ritual.**
   - `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check` all green.
   - Commit format: `<type>: <subject> per <REQ-ID> (#<issue>)`.
   - Push to a feature branch; open / update the PR with `gh pr create` / `gh pr edit`; PR description includes `Fixes #N` or `Implements #N`.
   - Apply `.claude/agents/ieee-traceability-reviewer.md` (and `mka-timing-auditor.md` for MKA/CP/PAE timing changes) before opening the PR.
   - After the PR lands: refresh `docs/PROGRESS.md` if a domain row changed, refresh `02-requirements/traceability-matrix.md` if a REQ chain changed, then tick `docs/TODO.md` and **move** the entry to the *Done* section with PR number + date (living-document rule at `docs/TODO.md:8`).
   - If the task closed a whole phase: write `0N-<phase-name>/phase-gate-report.md` (template at `04-design/phase-gate-report.md`) and follow `SKILL/prompts/phase-gate-check.prompt.md`.
   - Surface every newly-discovered `TODO:` as a fresh GitHub issue.
4. **Keep `CLAUDE.md`, this file, and `SKILL/WORKFLOW-GUIDE.md` consistent with the code.** When the workspace structure, build commands, lifecycle status, or close-out rules change, update all three in the same PR.

## 4. Quick commands

```bash
cargo build --workspace
cargo test  --workspace
cargo test  -p <crate>
cargo test  <test_name>
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt   --all -- --check
cargo build -p pae --no-default-features                    # no_std
cargo build -p pae --no-default-features --features macsec  # no_std + MACsec
cargo build -p <crate> --target aarch64-unknown-linux-gnu   # cross
```

## 5. Pointers

| For | Read |
|---|---|
| Canonical agent guide (everything in detail) | `CLAUDE.md` |
| Long-form lifecycle workflow | `SKILL/WORKFLOW-GUIDE.md` |
| Live backlog | `docs/TODO.md` |
| Phase + per-domain status | `docs/PROGRESS.md` |
| REQ-by-REQ traceability | `02-requirements/traceability-matrix.md` |
| Root project rules / applicable standards | `SKILL/instructions/root.instructions.md` |
| Standard text (clause numbers only) | `../8021X-2020.md/8021X-2020.md` |
| YANG models | `../8021X-2020.YANG/` |
