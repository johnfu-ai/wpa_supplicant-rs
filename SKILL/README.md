# SKILL System — IEEE 802.1X-2020 Rust Supplicant

This directory contains the AI development skill system for building the IEEE 802.1X-2020 supplicant in Rust. It is self-contained and independent — no references to external repositories.

## Structure

```
SKILL/
├── agents/         # Role-oriented agent profiles (who does what)
├── instructions/   # Root and phase-specific instructions (how to do it)
├── skills/         # Focused, composable capabilities (what you can do)
└── prompts/        # Actionable workflow prompts (start here)
```

## How to Use

### Starting a Lifecycle Phase

1. Read `instructions/root.instructions.md` for project constraints and methodology
2. Read the relevant `instructions/phase-0N-*.instructions.md` for phase-specific guidance
3. Use the corresponding `prompts/` file to kick off work
4. Invoke the relevant `agents/` profile for the phase

### Quick Reference: Phase → Agent → Prompt

| Phase | Agent | Prompt |
|---|---|---|
| 01-02 Stakeholder & System Requirements | Requirements Analyst | `project-kickoff`, `requirements-elicit`, `requirements-validate` |
| 03 Architecture | Architecture Strategist | `architecture-starter` |
| 04 Design | Architecture Strategist | — |
| 05 Implementation | TDD Driver | `tdd-compile` |
| 06 Integration | TDD Driver | — |
| 07 Verification & Validation | Testing Specialist | `test-validate` |
| Any phase transition | — | `phase-gate-check` |
| Any time | Security Analyst | `security-review` |
| Any time | — | `traceability-builder`, `corrective-action-loop` |

## Scope: Supplicant Only

This project implements the **supplicant role only** per IEEE 802.1X-2020:

| Clause | Protocol Entity | Rust Crate |
|---|---|---|
| 8 | Supplicant PAE state machine | `crates/eapol-supp/` |
| 9 | MKA (supplicant perspective) | `crates/pae/` |
| 10 | CP (supplicant-controlled port) | `crates/pae/` |
| 12 | Logon Process (NID selection) | `crates/logon/` |
| — | EAP peer methods (TLS, PEAP, TEAP) | `crates/eap-peer/` |
| — | Top-level supplicant binary | `crates/wpa-supplicant/` |

## Copyright Compliance

Reference IEEE 802.1X-2020 clauses by number only. Do not quote standard text verbatim. See `instructions/root.instructions.md` for full rules.
