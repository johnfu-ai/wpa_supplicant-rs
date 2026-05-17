# Skill: 8021X Domain Model

## Purpose

Apply IEEE 802.1X-2020 domain knowledge (supplicant role only) without reproducing copyrighted standard text.

## Use When

- Mapping clauses to Rust crate code
- Interpreting PAE, EAPOL, MKA, CP, NID, and ANCP terms (supplicant perspective)
- Relating YANG models to implementation and documentation
- Reviewing 2010 vs 2020 compliance gaps

## Inputs

- `SKILL/instructions/root.instructions.md` (workspace layout)
- IEEE 802.1X-2020 standard reference (read-only, search by clause number only)
- IEEE 802.1X-2020 YANG data models (reference)

## Expected Output

- Clause-number references (e.g., "per IEEE 802.1X-2020 Clause 8.3")
- Rust crate/module pointers (e.g., `crates/eapol-supp/`)
- Protocol-correct terminology using IEEE 802.1X-2020 ubiquitous language
- Copyright-safe summaries

## Guardrails

- Reference IEEE clauses by number only — do not quote standard text verbatim
- This project is supplicant-only — do not reference Authenticator PAE, `src/eapol_auth/`, or AP-side logic
- Prefer Rust crate paths and type names over generic restatements

## Supplicant-Only Scope

| Clause | Protocol Entity | Rust Crate |
|---|---|---|
| 8 | Supplicant PAE state machine | `crates/eapol-supp/` |
| 9 | MKA (supplicant perspective) | `crates/pae/` |
| 10 | CP (supplicant-controlled port) | `crates/pae/` |
| 12 | Logon Process (NID selection) | `crates/logon/` |
| — | EAP peer methods (TLS, PEAP, TEAP) | `crates/eap-peer/` |
| — | Top-level supplicant binary | `crates/wpa-supplicant/` |
