# Skill: Security Review

## Purpose

Review IEEE 802.1X-2020 supplicant Rust code for security flaws, cryptographic misuse, and secret-handling issues.

## Use When

- Auditing EAPOL, MKA, KaY, CP, and related flows
- Checking for credential or secret leakage in docs and code
- Reviewing crypto- and identity-sensitive changes
- Evaluating threat models and mitigations
- Auditing `unsafe` Rust blocks

## Inputs

- Workspace crate source code (`crates/*/src/`)
- `SKILL/instructions/root.instructions.md` (security rules)
- `07-verification-validation/` (security test evidence)
- AI prompts and agent outputs touching security-sensitive areas

## Expected Output

- Concrete findings with severity
- Attack surface notes
- Mitigation recommendations
- Secret and privacy hygiene checks
- `unsafe` block audit results

## Guardrails

- Distinguish example placeholders from live secrets
- Prefer concrete exploit paths over generic warnings
- Review both code and documentation for leakage

## Rust-Specific Security Concerns

| Concern | Check |
|---|---|
| `unsafe` blocks | Must have safety comment; must be justified; minimize use |
| `unwrap()` in production | Replace with `?`, `expect("reason")`, or proper error handling |
| Secret material in memory | Zeroize on drop; use `zeroize` crate for keys/credentials |
| `println!` / `dbg!` of secrets | Never log secrets — use `tracing` with careful filtering |
| Integer overflow | Use checked/overflowing arithmetic in protocol counters |
| Panic in library code | Library crates must not panic — return `Result` |
| Deserialization | Validate all data from network before use |
| Thread safety | Protocol state must be Send + Sync where shared |
