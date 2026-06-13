# Security Posture — wpa_supplicant-rs

**Last refreshed:** 2026-06-13
**Verifies:** REQ-NF-SEC-001 / REQ-NF-SEC-002 / REQ-NF-SEC-003 / REQ-NF-SEC-005

This document is the **operator-facing summary** of the project's security posture and supply-chain hygiene policy. It is the public counterpart to:

- The traceability-matrix governance row for `REQ-NF-SEC-001` / `REQ-NF-SEC-002` / `REQ-NF-SEC-003` / `REQ-NF-SEC-005`.
- The Phase 07 V&V gate report at `07-verification-validation/phase-gate-report.md`.
- The clean-room verification record at `07-verification-validation/clean-room-review.md`.

---

## 1. Reporting a vulnerability

Report security issues privately via GitHub's [private vulnerability reporting][gh-pvr] ("Report a vulnerability" button on the repo Security tab). **Do not file public GitHub issues for unpatched flaws.**

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

We aim to:

- Acknowledge a report within **3 business days**.
- Triage and assign a CVSS within **10 business days**.
- Ship a fix on a private branch and coordinate disclosure with the reporter.

---

## 2. Supported versions

Until v1.0.0 lands, only the `main` branch tip is supported. Pre-1.0 minor versions are *not* patched in place.

---

## 3. Cryptographic primitives

| Surface | Crate | Primitive | Standards anchor |
|---|---|---|---|
| MKA KDF (CAK / KEK / ICK derivation) | `pae` | AES-CMAC-PRF-128 | IEEE 802.1X-2020 Cl.9.3.3, Cl.6.2.2 (KDF) |
| MKA SAK distribution | `pae` | AES Key Wrap (RFC 3394) | RFC 3394 / 802.1X-2020 Cl.9.8 |
| MKA ICV protection | `pae` | AES-CMAC-128 | 802.1X-2020 Cl.9.4 |
| Secret zeroization (CAK / SAK / KEK / ICK) | `pae` | `zeroize::Zeroize` derive | ADR-SEC-004 (#76) |

All primitives are sourced from `RustCrypto` (`aes`, `cmac`) and used in the `pae` crate. The Supplicant role is a **net consumer** of distributed SAKs — it does not generate or wrap SAKs itself (only the MKA Key Server, which is the Authenticator, does).

---

## 4. Supply-chain hygiene (CI gates)

The `.github/workflows/ci.yml` workflow runs three jobs on every push and pull request: `Test (x86_64)`, `Cross-build (aarch64)`, and **`Supply-chain (audit + deny)`**.

### 4.1 `cargo audit`

Runs against the [RustSec advisory database][rustsec]. Fails the build on:

- Any **vulnerability** advisory affecting any transitive crate.
- Any **yanked** version present in `Cargo.lock`.
- Warnings are also treated as errors (`--deny warnings`).

[rustsec]: https://rustsec.org/

### 4.2 `cargo deny check`

Driven by [`deny.toml`](../deny.toml) at the repo root. Checks four facets:

| Facet | Policy |
|---|---|
| **Advisories** | `yanked = "deny"`, `unmaintained = "workspace"` (informational on workspace crates only) |
| **Licenses** | Allow-list scoped to licenses currently encountered: `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-3-Clause`, `MIT`, `Unicode-3.0`, `Unlicense`. New transitive licenses **fail closed** — they must be added with rationale in a follow-up PR. **GPL / AGPL family rejected** for runtime dependencies. |
| **Bans** | `wildcards = "warn"` — workspace-internal `path = "..."` deps without explicit `version =` pin are reported as wildcards by cargo-deny. The Phase-08 release plan (`docs/TODO.md` P4.1, `08-transition/release-plan.md`) will pin versions and flip this to `"deny"`. `multiple-versions = "warn"` (surfaced, non-fatal). `allow-wildcard-paths = true` accepts intra-workspace path deps for the binary crate (`publish = false`). |
| **Sources** | `crates.io` only. No git or unknown-registry sources permitted. |

Run locally:

```sh
cargo install --locked cargo-audit cargo-deny
cargo audit --deny warnings
cargo deny --all-features check
```

### 4.3 Updating the policy

Adjustments to `deny.toml` (license changes, deliberate ban / skip entries) require:

1. A code-review PR with the rationale in the description.
2. Re-running the workflow on `main` after merge to confirm the gate still goes green.

---

## 5. Cross-cutting non-negotiables (per `CLAUDE.md` §8)

- **No `unwrap()` in production code** — three documented residuals on demonstrably-infallible constructions; new ones are findings.
- **No `unsafe` without a `// SAFETY:` comment** — one documented case in `crates/wpa-supplicant/src/systemd.rs`.
- **Secret zeroization** — `zeroize::Zeroize` derive applied to all credential-bearing types per ADR-SEC-004 (#76).
- **Clean-room implementation** — verified by `07-verification-validation/clean-room-review.md` (35 / 35 production source files carry the disclaimer; verdict PASS for `REQ-NF-SEC-004`).

---

## 6. Open security follow-ups

| Issue | Topic |
|---|---|
| #139 (TEST-VV-001) | `cargo llvm-cov ≥ 80 %` coverage gate (REQ-NF-MNT-001) |
| #141 (TEST-VV-003) | `cargo geiger` + `// SAFETY:` adjacency CI gate (REQ-NF-SEC-001) |
| #142 (TEST-VV-004) | `no_std` build CI gate (REQ-NF-PORT-002) |
| #143 (TEST-VV-005) | Fuzz harness for `EapolFrame` / `EapPacket` / `Mkpdu` decoders (REQ-NF-REL-001/002) |
| #144 (TEST-VV-006) | `clippy.toml` policy gating `unwrap()` / `expect()` in production (REQ-NF-SEC-002) |
