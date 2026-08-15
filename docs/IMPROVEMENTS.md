# Improvements Register — wpa_supplicant-rs

**Generated:** 2026-08-14 (deep-study sweep, session `2b148e27`)
**Source basis:** `docs/TODO.md`, `docs/PROGRESS.md`, `02-requirements/traceability-matrix.md`, `git log`, a full read of `crates/**`, and the #133 EAP-method-factory implementation landing in this same batch.

This is the **deep-study deliverable**: a single, prioritized catalog of every improvement item the project is aware of — open tracked issues, carry-forwards, and correctness/quality findings surfaced by reading the code. It is the *consolidated index*; the *live status* of each item still lives in `docs/TODO.md` (action log) and `docs/PROGRESS.md` (status roll-up). New findings discovered here that have no tracking issue are filed as one before this list is considered authoritative (see §4).

> **Relationship to the other tracking artifacts.**
> - `docs/TODO.md` — *what to do next*, with PR/close trails (audit evidence per StR-006).
> - `docs/PROGRESS.md` — *where the project stands* per phase / domain.
> - `docs/IMPROVEMENTS.md` (this file) — *the full backlog as a ranked catalog*, including items not yet big enough to be a GitHub issue and items deferred past v1.0.

---

## Legend

| Field | Meaning |
|---|---|
| **Priority** | P0 blocker · P1 high · P2 medium · P3 low · P4 nice-to-have / deferred |
| **Status** | 🟢 done · 🟡 in-progress · 🔴 open · ⚪ deferred |
| **REQ / ADR** | traceability anchor (the `#REQ-*` / `ADR-*` the item serves) |

---

## 1. Open tracked backlog (GitHub issues)

These already have an issue number and live in `docs/TODO.md`. Listed here for completeness.

| ID | Title | Priority | Status | Anchor | Note |
|---|---|---|---|---|---|
| **#142** | `no_std` build CI gate for `pae` (TEST-VV-004) | P3 | 🔴 open | REQ-NF-PORT-002 | The crate already builds `--no-default-features`; the CI job that *asserts* it on every push is missing. Last TEST-VV sibling to land (#139/#140/#141/#144 are done). |
| **#143** | Fuzz harness for `EapolFrame` / `EapPacket` / `Mkpdu` decoders (TEST-VV-005) | P2 | 🔴 open | QA-SC-REL-003 (#88) | Decoders all bounds-check before allocation (verified in the 2026-06-13 security review); a `cargo-fuzz` corpus would harden the untrusted-input boundary further. |
| **P5.3 / ADR-MGMT-009** | YANG / NETCONF management surface | P4 | ⚪ deferred to v1.x | REQ-F-MGMT (not yet opened) | Deferral record at `08-transition/yang-deferral.md`. Lifts when an ADR opens with a concrete transport, a REQ-F-MGMT row lands, or operator demand accumulates. |

---

## 2. #133 follow-ups (EAP method factory — factory + engine landed this batch)

The factory (`crates/wpa-supplicant/src/method_factory.rs`), the rustls engine (`rustls_engine.rs`), and the `Supplicant` wiring landed. A real loopback TLS 1.2 handshake test (`test_rustls_engine_full_handshake_exports_msk`) proves the engine drives a handshake and exports an MSK. What remains:

| ID | Title | Priority | Status | Anchor | Evidence / next step |
|---|---|---|---|---|---|
| **F-INT-1** | Live EAP-TLS/PEAP/TEAP handshake validation against FreeRADIUS | P2 | 🔴 open | REQ-F-EAP-002/003/004 | The loopback test proves the *engine*; a full EAP conversation against the Phase-07 FreeRADIUS/hostapd stack (`07-verification-validation/interop/`) proves the *system*. The harness stays `workflow_dispatch`-only until this lands. Re-arm `.github/workflows/interop.yml` auto-trigger + convert `crates/wpa-supplicant/tests/interop_freeradius.rs` `TODO(#133)` markers into real assertions. |
| **F-EAP-1** (#174) | EAP-TLS `Session-Id` is incomplete per RFC 5216 §1.4 | P2 | 🟢 done | REQ-F-EAP-002 (#39) · issue #174 | Fixed: `TlsEngine::session_id()` accessor (defaulted) + `EapTls::eap_session_id` builds `0x0D \|\| TLS session identifier`. Under TLS 1.3 the production engine derives the 64-octet Method-Id via `TLS-Exporter("EXPORTER_EAP_TLS_Method-Id")` per RFC 9190 §2.3; under TLS 1.2 rustls 0.23 does not expose the negotiated session ID, so the Session-Id degrades to the type byte alone (documented limitation — revisit when rustls exposes it). |
| **F-EAP-2** (#175) | EAP-TLS fragmentation/reassembly not validated end-to-end | P3 | 🟢 done | REQ-F-EAP-002 (#39) · issue #175 | Fixed (PR #181): inbound M-flag fragments are buffered and flags-only-ACKed; the TLS engine sees only the reassembled whole (L-flag announced length validated, reassembly capped at `TLS_MAX_REASSEMBLY_LEN` = 16 KiB record + TLS 1.3 margin). Outbound engine flights larger than `TLS_MAX_FRAGMENT_LEN` (1024) are split with L/M flags; flags-only EAP-server requests solicit continuation. Fragmentation state is idempotent under Identifier retransmission per RFC 3748 §4.1 (retransmitted fragment restarts accumulation; retransmitted flags-only request replays the same outbound fragment). 6 TDD unit tests in `eap_tls.rs`. |
| **F-EAP-3** (#176) | `config.macsec.cipher_suite` → `pae::CipherSuite` mapping not wired | P3 | 🟢 done | REQ-F-CP-004 (#32) / REQ-F-MKA-005 (#23) · issue #176 | Fixed: `MacsecConfig::resolve_cipher_suite()` maps the TOML string onto the enum per Cl.9.7 (`gcm-aes-128`/`-256`/`-xpn-256`/`null`); unknown values rejected at config load; `try_construct_mka` uses the mapping. Integration tests in `tests/cipher_suite_wiring.rs`. |
| **F-EAP-4** (#179) | TLS 1.2 MSK derivation did not match RFC 5216 §2.3 | P2 | 🟢 done | REQ-F-EAP-002 (#39) · issue #179 | Fixed: `RustlsTlsEngine::derive_msk` is version-scoped — TLS 1.3 keeps `TLS-Exporter("EXPORTER_EAP_TLS_Key_Material", Type, 128)` per RFC 9190 §2.3; TLS 1.2 now derives `PRF(MS, "EAP TLS Keying Material", client_random \|\| server_random)` per RFC 5216 §2.3 via the RFC 5705 exporter with empty context. TDD unit test `test_derive_msk_tls12_uses_rfc5216_prf` cross-checks against the loopback server's derivation and asserts divergence from the TLS 1.3 label. |
| **F-SEC-1** | `wpa-supplicant-ctl` control client unshipped | P4 | ⚪ deferred | REQ-NF-DEPLOY-002 | `09-operation-maintenance/runbook.md` §11 lists the control-socket text protocol but no client binary ships. Operators use `socat`/`nc` today. Defer to v0.1.x. |

---

## 3. Correctness & quality findings (from the deep-study read)

Each is evidence-backed; none is a known security vulnerability (the 2026-06-13 + 2026-06-21 security sweeps are closed). Severity is *engineering* severity, not security.

| ID | Finding | Severity | Anchor | Evidence / next step |
|---|---|---|---|---|
| **Q-1** | Feature-gated code is **compiled** in CI (`--all-features` clippy) but only the *default*-feature suite is **coverage-gated**. The `eap-tls-rustls` modules (88–91 % covered by dedicated tests) are not asserted by `scripts/check_coverage.py`. | Low | REQ-NF-MNT-001 (#139) | Add a feature-coverage variant or accept the dedicated-test posture. Documented in `docs/TESTING.md`. |
| **Q-2** | `EapSession::started_at` is `#[allow(dead_code)]` — wired for the factory's retransmit deadlines but never read. | Trivial | ADR-EVT-007 (#79) | Either wire `now()`/retransmit deadlines to the EAP methods or drop the field. |
| **Q-3** | `EapPeer::eap_results()` is `#[deprecated]` and returns `None` unconditionally (`Msk` is not `Clone`). Still present in the public API. | Trivial | REQ-F-EAP-001 (#38) | Remove at the next minor bump once all in-tree callers are confirmed migrated to `take_msk()`. |
| **Q-4** | `MethodFactoryOutput` lacks a `Debug` impl (blocked by `Box<dyn EapMethod>`). Test code must `match` instead of `unwrap_err()`. | Trivial | #133 | Acceptable; document the pattern or add a manual redacting `Debug`. |

---

## 4. Filing discipline

Per `CLAUDE.md` §6.8 and StR-006: a bare finding in this list with no tracking issue is not yet actionable. The three initial follow-up findings are filed: **F-EAP-1 → #174, F-EAP-2 → #175, F-EAP-3 → #176** (issue numbers back-filled into the *ID* / *Anchor* columns). When an item lands a PR, its row moves to `docs/TODO.md` Done (the audit trail) rather than being deleted here.

---

## 5. Not improvements (explicitly out of scope, to prevent re-litigation)

- **No Authenticator PAE / AP-side logic.** This is a supplicant-only implementation per StR-001. Do not file "add authenticator" items.
- **No verbatim IEEE/RFC text in source.** Clean-room per StR-008 / `SKILL/instructions/root.instructions.md:450`. Clause numbers only.
- **`wpa-supplicant` binary stays `publish = false`.** Distributed as a release artifact, not via crates.io (per `08-transition/release-plan.md`).
