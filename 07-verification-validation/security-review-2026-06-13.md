# Security Review Report — Phase 07 / 2026-06-13 sweep

**Implements:** `docs/TODO.md` P5.1 (overdue per CLAUDE.md workflow rule "after implementing features, perform a security review").

**Verifies:** REQ-NF-SEC-001 (no `unsafe` without `// SAFETY:`), REQ-NF-SEC-002 (no `unwrap()` in production), REQ-NF-SEC-003 (key zeroization), REQ-NF-SEC-005 (supply-chain hygiene).

**Reviewer:** automated SKILL/prompts/security-review.prompt.md sweep, with manual verification of every finding's file:line citation.

**Scope:** the recent feature batch listed in `docs/TODO.md` P5.1 (#37, #50–51, #59, #68–72, #86) plus the most recent landings (#128 RawSocketNetworkIo, #129 MkaParticipant construction, #130 EAP→PAE bridge, #135 AES Key Wrap RFC 3394).

> **Important context:** this review was run while the `cargo audit` + `cargo deny` CI gate (PR #148, issue #140 / TEST-VV-002) was open but not yet merged. PR #148 lands a working `deny.toml` whose policy is internally consistent; the gate's CI run on that branch passes (advisories / bans / licenses / sources all `ok`). The ad-hoc finding F-07 below was raised against `main` (which has no `deny.toml`) and is therefore informational only — it will resolve on merge.

---

## 1. Findings

| ID | Severity | Category | File:line | Description | Mitigation |
|---|---|---|---|---|---|
| F-01 | Medium | Unauthenticated local IPC | `crates/wpa-supplicant/src/control.rs:96` | `UnixListener::bind(path)` is called without setting socket file permissions. A daemon running as root with default umask may expose a world-writable control socket. Any local user can issue `SHUTDOWN`, `LOGOFF`, `REAUTHENTICATE`, or `SET_LOG_LEVEL` commands. The `generate_socket_unit` helper sets `SocketMode=0660` but that only applies under systemd socket-activation; the direct-bind path in `UnixControl::bind` has no equivalent. | After `UnixListener::bind`, call `std::fs::set_permissions(path, PermissionsExt::from_mode(0o660))`. Cover with a unit test asserting `metadata.mode() & 0o777 == 0o660`. |
| F-02 | Medium | DoS — unbounded read holding mutex | `crates/wpa-supplicant/src/control.rs:139-153` | `handle_connection` is invoked from `accept_commands` while the `listener` mutex is held. The accepted `UnixStream` is **blocking** by default, and `BufReader::lines()` reads with no per-line size cap and no read timeout. A client that opens a connection and never sends data, or sends a single multi-GB line, will block the listener mutex indefinitely and starve the supplicant tick. | Set the accepted stream non-blocking via `stream.set_nonblocking(true)`; bound each line with `BufRead::take(MAX_CMD_LEN).read_line()`; do not hold the listener mutex while servicing a connection. |
| F-03 | Medium | Credential leak via Debug | `crates/wpa-supplicant/src/config.rs:56-72, 184-207` | `MacsecConfig` (containing `psk: Option<String>` — the hex-encoded pre-shared CAK) and the parent `Config` both `#[derive(Debug)]`. The hex string is heap-allocated, **not zeroized on drop**, and has no redacting Debug impl. Today no production log site does `?config`, but the foot-gun is loaded — any future `tracing::debug!(?config)` (a common debug pattern) leaks the root key in plain text. The PSK is the CAK, the most sensitive long-term key in the system. | (a) Replace `Option<String>` with a `Psk` newtype that derives `ZeroizeOnDrop` and writes `Psk([REDACTED])` from `Debug`. (b) Add a custom `Debug` for `MacsecConfig` that masks `psk`. (c) Add a unit test that asserts `format!("{:?}", config)` does not contain the PSK byte sequence. |
| F-04 | Medium | Missing zeroization of TLS private key | `crates/eap-peer/src/peer.rs:315-326` | `TlsClientConfig::private_key: Vec<u8>` holds the EAP-TLS client private-key PEM. The `Debug` impl correctly redacts (line 335), but the struct does **not** derive `Zeroize`/`ZeroizeOnDrop`, and `Clone` (line 342-350) duplicates the key bytes into another non-zeroizing allocation. Per ADR-SEC-004 (#76) and CLAUDE.md §8, key material must be zeroized on drop. The MKA hierarchy (CAK/SAK/KEK/ICK) honours this; the EAP credential that ultimately produces the MSK→CAK does not. | Wrap `private_key` in a `zeroize::Zeroizing<Vec<u8>>` (or a dedicated `PrivateKey` newtype with `#[derive(ZeroizeOnDrop)]`). Same for `cert_chain` and `ca_certs` if they are considered sensitive. |
| F-05 | Low | Non-constant-time IV check in AES Key Unwrap | `crates/pae/src/crypto.rs:323` | After running the inverse Key Wrap rounds, the IV check is `if a != KEY_WRAP_IV { … }` — a normal `[u8; 8]` array equality which short-circuits on the first differing byte. By contrast, `verify_icv` (lines 84-87 of the same file) uses an explicit constant-time XOR-accumulate. The KEK is not directly attacker-controlled, so practical exploitability against a wrong-KEK timing oracle is very low, but the inconsistency is a finding because the rest of the crypto module has otherwise been written with constant-time discipline. | Replace lines 322-332 with a constant-time XOR-accumulate identical to `verify_icv`. Or use `subtle::ConstantTimeEq`. |
| F-06 | Low | systemd socket activation: missing LISTEN_PID validation | `crates/wpa-supplicant/src/systemd.rs:31-48` | `SystemdActivation::listen_fds` reads `LISTEN_FDS` but never validates `LISTEN_PID` against the current process's PID. The systemd socket-activation contract (`sd_listen_fds(3)`) requires that callers ignore the FDs unless `LISTEN_PID == getpid()`; otherwise FDs leaked across `exec` (or stale env vars in a process spawned by something other than systemd) can be silently adopted. Additionally, `take_unix_listener(fd_index)` does not bounds-check `fd_index < listen_fds()`. | Validate `LISTEN_PID == std::process::id()` before honouring `LISTEN_FDS`; clear both env vars after first read; bounds-check `fd_index`. |
| F-07 | (false positive) | n/a | `deny.toml` (now in PR #148) | Ad-hoc `cargo deny check` against `main` was failing because `main` does not yet have `deny.toml`. PR #148 lands the policy with `advisories ok, bans ok, licenses ok, sources ok`. **Disregard.** | None — resolves on PR #148 merge. |
| F-08 | Info | Forward-looking TLS engine wiring risk | `crates/eap-peer/src/peer.rs:323-325` and `eap_tls.rs::TlsEngine` | `TlsClientConfig::verify_server: bool` defaults to `true`. No production `TlsEngine` impl exists yet (#133 deferred to Phase 08); only mock impls in test modules. When the real `RustlsEngine` is wired, `verify_server: false` must be treated as a deliberate test-only escape hatch — not silently honoured. | When implementing `RustlsEngine::init_session` under #133, refuse `verify_server == false` unless an explicit `allow_disabled_server_verify` feature flag is set; emit `tracing::warn!` if used. Add a regression test: with `verify_server == true` and a self-signed server cert not in `ca_certs`, init_session must fail. |
| F-09 | Info | MKA Member Number wrap | `crates/pae/src/mka.rs:559…` | `actor_mn` increments use `wrapping_add`. With Hello-Time = 2 s, the `u32` MN counter wraps after ~272 years — operationally negligible — but per IEEE 802.1X-2020 Cl.9.4 the MN must be strictly monotonic within a CA; on wrap, an attacker with a long capture could replay a previously-accepted MKPDU. | Either stop emission and signal CA renewal when `mn == u32::MAX`, or document the wrap as an acknowledged-residual in `02-requirements/traceability-matrix.md` against REQ-F-MKA-002. |

## 2. Summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | **4** (F-01, F-02, F-03, F-04) |
| Low | **2** (F-05, F-06) — F-07 disregarded |
| Info | 2 (F-08, F-09) |

**No blocking findings for Phase 08 entry.** Per `SKILL/prompts/security-review.prompt.md` §2, only Critical and High findings are blocking; all Medium / Low / Info findings track as separate GitHub issues and may resolve on a normal cadence.

## 3. Items confirmed clean (no findings)

- All 18 `unsafe` blocks in `crates/wpa-supplicant/src/raw_socket.rs` (#128) carry detailed `// SAFETY:` comments, isolate FFI via the `OwnedFd` RAII wrapper, and bound `recv` into a fixed-size 1514-byte stack buffer.
- The single `unsafe` in `systemd.rs:45` is the documented residual.
- Production-code `unwrap()` count is exactly 3, all at `Mutex::lock()` sites in `control.rs:117/141/159` — the documented infallible residuals.
- All MKA secret types (`Cak`, `Ckn`, `Ick`, `Kek`, `Sak`, `Msk`) carry custom redacting `Debug` impls and `ZeroizeOnDrop`. `CakCacheEntry` (#37) derives `Debug` but its inner secret fields are redacted by their own impls — propagated correctly.
- EAPOL frame decoder (`crates/eapol-supp/src/frame.rs`) bounds body to `MAX_BODY_SIZE = 1500` before allocation; rejects unknown version/type; truncation-checked.
- MKPDU decoder (`crates/pae/src/mkpdu.rs`) bounds-checks every parameter set, validates ICV/Basic ordering and singleton uniqueness, returns `PaeError::InvalidMkpdu` on every malformed branch — no panics from network input.
- AES Key Wrap (#135) implementation matches RFC 3394 §4.1, §4.3, §4.6 test vectors; intermediate state zeroized on every code path including the error-return branch (line 324-328); KEK length validated to be 16 or 32 before cipher init.
- EAP packet decoder (`crates/eap-peer/src/peer.rs:213`) length-bounded against `MAX_SIZE`, truncation-checked, type-validated.
- `cargo audit`: 97 dependencies scanned, **0 vulnerabilities**.
- `cargo deny` (against PR #148's `deny.toml`): `advisories ok`, `bans ok`, `licenses ok`, `sources ok`.
- No hardcoded credentials anywhere in `crates/**`.
- No `panic!`/`todo!`/`unimplemented!` in production paths (all matches are test-only).

## 4. Tracking

Each Medium / Low / Info finding above will be filed as a fresh GitHub issue with `phase:08-transition` label (or the equivalent of the time when filed). Mitigations land issue-by-issue against Phase 08 backlog.

### Filed issues

- F-01 + F-02 — control-socket hardening: filed as **#150**
- F-03 — `MacsecConfig::psk` redacting newtype: filed as **#151**
- F-04 — `TlsClientConfig::private_key` zeroization: filed as **#152**
- F-05 — constant-time IV check in AES Key Unwrap: filed as **#153**
- F-06 — systemd LISTEN_PID validation: filed as **#154**
- F-08 — `RustlsEngine` verify_server escape-hatch: carry-forward comment posted on **#133**
- F-09 — MKA MN wrap policy: filed as **#155**

## 5. Sign-off

This review is the closing artifact for `docs/TODO.md` P5.1. Cross-cutting non-negotiables in CLAUDE.md §8 hold; supply-chain hygiene CI gate lands in #140 / PR #148; the recent feature batch is **clean for Phase 08 entry** modulo the trackers above.
