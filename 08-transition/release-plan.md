# Phase 08 Release Plan — wpa_supplicant-rs v0.1.0

**Implements:** `docs/TODO.md` P4.1.
**Standard anchor:** ISO/IEC/IEEE 12207:2017 (Transition Process).
**Verifies:** REQ-NF-DEPLOY-001..005 (Linux deployment), REQ-NF-REL-003 (interop), REQ-NF-PORT-001 (aarch64), StR-009 (Library and Daemon Architecture).
**Date:** 2026-06-13.

---

## 1. Scope

This document is the **release plan for the first cut of `wpa_supplicant-rs`** as a deployable IEEE 802.1X-2020 supplicant on Linux. It is the artifact required by Phase 08 / `docs/TODO.md` P4.1 ("cargo publish strategy, version pinning policy, `cargo-deny` baseline, deb/rpm scope").

**Out of scope** for this release: Authenticator role (the project is supplicant-only per StR-001), and a full *live* EAP-TLS / PEAP / TEAP handshake against a real RADIUS server (the #133 method factory + rustls engine landed 2026-08-14 and are wired into `Supplicant::new`; the live-stack handshake validation is follow-up **F-INT-1**, `docs/IMPROVEMENTS.md`). The security-review findings #150–#155 are all closed (2026-06-21).

## 2. Versioning policy

| Concern | Policy |
|---|---|
| Workspace root version | Single `version` in `[workspace.package]` of the top-level `Cargo.toml`. Every member crate sets `version.workspace = true`. |
| First public release | **`0.1.0`** — current workspace version. The `0.x.y` line signals "pre-stable API"; minor bumps (`0.x` → `0.y`) MAY break the public API; patch bumps (`0.0.y` → `0.0.z`) MUST NOT. |
| Stable line target | `1.0.0` will gate on (a) ~~#133 EAP method factory landing with a real `RustlsEngine`~~ ✅ landed 2026-08-14 (real rustls engine wired into `Supplicant::new`), (b) ~~all security-review Medium findings (#150–#155)~~ ✅ closed 2026-06-21, and (c) one external interop run reaching CP→Secured against an unmodified hostapd Authenticator (follow-up **F-INT-1**). |
| Compatibility | The four library crates (`pae`, `eapol-supp`, `eap-peer`, `logon`) follow [semver](https://semver.org/) once they are first published to crates.io. The binary crate (`wpa-supplicant`) follows the workspace version line; its CLI / config / control-socket protocol carry separate stability guarantees described in §6. |
| Rust toolchain | MSRV pinned at the workspace level: `rust-version = "1.75"` (already set in `Cargo.toml`). Bumps are a minor-version event (`0.x.y` → `0.(x+1).0`) and CHANGELOG-noted. |

## 3. crates.io publication strategy

### 3.1 Publishability today (snapshot)

| Crate | `publish` | Reason |
|---|---|---|
| `pae` | `false` | All four library crates are `publish = false` pending §3.2 below. |
| `eapol-supp` | `false` | Pre-1.0; carries intra-workspace `path = "..."` deps without explicit version pins. |
| `eap-peer` | `false` | Same. |
| `logon` | `false` | Same. |
| `wpa-supplicant` | `false` | **Permanent** — binary distributed as a release artifact, not via `cargo install`. |

The `publish = false` on the four libraries was set deliberately by PR #148 (cargo-deny gate) so that `allow-wildcard-paths = true` could accept the workspace-internal `path = "..."` deps. Phase 08 flips them to publishable.

### 3.2 Pre-publish prerequisites (required, in order)

1. **Pin explicit versions on every intra-workspace `path = "..."` dep.** Cargo treats `path = "../pae"` without a `version =` field as a wildcard, which crates.io rejects. Update each library crate's `[dependencies]`:
   ```toml
   # Before
   pae = { path = "../pae" }
   # After
   pae = { path = "../pae", version = "0.1" }
   ```
   This change permits `cargo publish` while still letting the local workspace build resolve through the path. Once landed, `deny.toml` flips `wildcards = "warn"` → `wildcards = "deny"`.
2. **Remove `publish = false` from the four library crates.**
3. **Run `cargo publish --dry-run`** for each library crate, in dependency order (`pae` first, then `eapol-supp` / `eap-peer` / `logon`). Confirm the package tarballs build clean with no path-dep escapes.
4. **Confirm `cargo doc --no-deps` succeeds** for every library crate; broken intra-doc links block publish.
5. **Confirm `cargo deny check` is clean** (advisories, bans, licenses, sources).

### 3.3 Publish order

Library crates only — the binary stays unpublished:

```
pae  →  eapol-supp  →  eap-peer  →  logon
```

`pae` is the dependency-graph root (every other library re-exports `PaeError`). Each subsequent publish needs the previous one already on crates.io. `eapol-supp` and `eap-peer` are siblings; either order works, but the script publishes `eapol-supp` first so that `logon` (which depends on both `pae` and `eapol-supp`) finds them in stable order.

### 3.4 Version-bump checklist (per release)

This list is the per-release operational counterpart to the high-level Phase 08 release-checklist in `SKILL/instructions/phase-08-transition.instructions.md`:

- [ ] All open Phase 08 / 09 issues for the target version are closed or deferred (and the deferral is recorded in `CHANGELOG.md`).
- [ ] `git log` since the last release is summarized into a fresh `CHANGELOG.md` entry (Keep-a-Changelog format, sections: Added / Changed / Deprecated / Removed / Fixed / Security).
- [ ] `cargo test --workspace` passes locally.
- [ ] `cargo test --workspace -- --ignored` passes (wall-clock perf checks per `a90c033`).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo audit --deny warnings` clean.
- [ ] `cargo deny --all-features check` clean (all four facets).
- [ ] `cargo doc --workspace --no-deps` clean.
- [ ] Cross-build green: `cargo build --workspace --target aarch64-unknown-linux-gnu`.
- [ ] Workspace `version` bumped in `Cargo.toml` `[workspace.package]`.
- [ ] If MSRV changed, `rust-version` bumped and noted in CHANGELOG `Changed` section.
- [ ] Tag the release: `git tag -s v$(version) -m "Release v$(version)"; git push --tags`.
- [ ] Run `./scripts/publish.sh` (see §3.5).
- [ ] Build the deb + rpm packages (§5).
- [ ] Attach release artifacts (deb, rpm, source tarball, binary tarballs for x86_64 + aarch64) to the GitHub Release.
- [ ] Post-release: bump workspace `version` to `0.x.(y+1)-dev` on `main` (so `cargo publish` against `main` between releases fails fast).

### 3.5 Publish script (to be added)

`scripts/publish.sh` (TODO under #TBD-publish-script):

```sh
#!/bin/sh
set -eu
# Publishes the four library crates in dependency order. Idempotent —
# crates.io rejects re-publish of an already-published version.
for crate in pae eapol-supp eap-peer logon; do
    cargo publish --package "$crate" --token "$CARGO_REGISTRY_TOKEN"
    # crates.io needs ~30 s after each publish to make the new version
    # discoverable to the next dependent crate's dry-run.
    sleep 45
done
```

## 4. `cargo-deny` baseline

The supply-chain CI gate landed in PR #148 (issue #140). The Phase 08 release plan inherits that policy verbatim and pins three additional posture changes:

| Setting | Today (PR #148) | Phase 08 |
|---|---|---|
| `[bans] wildcards` | `"warn"` | **`"deny"`** — flip after §3.2 step 1. |
| `[bans] multiple-versions` | `"warn"` | `"warn"` (unchanged — workspace stays small) |
| `[licenses]` allow-list | scoped to currently encountered ids | unchanged; new transitive licenses still fail closed |
| `[advisories] yanked` | `"deny"` | unchanged |
| `[advisories] unmaintained` | `"workspace"` | unchanged |
| `[sources]` | crates.io only | unchanged |

The `cargo deny check` output for the v0.1.0 baseline must read `advisories ok, bans ok, licenses ok, sources ok`. Any deviation blocks the release.

## 5. Distribution packages

### 5.1 Source tarball

`cargo package --workspace --no-verify` followed by per-crate tarballs published to crates.io (§3.3). The GitHub Release also attaches a `wpa_supplicant-rs-v$(version).tar.gz` containing the full workspace including the lifecycle directories — useful for downstream auditors (StR-006).

### 5.2 Static binary tarballs

Two build flavors per release, both with `--features raw-socket` so the binary actually owns an `AF_PACKET / SOCK_RAW` socket:

| Target | Builder | Artifact |
|---|---|---|
| x86_64-unknown-linux-gnu | `ubuntu-latest` runner via `cargo build --release` | `wpa-supplicant-v$(version)-x86_64-linux-gnu.tar.gz` |
| aarch64-unknown-linux-gnu | `ubuntu-latest` + `gcc-aarch64-linux-gnu` cross | `wpa-supplicant-v$(version)-aarch64-linux-gnu.tar.gz` |

Each tarball contains: `wpa-supplicant` (binary), `wpa-supplicant.conf.example`, `LICENSE`, `README.md`, `09-operation-maintenance/runbook.md`, and a sample `systemd/` unit + socket file pair.

### 5.3 Distro packages — first-cut posture

For v0.1.0 the **scope is to ship the static tarballs only.** Native deb/rpm packages have non-trivial maintainer overhead (signing keys, distribution-specific lint, repository hosting) and are most cost-effectively delegated to volunteer downstream packagers once the upstream is stable.

The repository's `08-transition/packaging/` directory will hold a thin reference for downstreams:

```
08-transition/packaging/
├── deb/
│   ├── debian/control               # Source package metadata (architecture: linux-any).
│   ├── debian/rules                 # cargo-debian-style override.
│   ├── debian/postinst              # systemctl daemon-reload + enable wpa-supplicant.socket.
│   └── README.md                    # "How to build the deb locally."
├── rpm/
│   ├── wpa-supplicant.spec          # %_target_cpu: x86_64 + aarch64.
│   └── README.md
└── README.md                        # "Distro packaging is community-driven."
```

Inclusion of these stubs is **deferred to a v0.1.x point release** unless a downstream packager surfaces ahead of the v0.1.0 cut.

### 5.4 Signing & provenance

- All Git tags signed with the maintainer's GPG key (`git tag -s`).
- Release tarballs are SHA-256-summed; sums published in the GitHub Release notes and signed with the same GPG key.
- (Future, post-1.0) sigstore / SLSA provenance via `cosign` — tracked as a Phase 09 enhancement, not blocking v0.1.0.

## 6. Public API stability surfaces

| Surface | Stability promise |
|---|---|
| `pae` library crate public API | `0.x.y` semver; breaking changes bump minor. The MKA timer constants (Hello 2 000 ms / Life 6 000 ms / SAK-Retire 3 000 ms; `83bca6f`) are clause-derived and will not change without a corresponding standard erratum. |
| `eapol-supp` / `eap-peer` / `logon` public APIs | Same. |
| `wpa-supplicant` CLI flags (`--config`) | Stable across `0.x.y`. New flags are minor-bump events; renames are minor-bump deprecation events with a one-version overlap. |
| Config TOML schema | Adding optional fields is a patch-bump event. Removing or renaming a field is a minor-bump deprecation event with a one-version overlap. |
| Control-socket text protocol (`REAUTHENTICATE` / `LOGOFF` / `GET_STATE` / `SET_LOG_LEVEL <level>` / `SHUTDOWN`) | Stable across `0.x.y`. New commands are additive. The `GET_STATE` JSON schema is fenced by integration test `tests/control_status.rs` and changes are minor-bump events. |
| systemd unit files in `08-transition/packaging/` | Reference material; not part of the API. |

## 7. Phase 08 gate exit criteria

Per `04-design/phase-gate-report.md` template structure:

| Criterion | How verified |
|---|---|
| Release artifacts built and tested | x86_64 + aarch64 binary tarballs built; `cargo test --workspace` and `--ignored` both pass. |
| Source artifacts published | `pae` / `eapol-supp` / `eap-peer` / `logon` v0.1.0 visible on crates.io. |
| Deployment validated in target environment | At least one VM smoke run: install the deb (or extract the static tarball), enable `wpa-supplicant.socket`, send `REAUTHENTICATE` via `nc -U /run/wpa-supplicant/control.sock`, observe non-error response. |
| User documentation complete | `docs/PROGRESS.md` + `09-operation-maintenance/runbook.md` (P4.2) + `docs/SECURITY.md` + this release plan. |
| Verification evidence collected | `cargo audit`, `cargo deny`, `cargo test --ignored`, `cargo clippy`, `cargo fmt`, `cargo doc` outputs all archived in the release notes. |
| All TEST issues closed or deferred | The six TEST-VV issues (#139–#144) plus the seven security-review trackers (#150–#155) are categorized: closed, deferred to Phase 09, or assigned a Phase 08 owner. |
| All REQ-F / REQ-NF verified | `02-requirements/traceability-matrix.md` reflects v0.1.0 closing commits and tests. |

Once all rows say ✅, file `08-transition/phase-gate-report.md` and run `/phase-gate-check`.

## 8. Risks & open questions

| Risk | Mitigation |
|---|---|
| crates.io rate-limits / first-publish surprises | Use `--dry-run` for every crate first; sleep 45 s between publishes (see §3.5). |
| Path-dep version pin breaks workspace build | Test the version-pin change locally on a clean `cargo clean && cargo build --workspace` before pushing the release branch. |
| Cross-build cache miss in CI | `Swatinem/rust-cache@v2` keys by toolchain + target; the cross-build job already uses a separate cache key. No action needed. |
| `cargo audit` advisory landing between dry-run and publish | Re-run `cargo audit` immediately before each `cargo publish`. If a new advisory lands, defer the affected crate to a patch release with the fix. |
| Security-review Medium findings still open at v0.1.0 | Document explicitly in the release notes that #150–#152 are tracked Phase 09 mitigations and the v0.1.0 binary should be deployed only on hosts that already restrict access to the supplicant's UID. |
| YANG management surface decision (P5.3) still open | YANG/NETCONF management remains out of scope for v0.1.0. The decision is captured by the Phase 09 runbook §troubleshooting rather than blocking the release. |

## 9. Out-of-band tasks (do not block the release plan)

- Open follow-up issue: "Phase 08 publish script — `scripts/publish.sh`" — owner picks the actual implementation against the §3.5 sketch.
- Open follow-up issue: "GitHub Actions release workflow — tag-driven binary tarball + GitHub Release upload."

---

**Cross-references:**

- `09-operation-maintenance/runbook.md` (P4.2) — operator-facing daily operations for the released binary.
- `docs/SECURITY.md` — public security posture and reporting policy.
- `docs/PROGRESS.md` — phase / per-domain implementation status.
- `02-requirements/traceability-matrix.md` — REQ-by-REQ chain.
- `07-verification-validation/security-review-2026-06-13.md` — the Phase 07 → 08 security-review record.
