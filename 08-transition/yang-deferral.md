# YANG Management Surface — Scope Deferral

**Implements:** `docs/TODO.md` P5.3.
**Date:** 2026-06-13.
**Decision:** Defer NETCONF / YANG management to v1.x at the earliest. No `ADR-MGMT-009` is opened today.

This note is the durable artifact for the P5.3 scope decision recorded against `wpa_supplicant-rs`. It exists so that any future contributor reading this codebase, the sibling reference repo, or `docs/TODO.md`, finds **one** authoritative answer to "where does YANG fit into this project?" — namely, *not in v0.1.0*.

---

## 1. Context

### 1.1 The sibling reference repo

`../8021X-2020.YANG/` (one level above this project) contains the **official YANG modules for IEEE 802.1X-2020**, plus their IETF / IANA transitive deps. Per `CLAUDE.md` §7, the project treats that repo as **reference-only** — a permitted on-disk source for canonical attribute names and the eventual NETCONF management surface.

### 1.2 The choice P5.3 puts on the table

`docs/TODO.md` P5.3 framed it as a binary:

- **(a)** Open `ADR-MGMT-009: NETCONF/YANG management surface` via `SKILL/prompts/architecture-starter.prompt.md` — i.e. plan the management surface now.
- **(b)** Add an explicit deferral note documenting that the scope decision is "not yet" — i.e. keep the question on file but don't pull it into the v0.1.0 critical path.

This document chooses **(b)**.

## 2. Why defer

| Reason | Detail |
|---|---|
| **No production consumer.** | Zero Rust source files in `crates/**` import anything YANG- / NETCONF-related; `cargo tree` shows zero YANG-adjacent transitive deps. The reference modules are read by humans (and by the `ieee-traceability-reviewer` subagent) for vocabulary, not by the binary at runtime. |
| **Scope mismatch with v0.1.0.** | The release plan (`08-transition/release-plan.md`) targets *the supplicant binary plus four library crates* as the deployable surface. NETCONF / YANG would land another crate, another transitive dependency stack (`yang-rs` or equivalent), and a separate management daemon contract (`netconfd` / `sysrepo` / similar). That is a Phase-09 enhancement, not a transition prerequisite. |
| **Operator surface already covered.** | The v0.1.0 control surface — config TOML + Unix-socket text protocol with `REAUTHENTICATE` / `LOGOFF` / `GET_STATE` / `SET_LOG_LEVEL` / `SHUTDOWN` — is documented end-to-end in `09-operation-maintenance/runbook.md`. Operators today do not need YANG / NETCONF to run, observe, or recover the daemon. |
| **No requirement traces here.** | Re-checking `02-requirements/traceability-matrix.md`: no `REQ-F-MGMT-…` rows exist; no `REQ-NF-MGMT-…` rows either. The *Linux deployment* requirements (`REQ-NF-DEPLOY-001..005`, `StR-007`) are satisfied by config + socket + systemd; they do not call for management-by-YANG. |
| **YANG is a model, not a transport.** | Even if the project eventually exposes a YANG schema, the model alone is half the work — it has to be served by something (NETCONF / RESTCONF / gNMI). Picking the transport is itself an ADR. Today's deferral is a deliberate *single decision*: *not now, full stop.* |

## 3. What this deferral commits us to

1. The reference repo `../8021X-2020.YANG/` stays **reference-only** for the foreseeable future. Contributors may consult it for canonical attribute spellings (`ieee802-dot1x.yang`, `ieee802-dot1x-eapol.yang`, `ieee802-dot1x-types.yang`) when writing config-schema field names or trace-log key names — this is what `CLAUDE.md` §7 already permits.
2. **No new crate** is added to the workspace for YANG / NETCONF / RESTCONF / gNMI in v0.1.0 or any v0.1.x patch line.
3. **No new feature flag** named `yang` / `netconf` / `restconf` is added to existing crates in v0.1.x.
4. The runbook (`09-operation-maintenance/runbook.md` §11 *Known caveats*) and the release plan (`08-transition/release-plan.md` §6 *Out-of-band tasks*) both record the deferral and point here.

## 4. What lifts the deferral

This deferral becomes obsolete the day **any one** of the following is true:

- A v1.x ADR is opened that proposes a concrete management transport (NETCONF / RESTCONF / gNMI) with rationale, a candidate Rust crate, and a stability story.
- A `REQ-F-MGMT-NNN` or `REQ-NF-MGMT-NNN` row lands in `02-requirements/traceability-matrix.md`.
- An operator-facing GitHub issue accumulates concrete demand for management-by-YANG with a use case that the current control socket cannot meet.

When that day arrives, the next contributor opens `ADR-MGMT-009: NETCONF/YANG management surface` via `SKILL/prompts/architecture-starter.prompt.md`, references this note, and proceeds. Until then, the question is closed.

## 5. Cross-references

- `../8021X-2020.YANG/README.md` — the reference repo's own description (read-only from this project's perspective).
- `CLAUDE.md` §7 — the project rule that pins the YANG repo as reference-only.
- `docs/TODO.md` P5.3 — the action item this note closes.
- `08-transition/release-plan.md` §6 *Out-of-band tasks* — release-side view of the deferral.
- `09-operation-maintenance/runbook.md` §11 *Known caveats* — operator-side view of the deferral.
