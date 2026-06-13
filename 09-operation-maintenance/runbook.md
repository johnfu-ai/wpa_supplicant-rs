# Operator Runbook — wpa_supplicant-rs

**Implements:** `docs/TODO.md` P4.2.
**Standard anchor:** ISO/IEC/IEEE 12207:2017 (Maintenance Process).
**Verifies:** REQ-NF-DEPLOY-001..005 (Linux deployment), REQ-NF-REL-001/002 (reliability).
**Date:** 2026-06-13.

This document is the **operator-facing runbook** for running `wpa_supplicant-rs` in production. Pair it with `08-transition/release-plan.md` (release-side concerns) and `docs/SECURITY.md` (security posture / vulnerability reporting).

---

## 1. What this binary is

`wpa-supplicant` is a clean-room IEEE 802.1X-2020 **supplicant** in Rust — supplicant role only. It speaks EAPOL on the wire to an Authenticator (a switch port or a `hostapd` wired-mode bridge), runs the EAP method exchange to derive an MSK, and (optionally) participates in MKA so a MACsec-capable peer can install a Secure Association Key (SAK) and bring the Controlled Port to Secured.

It does **not** do any of these:

- Run as Authenticator. (Use `hostapd` for the Authenticator side.)
- Replace `wpa_supplicant(8)` for wireless 802.11 — this is an 802.1X supplicant; wireless WPA/WPA2/WPA3 four-way-handshake is out of scope.
- Provide MACsec dataplane encryption itself. The kernel `macsec` module installs the SAK derived by this daemon and does the actual frame encryption.

## 2. Quick start

### 2.1 Install (from a release tarball)

```sh
# Pick the matching architecture tarball from the GitHub Release.
sudo tar -C /usr/local -xzf wpa-supplicant-v0.1.0-x86_64-linux-gnu.tar.gz

sudo install -d /etc/wpa-supplicant /run/wpa-supplicant /var/log/wpa-supplicant
sudo cp /usr/local/share/wpa-supplicant/wpa-supplicant.conf.example \
        /etc/wpa-supplicant/wpa-supplicant.conf

sudo cp /usr/local/share/wpa-supplicant/systemd/wpa-supplicant.service \
        /etc/systemd/system/
sudo cp /usr/local/share/wpa-supplicant/systemd/wpa-supplicant.socket \
        /etc/systemd/system/
sudo systemctl daemon-reload
```

### 2.2 Configure

Edit `/etc/wpa-supplicant/wpa-supplicant.conf` (TOML). Minimum useful body:

```toml
[interface]
name = "eth0"

[eap]
identity = "alice@example.com"

[eap.tls]
ca_cert = "/etc/wpa-supplicant/certs/ca.pem"
client_cert = "/etc/wpa-supplicant/certs/client.pem"
private_key = "/etc/wpa-supplicant/certs/client.key"
verify_server = true                # MUST stay true in production

[control]
socket_path = "/run/wpa-supplicant/control.sock"

[logging]
level = "info"                      # error | warn | info | debug | trace
```

The full schema lives next to the binary in `wpa-supplicant.conf.example`. Optional sections: `[macsec]` (PSK-based CAK), `[logon]` (NID groups for multi-network selection).

### 2.3 Run

```sh
sudo systemctl enable --now wpa-supplicant.socket
sudo systemctl status wpa-supplicant
sudo journalctl -u wpa-supplicant -f          # live logs
```

The `.socket` unit owns `/run/wpa-supplicant/control.sock`. The `.service` unit is socket-activated; the daemon starts the first time `systemctl start wpa-supplicant` runs or a control client connects.

## 3. Daily operations

### 3.1 Inspecting state

The control socket speaks a tiny line-oriented text protocol. `socat` and `nc` both work; `wpa-supplicant-ctl` (a future thin client wrapper, tracked under Phase 09 — see §10) will eventually replace these.

```sh
# Get the JSON state blob.
echo "GET_STATE" | sudo nc -U /run/wpa-supplicant/control.sock | jq .

# Trigger a reauthentication.
echo "REAUTHENTICATE" | sudo nc -U /run/wpa-supplicant/control.sock

# Send EAPOL-Logoff (release the port).
echo "LOGOFF" | sudo nc -U /run/wpa-supplicant/control.sock

# Reload the log filter at runtime — same syntax as RUST_LOG.
echo "SET_LOG_LEVEL debug" | sudo nc -U /run/wpa-supplicant/control.sock
echo "SET_LOG_LEVEL info"  | sudo nc -U /run/wpa-supplicant/control.sock

# Graceful shutdown (the systemd unit will normally be the one calling this).
echo "SHUTDOWN" | sudo nc -U /run/wpa-supplicant/control.sock
```

The `GET_STATE` JSON schema is **stable across the `0.x.y` line** — fenced by integration test `crates/wpa-supplicant/tests/control_status.rs`. Each field reports the sub-state-machine that owns it; fields whose owner state machine is not yet constructed are `null` / `false` / `0` (see §11 for the v0.1.0 surface).

### 3.2 Log-level tuning

The `tracing-subscriber` filter accepts `error | warn | info | debug | trace` directly, or full env-filter syntax such as `wpa_supplicant=debug,pae=trace`. **Hot-reload via the control socket; no restart needed.**

| Symptom | Try |
|---|---|
| Boring logs at `info` | `SET_LOG_LEVEL debug` to see PAE state transitions. |
| Need MKPDU detail | `SET_LOG_LEVEL pae::mka=trace,pae::mkpdu=trace`. |
| Suspect EAPOL framing | `SET_LOG_LEVEL eapol_supp=trace`. |
| Production noise | Default `info`. Anything finer is a debugging session, not a steady state. |

`debug` and `trace` levels MUST NOT log secret material (CAK / SAK / KEK / ICK / MSK). All secret types (`Cak`, `Sak`, `Kek`, `Ick`, `Msk`) carry redacting `Debug` impls and `ZeroizeOnDrop`; verified by the Phase 07 security review (§Items confirmed clean in `07-verification-validation/security-review-2026-06-13.md`). Open finding #151 covers `MacsecConfig::psk` redaction.

### 3.3 Restart vs. reconfigure

| Change | Action |
|---|---|
| Edit `[logging] level` in config | Hot-reload via `SET_LOG_LEVEL` — no restart. |
| Edit `[interface]`, `[eap]`, or `[macsec]` | `systemctl restart wpa-supplicant` (the daemon does not yet hot-reload protocol config; tracked Phase 09 enhancement). |
| Replace certs at the paths in `[eap.tls]` | `systemctl restart wpa-supplicant` (the cert chain is read once at boot). |

### 3.4 Cycling auth without restart

Use `REAUTHENTICATE` if you suspect the Authenticator's session timer has drifted, or you want to force a fresh EAP exchange after a cert rotation that did not require a config change. `LOGOFF` brings the port back to Disconnected (Cl.8.5); a follow-up `REAUTHENTICATE` (or link-down/up event) restarts the PACP cycle.

## 4. systemd integration

### 4.1 Unit examples

`/etc/systemd/system/wpa-supplicant.service`:

```ini
[Unit]
Description=IEEE 802.1X-2020 Supplicant (wpa_supplicant-rs)
Documentation=https://github.com/johnfu-ai/wpa_supplicant-rs
After=network-pre.target
Wants=network-pre.target
Requires=wpa-supplicant.socket
ConditionPathExists=/etc/wpa-supplicant/wpa-supplicant.conf

[Service]
Type=notify
ExecStart=/usr/local/bin/wpa-supplicant --config /etc/wpa-supplicant/wpa-supplicant.conf
Restart=on-failure
RestartSec=2

# Security hardening — see also docs/SECURITY.md.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=false                 # raw socket needs /dev/null at minimum
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/wpa-supplicant /var/log/wpa-supplicant
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_PACKET AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/wpa-supplicant.socket`:

```ini
[Unit]
Description=Control socket for wpa_supplicant-rs

[Socket]
ListenStream=/run/wpa-supplicant/control.sock
SocketUser=root
SocketGroup=wpa-control
SocketMode=0660                      # see security-review finding F-01 (#150)
DirectoryMode=0755
RemoveOnStop=true

[Install]
WantedBy=sockets.target
```

The `wpa-control` group is the principal-of-least-privilege gate for who may issue control commands. Add operators with `usermod -aG wpa-control alice`.

### 4.2 Socket activation contract

`wpa-supplicant` honours systemd's socket-activation env vars (`LISTEN_FDS`, `LISTEN_PID`). Open follow-up: security-review finding F-06 (#154) — `LISTEN_PID` is not yet validated, so do not attach the unit's listen socket as a dropped FD from a non-systemd parent. In a normal `systemd start` flow this never matters.

### 4.3 Log routing

`tracing-subscriber` writes to stderr; systemd captures stderr into the journal. Use `journalctl -u wpa-supplicant` to read, `--since` / `--until` / `--grep` to filter. There is no separate logfile path in the binary; if you need persistent rotated logs outside the journal, configure `journald` itself (`SystemMaxUse=` etc).

## 5. Troubleshooting matrix

| Symptom | First diagnostic | Likely cause | Fix |
|---|---|---|---|
| `systemctl start wpa-supplicant` exits with `EPERM` on the AF_PACKET socket | `journalctl -u wpa-supplicant -n 20` | Service has no `CAP_NET_RAW` | Check `AmbientCapabilities=` in the service file. Re-run `systemctl daemon-reload`. |
| Daemon comes up but `pae_state` stays `Disconnected` | `GET_STATE` then `journalctl -u wpa-supplicant -f` | Link is down on the configured interface, or interface name typo | `ip link show <iface>` confirms presence + state. Edit `[interface] name` and restart. |
| `pae_state` reaches `Connecting` but never `Authenticated` | `SET_LOG_LEVEL debug`, then re-attempt | EAP method failure (cert path wrong, server cert untrusted, identity rejected by RADIUS) | Verify `[eap.tls]` paths exist and chain to the configured `ca_cert`. RADIUS-side: `radclient` against the AS to confirm the user record. |
| `pae_state` is `Authenticated` but `cp_state` is not `Secured` | `GET_STATE` | (a) MKA participant not yet constructed for non-MACsec setups (expected; CP stays `Open`). (b) For MACsec setups: distributed-SAK MKPDU not received from the Authenticator. (c) Pre-#135 builds: `unwrap_sak` was stubbed — upgrade to ≥ v0.1.0. | (a) is normal for plain 802.1X. (b) check Authenticator MKA logs. (c) `wpa-supplicant --version`; upgrade if pre-PR #146. |
| Repeated `EAPOL Type=2 (Logoff)` then re-auth from us, with link bouncing | `journalctl --grep 'link_changed'` | NIC driver is flapping carrier, or the switch port is fast-cycling (e.g. PortFast misconfig) | `ethtool <iface>` for link-flap counters; ask the switch admin. |
| Control commands hang (the `nc -U` blocks indefinitely) | `ss -lUx` to confirm the socket exists; `lsof <socket>` | Open security-review finding F-02 (#150) — unbounded read can lock the listener mutex | Workaround: `timeout 2 nc -U /run/wpa-supplicant/control.sock`. Mitigation lands under #150. |
| `cargo audit` reports a new advisory between releases | `cargo audit` against the deployed lock file | Transitive crate gained an advisory | If the advisory affects our usage, file an issue and ship a patch release that bumps the lock. The Phase 09 `Adaptive` maintenance flow (`SKILL/instructions/phase-09-operation-maintenance.instructions.md`) covers this. |
| Daemon panics in production | `journalctl -u wpa-supplicant --grep panic -B5 -A20` | Genuine bug; production code carries no `panic!` / `unwrap()` in non-test paths (see Phase 07 security review §3 confirmed-clean) so any panic is a regression | File a `type:bug` issue with the journal excerpt. Until a fix lands, `Restart=on-failure` will respin the daemon — but log the incident, do not normalize the loop. |

## 6. Performance expectations

The 12 `#[ignore]`-gated wall-clock perf tests (verified 2026-06-13 per `docs/TODO.md` P5.5) bound the worst-case latencies you should see on a representative x86_64 host:

| Operation | Target |
|---|---|
| EAPOL response latency, single | sub-ms |
| EAPOL response latency, 95th percentile | sub-ms |
| `pae.step()` bounded execution | sub-ms |
| `pae.handle_eapol()` bounded execution | sub-ms |
| CP transition latency / 95th | sub-ms |
| MKA transition latency / 95th | sub-ms |
| Timer-wheel `advance` bounded | sub-ms |

If you see CPU spikes correlated with PAE transitions, file an issue against `pae` with a reproducer. The ignored-perf suite is the canonical regression check (see `crates/eapol-supp/src/supplicant_pae.rs` and `crates/pae/src/{cp,mka,timer}.rs`).

## 7. Security operations

- **Vulnerability reports:** see `docs/SECURITY.md`. Use the GitHub private-vulnerability-reporting form, not public issues.
- **Supply chain:** every push and PR is gated by `cargo audit` (RustSec advisories) and `cargo deny check` (license + bans + sources). Policy at `deny.toml`.
- **Secret hygiene:** the daemon redacts CAK / SAK / KEK / ICK / MSK from all log levels. `MacsecConfig::psk` redaction is currently open as #151 — operators with a configured PSK should ensure config files are mode `0600` and not include them in support bundles unredacted.
- **Open Medium-severity findings (Phase 09 mitigations):** #150 (control-socket chmod + DoS), #151 (psk redact), #152 (TLS private_key zeroize). None block the v0.1.0 release per the security review verdict; all should be closed before a v1.0 line is cut.

## 8. Backup & disaster recovery

The daemon is **stateless across restarts** for the protocol layer — every PAE / CP / MKA / Logon state machine reinitializes from the configured identity + certs + (optional) PSK on boot. The only durable state on disk is:

- The config file (`/etc/wpa-supplicant/wpa-supplicant.conf`) — version it under your config-management of choice.
- The cert chain pointed to by `[eap.tls]`. Keys here are sensitive; treat them like SSH host keys.
- (Future) a CAK cache for `logon` (#37 LOGON-005) — currently in-memory only; no on-disk persistence in v0.1.0.

There is no on-disk database to backup. A clean restore is "drop the cert chain in place, start the unit, watch the journal."

## 9. Upgrade path

| Source | Target | Procedure |
|---|---|---|
| `0.1.x` → `0.1.(x+1)` | patch | `systemctl stop wpa-supplicant` → swap binary → `systemctl start wpa-supplicant`. No config changes. |
| `0.x.y` → `0.(x+1).0` | minor | Read the CHANGELOG `Removed` / `Deprecated` / `Changed` sections. Adjust the config if needed. Schema breaks are minor-bump events, never patch. |
| (future) `0.x` → `1.0` | major | Will carry a dedicated migration appendix. Anticipated breaks: `[eap.tls]` cert handling once #133 ships a real `RustlsEngine`. |

## 10. Where to file work

| Concern | Channel |
|---|---|
| Bug | GitHub Issue, label `type:bug`. Include `wpa-supplicant --version`, the journal excerpt, `GET_STATE` output, and the Authenticator's vendor / model. |
| Feature request | GitHub Issue, label `type:feature-request`. Reference the closest REQ-F / REQ-NF in `02-requirements/traceability-matrix.md`. |
| Security vulnerability | **NOT a public issue.** Use GitHub private-vulnerability-reporting per `docs/SECURITY.md`. |
| Documentation gap (this runbook is wrong) | GitHub Issue, label `type:docs`. PRs welcome. |

## 11. Known caveats in v0.1.0

These are **operational caveats, not blockers** — every one has a tracking issue and a planned mitigation.

- The `MkaParticipant` is constructed automatically only when an EAP-derived MSK is available **and** a `[macsec]` section is present in the config. For plain 802.1X (no MACsec), MKA never starts and `cp_state` stays `Open` — that is the standards-correct behaviour, not a bug.
- The control socket file mode is whatever `umask` produced at bind time (#150). Until the chmod-on-bind fix lands, rely on `wpa-supplicant.socket`'s `SocketMode=0660` and run **only** under the systemd unit (not directly with `--config` from a non-systemd parent).
- The full FreeRADIUS interop harness in `07-verification-validation/interop/` has its CI gate behind `workflow_dispatch` only (#138). Local runs work; CI auto-trigger is deferred to Phase 09.
- The CAK cache (`logon::CakCache`) is in-memory only. Restarts re-derive on next EAP success.
- A `wpa-supplicant-ctl` thin client wrapping the text protocol with a `--json` mode is **planned, not shipped** — track it as a Phase 09 enhancement issue. For v0.1.0, drive the socket with `nc -U` or `socat`.

---

**Cross-references:**

- `08-transition/release-plan.md` (P4.1) — release-side concerns: versioning, publish strategy, distribution packaging.
- `docs/SECURITY.md` — vulnerability reporting, supply-chain CI gate.
- `docs/PROGRESS.md` — phase / per-domain implementation status.
- `02-requirements/traceability-matrix.md` — REQ-by-REQ chain.
- `07-verification-validation/security-review-2026-06-13.md` — open security findings (#150–#155).
