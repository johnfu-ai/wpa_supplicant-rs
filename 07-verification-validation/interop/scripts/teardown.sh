#!/usr/bin/env bash
# Tear down the FreeRADIUS interop harness: stop containers, delete
# the veth pair and netns, optionally wipe the cert chain.
#
# Per docs/TODO.md P3.1.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

NETNS="wpa-sup-interop"
VETH_HOST="veth-host"

# Stop and remove containers + networks defined by docker-compose.
if command -v docker >/dev/null 2>&1; then
    (cd "$HERE" && docker compose down --remove-orphans 2>/dev/null) || true
fi

# Remove the veth pair (deleting one end removes both).
ip link delete "$VETH_HOST" 2>/dev/null || true

# Remove the network namespace.
if [[ $EUID -eq 0 ]]; then
    ip netns delete "$NETNS" 2>/dev/null || true
else
    sudo ip netns delete "$NETNS" 2>/dev/null || true
fi

# Optional cert chain wipe (off by default — `gen-certs.sh` is
# idempotent so leaving them in place is fine).
if [[ "${1:-}" == "--wipe-certs" ]]; then
    rm -rf "$HERE/certs" "$HERE/freeradius/certs"
    echo "[teardown] cert chain wiped"
fi

# Remove the generated supplicant.toml if present.
rm -f "$HERE/supplicant.toml"

echo "[teardown] done"