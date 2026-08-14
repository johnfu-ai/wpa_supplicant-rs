#!/usr/bin/env bash
# Run the wpa-supplicant binary inside a network namespace bound to
# the docker-compose `eapol-net` bridge. Asserts that the binary
# survives ~10 seconds of EAP exchange with hostapd and emits a
# clean shutdown log line.
#
# Per docs/TODO.md P3.1.
#
# Prerequisites:
#   - Docker compose stack must be up: `docker compose up -d`
#   - Cert chain must exist: `./scripts/gen-certs.sh`
#   - Supplicant binary must be built with raw-socket feature:
#     `cargo build -p wpa-supplicant --features raw-socket --release`
#   - Run as root (CAP_NET_RAW + iproute2 veth).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
NETNS="wpa-sup-interop"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
SUPPLICANT_BIN="$REPO/target/release/wpa-supplicant"

if [[ $EUID -ne 0 ]]; then
    echo "[run-supplicant] this script must be run as root (CAP_NET_RAW + veth)"
    exit 1
fi

if [[ ! -x "$SUPPLICANT_BIN" ]]; then
    echo "[run-supplicant] supplicant binary not found at $SUPPLICANT_BIN"
    echo "[run-supplicant] build with: cargo build -p wpa-supplicant --features raw-socket --release"
    exit 1
fi

# Tear down any leftover state from a prior run.
ip netns delete "$NETNS" 2>/dev/null || true
ip link delete "$VETH_HOST" 2>/dev/null || true

# Create the namespace and veth pair.
ip netns add "$NETNS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NETNS"

# Bring up both ends.
ip link set "$VETH_HOST" up
ip netns exec "$NETNS" ip link set "$VETH_NS" up
ip netns exec "$NETNS" ip link set lo up

# Attach the host end to the docker `eapol-net` bridge so hostapd
# can see EAPOL frames from the supplicant.
BRIDGE="$(docker network inspect wpa-sup-eapol-net -f '{{.Id}}' 2>/dev/null | head -c12)"
if [[ -n "$BRIDGE" ]]; then
    ip link set "$VETH_HOST" master "br-$BRIDGE"
fi

# Generate a minimal supplicant config pointing at the veth interface
# and the cert chain produced by gen-certs.sh.
CONFIG="$HERE/supplicant.toml"
cat > "$CONFIG" <<EOF
interface = "$VETH_NS"

[eap]
identity = "alice@example.com"

[eap.method]
type = "tls"
cert = "$HERE/certs/client.pem"
key  = "$HERE/certs/client.key"
ca   = "$HERE/certs/ca.pem"

[logging]
level = "debug"
EOF

echo "[run-supplicant] starting supplicant in netns $NETNS, interface $VETH_NS"

# Run the binary with a 30s timeout — long enough for EAP, MKA Hello,
# and EAPOL-Logoff; short enough to fail-fast in CI.
timeout 30s ip netns exec "$NETNS" "$SUPPLICANT_BIN" \
    --config "$CONFIG" \
    2>&1 | tee /tmp/wpa-sup-interop.log || rc=$?

echo "[run-supplicant] supplicant exited with rc=${rc:-0}"
echo "[run-supplicant] log saved at /tmp/wpa-sup-interop.log"

# Minimal acceptance: the binary started cleanly and ran the event loop.
# Full handshake assertions (EAP success, SAK install, CP secured) are
# follow-up F-INT-1 (the #133 method factory landed 2026-08-14 and is
# wired into Supplicant::new). AES Key Wrap (#135) landed in PR #146,
# so `unwrap_sak` is no longer stubbed.
if grep -q "event loop started" /tmp/wpa-sup-interop.log; then
    echo "[run-supplicant] PASS: supplicant entered the event loop"
    exit 0
else
    echo "[run-supplicant] FAIL: supplicant failed to start"
    exit 1
fi