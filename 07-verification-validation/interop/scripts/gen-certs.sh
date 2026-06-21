#!/usr/bin/env bash
# Throwaway cert chain for the Phase 07 V&V FreeRADIUS interop
# harness. CA + RADIUS server + supplicant client certs.
#
# IDEMPOTENT: if `certs/ca.pem` already exists, the script is a
# no-op. Delete the certs/ and freeradius/certs/ directories to
# regenerate.
#
# Per docs/TODO.md P3.1. Certs are *not* checked in — they live for
# the lifetime of a single harness run and carry no real-world trust.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_CERTS="$HERE/certs"
SERVER_CERTS="$HERE/freeradius/certs"

if [[ -f "$CLIENT_CERTS/ca.pem" && -f "$SERVER_CERTS/server.pem" ]]; then
    echo "[gen-certs] cert chain already exists — nothing to do."
    echo "[gen-certs] delete $CLIENT_CERTS and $SERVER_CERTS to regenerate."
    exit 0
fi

mkdir -p "$CLIENT_CERTS" "$SERVER_CERTS"

# --- Certificate Authority ---
echo "[gen-certs] generating CA"
openssl genrsa -out "$CLIENT_CERTS/ca.key" 2048 2>/dev/null
openssl req -new -x509 -days 30 -key "$CLIENT_CERTS/ca.key" \
    -out "$CLIENT_CERTS/ca.pem" \
    -subj "/C=US/O=wpa_supplicant-rs interop/CN=interop-harness-CA" 2>/dev/null
cp "$CLIENT_CERTS/ca.pem" "$SERVER_CERTS/ca.pem"

# --- RADIUS server cert ---
echo "[gen-certs] generating RADIUS server cert"
openssl genrsa -out "$SERVER_CERTS/server.key" 2048 2>/dev/null
openssl req -new -key "$SERVER_CERTS/server.key" -out "$SERVER_CERTS/server.csr" \
    -subj "/C=US/O=wpa_supplicant-rs interop/CN=freeradius.test" 2>/dev/null
openssl x509 -req -in "$SERVER_CERTS/server.csr" -days 30 \
    -CA "$CLIENT_CERTS/ca.pem" -CAkey "$CLIENT_CERTS/ca.key" -CAcreateserial \
    -out "$SERVER_CERTS/server.pem" -extfile <(cat <<EOF
extendedKeyUsage = serverAuth
EOF
) 2>/dev/null
rm -f "$SERVER_CERTS/server.csr"

# --- Supplicant client cert ---
echo "[gen-certs] generating supplicant client cert"
openssl genrsa -out "$CLIENT_CERTS/client.key" 2048 2>/dev/null
openssl req -new -key "$CLIENT_CERTS/client.key" -out "$CLIENT_CERTS/client.csr" \
    -subj "/C=US/O=wpa_supplicant-rs interop/CN=alice@example.com" 2>/dev/null
openssl x509 -req -in "$CLIENT_CERTS/client.csr" -days 30 \
    -CA "$CLIENT_CERTS/ca.pem" -CAkey "$CLIENT_CERTS/ca.key" -CAcreateserial \
    -out "$CLIENT_CERTS/client.pem" -extfile <(cat <<EOF
extendedKeyUsage = clientAuth
EOF
) 2>/dev/null
rm -f "$CLIENT_CERTS/client.csr"

# --- Diffie-Hellman params for RADIUS ---
# 2048 bits: OpenSSL 3 (used by the freeradius-server alpine image)
# rejects <2048-bit DH at SSL-context init with "dh key too small",
# which was the #138 exit-1 root cause. Interop-only, not for prod.
if [[ ! -f "$SERVER_CERTS/dh.pem" ]]; then
    echo "[gen-certs] generating DH params (2048 bits — interop only, not for prod)"
    openssl dhparam -out "$SERVER_CERTS/dh.pem" 2048 2>/dev/null
fi

# Tighten permissions — secrets are throwaway but still secrets.
chmod 600 "$CLIENT_CERTS"/*.key "$SERVER_CERTS"/*.key

echo "[gen-certs] done. Cert chain ready in $CLIENT_CERTS and $SERVER_CERTS"