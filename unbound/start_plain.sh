#!/bin/sh
set -e

TLS_DIR="/opt/unbound/etc/unbound/tls"
TLS_KEY="${TLS_DIR}/server.key"
TLS_CERT="${TLS_DIR}/server.pem"

# Ensure a self-signed cert exists for DoT.
if [ ! -s "${TLS_KEY}" ] || [ ! -s "${TLS_CERT}" ]; then
  mkdir -p "${TLS_DIR}"
  umask 077
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=resolver.test" \
    -keyout "${TLS_KEY}" \
    -out "${TLS_CERT}" >/dev/null 2>&1 || true
fi
if [ -s "${TLS_KEY}" ]; then
  chown _unbound:_unbound "${TLS_KEY}" "${TLS_CERT}" 2>/dev/null || true
  chmod 640 "${TLS_KEY}" 2>/dev/null || true
  chmod 644 "${TLS_CERT}" 2>/dev/null || true
fi

exec /unbound.sh
