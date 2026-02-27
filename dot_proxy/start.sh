#!/bin/sh
set -e

CERT_DIR="${CERT_DIR:-/certs}"
CERT_PATH="${CERT_DIR}/dot.pem"
KEY_PATH="${CERT_DIR}/dot.key"

if [ ! -s "${CERT_PATH}" ] || [ ! -s "${KEY_PATH}" ]; then
  mkdir -p "${CERT_DIR}"
  umask 077
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=dot.test" \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" >/dev/null 2>&1 || true
fi

exec python -m api.main
