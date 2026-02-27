#!/bin/sh
set -e

CERT_DIR="${CERT_DIR:-/certs}"
CERT_PATH="${CERT_DIR}/doh.pem"
KEY_PATH="${CERT_DIR}/doh.key"

if [ ! -s "${CERT_PATH}" ] || [ ! -s "${KEY_PATH}" ]; then
  mkdir -p "${CERT_DIR}"
  umask 077
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=doh.test" \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" >/dev/null 2>&1 || true
fi

exec uvicorn api.main:app \
  --host 0.0.0.0 \
  --port 443 \
  --ssl-keyfile "${KEY_PATH}" \
  --ssl-certfile "${CERT_PATH}" \
  --log-level "${LOG_LEVEL:-warning}"
