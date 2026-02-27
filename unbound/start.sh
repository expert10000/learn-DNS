#!/bin/sh
set -e

ANCHOR="/opt/unbound/etc/unbound/anchors/test.key"
CONTROL_DIR="/opt/unbound/etc/unbound"
echo "Waiting for test. trust anchor at ${ANCHOR}..."

while true; do
  if [ -s "${ANCHOR}" ] && (grep -q " DNSKEY 257 " "${ANCHOR}" 2>/dev/null || grep -q " DS " "${ANCHOR}" 2>/dev/null); then
    break
  fi
  sleep 1
done

# Ensure control certs exist for unbound-control (flush support).
if [ ! -s "${CONTROL_DIR}/unbound_server.key" ]; then
  /opt/unbound/sbin/unbound-control-setup -d "${CONTROL_DIR}" >/dev/null 2>&1 || true
fi

exec /unbound.sh
