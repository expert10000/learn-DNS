#!/bin/sh
set -e

ANCHOR="/opt/unbound/etc/unbound/anchors/test.key"
echo "Waiting for test. trust anchor at ${ANCHOR}..."

while true; do
  if [ -s "${ANCHOR}" ] && (grep -q " DNSKEY 257 " "${ANCHOR}" 2>/dev/null || grep -q " DS " "${ANCHOR}" 2>/dev/null); then
    break
  fi
  sleep 1
done

exec /unbound.sh
