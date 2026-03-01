#!/bin/sh
set -euo pipefail

MODE="${1:-}"

if [ -z "$MODE" ]; then
  echo "Usage: switch_signing.sh <nsec|nsec3>"
  exit 2
fi

case "$MODE" in
  nsec)
    rm -f /bind9/zones/db.example.test.signed \
      /bind9/zones/db.example.test.signed.jnl \
      /bind9/zones/db.example.test.internal.signed \
      /bind9/zones/db.example.test.internal.signed.jnl \
      /bind9_parent/zones/db.test.signed \
      /bind9_parent/zones/db.test.signed.jnl || true
    cp /bind9/named.inline.conf /bind9/named.conf
    cp /bind9_parent/named.inline.conf /bind9_parent/named.conf
    echo "Switched to inline NSEC."
    ;;
  nsec3)
    # Ensure no stale journals from previous inline/offline runs.
    rm -f /bind9/zones/db.example.test.signed.jnl \
      /bind9/zones/db.example.test.internal.signed.jnl \
      /bind9_parent/zones/db.test.signed.jnl || true
    cp /bind9/named.offline.conf /bind9/named.conf
    cp /bind9_parent/named.offline.conf /bind9_parent/named.conf
    echo "Switched to offline NSEC3 config. Signing zones..."
    cd /tmp
    sh /switcher/sign_zones.sh nsec3
    # Remove any journal created during signing to avoid rollforward mismatch.
    rm -f /bind9/zones/db.example.test.signed.jnl \
      /bind9/zones/db.example.test.internal.signed.jnl \
      /bind9_parent/zones/db.test.signed.jnl || true
    ;;
  *)
    echo "Invalid mode: $MODE (expected nsec or nsec3)"
    exit 2
    ;;
esac
