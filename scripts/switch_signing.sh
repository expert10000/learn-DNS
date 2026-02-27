#!/bin/sh
set -euo pipefail

MODE="${1:-}"

if [ -z "$MODE" ]; then
  echo "Usage: switch_signing.sh <nsec|nsec3>"
  exit 2
fi

case "$MODE" in
  nsec)
    cp /bind9/named.inline.conf /bind9/named.conf
    cp /bind9_parent/named.inline.conf /bind9_parent/named.conf
    echo "Switched to inline NSEC."
    ;;
  nsec3)
    cp /bind9/named.offline.conf /bind9/named.conf
    cp /bind9_parent/named.offline.conf /bind9_parent/named.conf
    echo "Switched to offline NSEC3 config. Signing zones..."
    cd /tmp
    sh /switcher/sign_zones.sh nsec3
    ;;
  *)
    echo "Invalid mode: $MODE (expected nsec or nsec3)"
    exit 2
    ;;
esac
