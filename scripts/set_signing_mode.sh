#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
RUN_SIGNER="${2:-}"

if [[ -z "$MODE" ]]; then
  echo "Usage: $0 <nsec|nsec3> [--run-signer]"
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHILD_DIR="${ROOT_DIR}/bind9"
PARENT_DIR="${ROOT_DIR}/bind9_parent"

case "$MODE" in
  nsec)
    rm -f "${CHILD_DIR}/zones/db.example.test.signed" \
      "${CHILD_DIR}/zones/db.example.test.signed.jnl" \
      "${CHILD_DIR}/zones/db.example.test.internal.signed" \
      "${CHILD_DIR}/zones/db.example.test.internal.signed.jnl" \
      "${PARENT_DIR}/zones/db.test.signed" \
      "${PARENT_DIR}/zones/db.test.signed.jnl" || true
    cp "${CHILD_DIR}/named.inline.conf" "${CHILD_DIR}/named.conf"
    cp "${PARENT_DIR}/named.inline.conf" "${PARENT_DIR}/named.conf"
    echo "Applied inline NSEC mode."
    ;;
  nsec3)
    cp "${CHILD_DIR}/named.offline.conf" "${CHILD_DIR}/named.conf"
    cp "${PARENT_DIR}/named.offline.conf" "${PARENT_DIR}/named.conf"
    echo "Applied offline NSEC3 mode."
    if [[ "$RUN_SIGNER" == "--run-signer" ]]; then
      docker compose run --rm signer
    else
      echo "Offline NSEC3 requires signed zone files. Run:"
      echo "  docker compose run --rm signer"
    fi
    ;;
  *)
    echo "Invalid mode: $MODE (expected nsec or nsec3)"
    exit 2
    ;;
esac

if [[ "$MODE" == "nsec3" ]]; then
  echo "Then restart authoritative containers:"
  echo "  docker compose restart authoritative_parent authoritative_child"
  echo "If keys changed, refresh DS + trust anchor:"
  echo "  docker compose run --rm ds_recompute"
  echo "  docker compose run --rm anchor_export"
  echo "  docker compose restart resolver"
else
  echo "Restart authoritative containers to apply:"
  echo "  docker compose restart authoritative_parent authoritative_child"
fi
