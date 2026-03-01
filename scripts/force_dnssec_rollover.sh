#!/bin/sh
set -e

if [ "${1:-}" != "--force" ]; then
  echo "This will delete DNSSEC keys. Re-run with --force to proceed." >&2
  exit 2
fi

echo "Stopping authoritative and resolver containers..."
docker compose stop authoritative_parent authoritative_child resolver resolver_plain >/dev/null

echo "Removing keys and signed zones..."
rm -rf bind9/keys/* bind9_parent/keys/* || true
rm -f bind9/zones/*.signed* bind9_parent/zones/*.signed* || true

echo "Starting authoritative servers..."
docker compose start authoritative_parent authoritative_child >/dev/null

echo "Recomputing DS + exporting trust anchor..."
docker compose run --rm ds_recompute >/dev/null
docker compose run --rm anchor_export >/dev/null

echo "Restarting resolvers..."
docker compose start resolver resolver_plain >/dev/null

echo "Done."
