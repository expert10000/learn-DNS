#!/bin/sh
set -e

OUTDIR="${1:-backups}"
ts=$(date +"%Y%m%d-%H%M%S")
dest="${OUTDIR}/dnssec-keys-${ts}.tar.gz"

mkdir -p "$OUTDIR"
echo "Creating backup: $dest"
tar -czf "$dest" bind9/keys bind9_parent/keys
echo "Done."
