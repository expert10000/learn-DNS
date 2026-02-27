#!/bin/sh
set -euo pipefail

MODE="${1:-nsec3}"

if [ "$MODE" != "nsec3" ]; then
  echo "Usage: sign_zones.sh [nsec3]"
  exit 2
fi

log() {
  echo "[signer] $*"
}

gen_salt() {
  dd if=/dev/urandom bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

ensure_keys() {
  zone="$1"
  keyname="$2"
  keydir="$3"

  if ls "$keydir"/K${keyname}.+013+*.key >/dev/null 2>&1; then
    return 0
  fi

  log "Generating keys for ${zone} in ${keydir}"
  dnssec-keygen -K "$keydir" -a ECDSAP256SHA256 -b 256 -f KSK -n ZONE "$zone" >/dev/null
  dnssec-keygen -K "$keydir" -a ECDSAP256SHA256 -b 256 -n ZONE "$zone" >/dev/null
}

sign_zone() {
  zone="$1"
  zonefile="$2"
  keydir="$3"

  keyname="${zone%.}"

  ensure_keys "$zone" "$keyname" "$keydir"

  salt="$(gen_salt)"
  log "Signing ${zone} with NSEC3 (salt ${salt})"
  dnssec-signzone \
    -S \
    -K "$keydir" \
    -3 "$salt" \
    -A \
    -N increment \
    -o "$zone" \
    -u \
    -t \
    "$zonefile" \
    >/dev/null
}

sign_zone "test." "/bind9_parent/zones/db.test" "/bind9_parent/keys"
sign_zone "example.test." "/bind9/zones/db.example.test" "/bind9/keys"

log "Signing complete."
