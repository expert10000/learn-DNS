#!/bin/sh
set -e

PROFILE=${PROFILE:-trusted}
RESOLVER=${RESOLVER:-172.32.0.20}
NAME=${NAME:-www.example.test}
QTYPE=${QTYPE:-A}
COUNT=${COUNT:-200}
QPS=${QPS:-20}

case "$PROFILE" in
  trusted) container="dns_client" ;;
  untrusted) container="dns_untrusted" ;;
  mgmt) container="dns_mgmt_client" ;;
  *)
    echo "Unknown PROFILE: $PROFILE (expected trusted|untrusted|mgmt)" >&2
    exit 2
    ;;
esac

if [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt 600 ]; then
  echo "COUNT must be between 1 and 600." >&2
  exit 2
fi
if [ "$QPS" -lt 1 ] || [ "$QPS" -gt 100 ]; then
  echo "QPS must be between 1 and 100." >&2
  exit 2
fi

sleep_s=$(awk "BEGIN {printf \"%.3f\", 1/$QPS}")
loop="for i in \$(seq 1 $COUNT); do dig @$RESOLVER $NAME $QTYPE +time=1 +tries=1 >/dev/null; "
if [ "$sleep_s" != "0.000" ]; then
  loop="${loop}sleep $sleep_s; "
fi
loop="${loop}done"

echo "Running load: $COUNT queries at ~$QPS qps via $PROFILE ($RESOLVER)"
docker compose exec "$container" sh -lc "$loop"
