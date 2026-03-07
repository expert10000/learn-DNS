# DNSSEC Key Rotation Implementation

This document describes the key rotation behavior that is actually implemented in this lab, and how it is wired together. It focuses on DNSSEC KSK/ZSK rollover and the DS/trust-anchor updates that keep the chain of trust valid.

## Scope
- Authoritative parent: `test.` zone in BIND (`bind9_parent/named.conf`)
- Authoritative child: `example.test.` zone in BIND (`bind9/named.conf`)
- Validating resolver: Unbound with trust anchor for `test.` (`unbound/unbound.conf` + `anchors/test.key`)
- Non-validating resolver: Unbound without trust anchor (`unbound/unbound.plain.conf`)
- DS management: helper script + one-shot service (`scripts/recompute_ds.py`, `docker-compose.yml`)

## Mail DNS Records (MX / SPF / DKIM) — Lab Add-on
The lab also includes a mail flow for `example.test`. The DNS side is defined
in the child zone file: `bind9/zones/db.example.test`.

Records used:
- **MX**: `example.test. IN MX 10 mail.example.test.`
- **A**: `mail.example.test. IN A 172.32.0.25`
- **SPF**: `example.test. IN TXT "v=spf1 ip4:172.32.0.25 -all"`
- **DKIM**: `mail._domainkey.example.test. IN TXT "..."`

Theory (quick):
- **MX** tells senders where to deliver mail for the domain.
- **SPF** tells receivers which IPs are allowed to send mail for the domain.
- **DKIM** is a cryptographic signature added by the sender; the public key
  is published in DNS under `selector._domainkey.domain`.

Operational notes:
- If you regenerate DKIM keys with `docker compose exec mailserver setup config dkim`,
  update the DKIM TXT record from:
  `/tmp/docker-mailserver/opendkim/keys/example.test/mail.txt`
  and re-sign the zone.

## What We Actually Implement
- BIND auto-signing with the default DNSSEC policy for both parent and child zones:
  - `dnssec-policy default;`
  - `inline-signing yes;`
  - BIND generates and rolls keys according to its built-in defaults.
- Automatic DS recompute on startup for child KSK changes:
  - `ds_recompute` runs during `docker compose up -d`.
  - It computes the child's current KSK DS and patches the parent zone if needed.
- Trust anchor export on startup for parent KSK:
  - `anchor_export` writes the parent KSK DNSKEY to `anchors/test.key`.
  - Unbound waits for this file before starting.
- Unbound validation wiring:
  - `module-config: "validator iterator"` (validator must come first).
  - `local-zone: "test." nodefault` to override Unbound's built-in RFC 2606 `.test` local-zone.

There is no periodic scheduler for DS or trust-anchor refresh while the stack is running. If a rollover happens while containers are already up, you must run the recompute/export steps manually (details below).

## Where Keys Live
- Parent keys: `bind9_parent/keys/`
- Child keys: `bind9/keys/`
- Parent zone file: `bind9_parent/zones/db.test`
- Child zone file: `bind9/zones/db.example.test`
- Unbound trust anchor: `anchors/test.key`

BIND stores DNSSEC key material under each `key-directory`, and inline-signs the zone with the active keys.

## Child KSK Rotation and DS Update Flow
When the child KSK changes, the parent DS must be updated. Our implementation is:

1. `ds_recompute` runs `python scripts/recompute_ds.py --wait 120 --exit-code-on-change`
2. `recompute_ds.py`:
   - Scans `bind9/keys` for a KSK record (`DNSKEY 257`) for `example.test`
   - Computes DS using SHA-256 (digest type 2)
   - Updates the DS record in `bind9_parent/zones/db.test`
   - Bumps the SOA serial
   - Exits with code `10` if the DS changed
3. The `ds_recompute` service restarts `dns_authoritative_parent` only if the DS changed.

This is the only automated DS update path in the lab.

### DS Computation Details (from `scripts/recompute_ds.py`)
- Keytag calculation: computed from the DNSKEY RDATA.
- Digest: SHA-256 over the owner name wire format + DNSKEY RDATA.
- Record format inserted/updated:
  ```
  example  IN DS  <keytag> <alg> 2 <digest>
  ```
- If no DS line is found, the script inserts it after the `example IN NS` line.

## Parent KSK Rotation and Trust Anchor Export
Unbound needs a trust anchor for `test.`. The implementation is:

- `anchor_export` waits for a parent KSK (`Ktest.+013+*.key` containing `DNSKEY 257`) and copies it to `anchors/test.key`.
- `unbound/start.sh` waits for `anchors/test.key` before launching Unbound.

If the parent KSK changes while the stack is already running, the validating resolver will not automatically refresh the trust anchor. You must re-export and restart it (details below).

## Manual Rotation Procedures (What We Support)
These steps match the lab's current implementation. They assume you want to force a new keyset and keep the chain of trust intact.

### Force child key regeneration and DS update
1. Stop the stack (optional but safer for deterministic results):
   ```
   docker compose down
   ```
2. Delete child keys (and optionally signed zone data):
   ```
   Remove-Item -Recurse -Force .\bind9\keys\*
   Remove-Item -Recurse -Force .\bind9\zones\*.signed
   ```
3. Start the stack:
   ```
   docker compose up -d
   ```
4. If the stack is already running (or you want to ensure DS refresh), run:
   ```
   docker compose run --rm ds_recompute
   docker compose restart authoritative_parent
   ```

### Force parent key regeneration and trust-anchor update
1. Stop the stack (optional but safer for deterministic results):
   ```
   docker compose down
   ```
2. Delete parent keys:
   ```
   Remove-Item -Recurse -Force .\bind9_parent\keys\*
   ```
3. Start the stack:
   ```
   docker compose up -d
   ```
4. If the stack is already running, re-export the trust anchor and restart the validating resolver:
   ```
   docker compose run --rm anchor_export
   docker compose restart resolver
   ```

## Verification Checks
After any rotation, validate both DS continuity and resolver validation:

- DS record in parent:
  ```
  dig @172.31.0.10 example.test DS +dnssec +multi
  ```
- Resolver validation:
  ```
  docker compose exec client sh -lc "delv @172.32.0.20 example.test A"
  ```

## Important Limitations (Current Behavior)
- No periodic DS recompute while the lab is running.
  - `ds_recompute` runs on `docker compose up -d` or when manually invoked.
- No automatic trust-anchor refresh for parent KSK rollover.
  - `anchor_export` runs on `docker compose up -d` or when manually invoked.
- Key rollover schedule is controlled by BIND's built-in `dnssec-policy default`.
  - We do not override timing or lifecycle parameters in this lab.

## Architecture Confirmation (As Implemented)
The lab is built exactly as follows:
- Two authoritative servers:
  - `authoritative_parent` serves `test.` (signed)
  - `authoritative_child` serves `example.test.` (signed)
- Delegation + DS:
  - `test.` delegates `example.test.` with `NS` + `DS(example.test)`
- Child NS name:
  - Delegation uses an in-parent NS name (`ns-child.test.`) to avoid unsigned glue.
- Two resolvers:
  - `resolver` (validating) trusts only `test.` via `anchors/test.key`
  - `resolver_plain` (non-validating) has no trust anchor and runs `module-config: "iterator"`

## Scheduled Workflow (Optional)
If you want a recurring refresh to catch KSK rollovers while the lab stays up, schedule these two operations:
- `ds_recompute` (child KSK -> parent DS update)
- `anchor_export` + `resolver` restart (parent KSK -> trust anchor refresh)

This does not change BIND's rollover timing; it just keeps the parent DS and resolver trust anchor in sync.

### Option A: Cron (Linux/macOS)
Create a daily job (example: 03:15):
```bash
15 3 * * * cd /path/to/Applications-2026-02-25-aspirepl2 && \
  docker compose run --rm ds_recompute && \
  docker compose run --rm anchor_export && \
  docker compose restart resolver
```

### Option B: Windows Task Scheduler
Create a daily task (example: 03:15) that runs PowerShell:
```powershell
cd g:\Applications-2026-02-25-aspirepl2
docker compose run --rm ds_recompute
docker compose run --rm anchor_export
docker compose restart resolver
```

### Notes
- These jobs are safe to run even if no keys changed; `ds_recompute` exits cleanly when DS is already current.
- For more frequent checks, shorten the schedule (e.g., every 6 hours).

## Switching Between NSEC and NSEC3

Inline NSEC (default):
```powershell
.\scripts\set_signing_mode.ps1 -Mode nsec
docker compose restart authoritative_parent authoritative_child
```

Offline NSEC3:
```powershell
.\scripts\set_signing_mode.ps1 -Mode nsec3 -RunSigner
docker compose restart authoritative_parent authoritative_child
docker compose run --rm ds_recompute
docker compose run --rm anchor_export
docker compose restart resolver
```

Linux/macOS:
```bash
./scripts/set_signing_mode.sh nsec
./scripts/set_signing_mode.sh nsec3 --run-signer
```

Offline mode behavior (one-shot signer)
- Offline NSEC3 is not a long-running service. The signer runs once to produce
  `db.*.signed`, then BIND serves those pre-signed files.
- Inline mode must not load offline `.signed` files. If you switch back to
  inline NSEC, remove any `db.*.signed` and `db.*.signed.jnl` files or BIND will
  fail to load the zone and clients will see SERVFAIL.

Cleanup after switching back to inline NSEC (Windows PowerShell):
```powershell
Remove-Item -Force .\bind9_parent\zones\db.test.signed, .\bind9_parent\zones\db.test.signed.jnl
Remove-Item -Force .\bind9\zones\db.example.test.signed, .\bind9\zones\db.example.test.signed.jnl
docker compose restart authoritative_parent authoritative_child
```

UI switch (online):
- Use the "Switch to NSEC3 (offline)" and "Switch to NSEC (inline)" buttons.
- The UI triggers the Lab API to apply the config, sign zones (NSEC3), and restart components.
- Refresh indicators after switching to confirm the active mode.

Notes:
- Offline NSEC3 uses `dnssec-signzone -3` via `docker compose run --rm signer`.
- `anchor_export` supports both BIND-managed keys (`.state`) and offline key files (`.key`).

## UI Demos (As Implemented)

### NSEC3 Proof (NXDOMAIN)
Run Query uses the validating resolver against a non-existent name.

Inline NSEC (default) expected authority:
- `SOA + RRSIG + NSEC + RRSIG`

Offline NSEC3 expected authority:
- `SOA + RRSIG + NSEC3 + RRSIG + NSEC3PARAM`

### Aggressive NSEC Demo
Run Demo fires two NXDOMAIN queries in a row; the second should be synthesized
from cached denial proofs.

Run Demo + Proof:
- Captures authoritative traffic and summarizes upstream queries.
- Uses the authoritative capture target in the Lab API.

Cache controls:
- Restart resolver (clear cache): full cold cache.
- Flush resolver cache (example.test): clears only the `example.test` zone.

Upstream query count:
- Cold cache usually shows 2 (DNSKEY + NXDOMAIN proof).
- Sometimes you will see 3 on a fully cold cache because the resolver also
  fetches the parent `DS` for `example.test` (from `test.`) before validating.
- If you want the summary to show 1, pre-warm DNSKEY first:
  `dig @172.32.0.20 example.test DNSKEY +dnssec`

### QNAME Minimization (Privacy)
QNAME minimization is enabled in `unbound/unbound.conf` via
`qname-minimisation: yes`.

UI demo:
- Use the QNAME Minimization (Privacy) preset (e.g., `deep.sub.example.test`).
- Check the QNAME indicator to confirm minimisation is enabled.

### DNS Query Privacy (Concepts)
This is a conceptual overview. The lab implements QNAME minimization, DoT, DoH,
and log minimization.

What it protects:
- Eavesdropping on DNS queries (who, what, and when someone resolves).

Mechanisms / topics:
- DoT (DNS-over-TLS): classic TLS channel to the resolver.
- DoH (DNS-over-HTTPS): DNS over HTTP/2/3, easier to blend into web traffic.
- ECH / SNI privacy: broader TLS privacy, affects DoH visibility.
- Log minimization, retention, anonymization (RODO / privacy-by-design).

Risks / downsides:
- Centralization (large DoH providers).
- Harder filtering in enterprise networks.
- DoH can bypass local policies (split-horizon, filtering).

### DNS Query Privacy (Implemented)
What is implemented in this lab:
- DoT (DNS-over-TLS) via `dot_proxy` (port 853).
- DoH (DNS-over-HTTPS) via a sidecar proxy (`doh_proxy`).
- Log minimization in Unbound and BIND (no query logging).

DoT details:
- Implemented via `dot_proxy` (TLS-terminating sidecar forwarding to the resolver).
- TLS certs are generated on startup into `dot_proxy/certs/` (self-signed).
- Host port mapping: `127.0.0.1:853 -> dot_proxy:853/tcp`.
- Use a DoT-capable client (e.g., `kdig +tls @127.0.0.1 -p 853 www.example.test`).

DoH details:
- Service: `doh_proxy` (HTTPS on `127.0.0.1:8443`).
- Endpoint: `https://127.0.0.1:8443/dns-query`
- Self-signed cert; clients must trust or skip verification (`-k` in curl).

### Availability and Abuse Resistance (DDoS / amplification)
This section is a conceptual overview plus simple lab exercises. The lab enables
basic authoritative RRL and resolver rate limiting with conservative defaults.

What it protects:
- Availability of resolvers/authoritatives under overload.
- Link saturation and abuse (reflection/amplification).
- Upstream dependency failures (timeouts, SERVFAIL spikes).

Mechanisms / topics:
- DNS amplification/reflection: why it works, role of EDNS0, large responses,
  and how DNSSEC increases response size.
- RRL (Response Rate Limiting) on authoritative servers (BIND `rate-limit`).
- Resolver rate limiting and query limiting (Unbound `ratelimit`,
  `ip-ratelimit`, `outgoing-range`, `num-queries-per-thread`).
- Anycast as an availability pattern (concept only in this lab).
- Cache as availability: reduce upstream load and hide short outages.
- Circuit breaker / fallback resolvers: secondary upstreams or fast-fail.
- Monitoring and alerting: NXDOMAIN spike, SERVFAIL spike, latency.

### Controls (UI toggles)
The UI exposes safety knobs that update config and restart services:

Unbound (resolver):
- `ratelimit` / `ip-ratelimit` + dropped counters.
- `unwanted-reply-threshold` (reply flood protection).
- `serve-expired` + `serve-expired-ttl` (availability during upstream failure).
- `prefetch`, `msg-cache-size`, `rrset-cache-size` (performance).
- `aggressive-nsec` (helps under NXDOMAIN flood).

BIND (authoritative):
- RRL (Response Rate Limiting) with before/after comparison.
- Recursion toggle (ensure auth is not an open resolver).

### Governance / Access Control (Implemented)
The lab implements several operational security controls:

Split-horizon DNS (internal vs public):
- Authoritative `example.test` is served via BIND views.
- Internal view is selected for the validating resolver (`172.31.0.20`).
- External view is served for other clients (e.g., `resolver_plain`).
- Internal zone file: `bind9/zones/db.example.test.internal`
- External zone file: `bind9/zones/db.example.test`

ACL / views in BIND (who can query what):
- Views use `match-clients` ACLs to separate internal/external visibility.
- Internal view restricts `allow-query` to trusted resolvers only.

Recursion control (avoid open resolver on authoritative):
- `recursion no`, `allow-recursion { none; }`, `allow-query-cache { none; }`
  in authoritative servers.

Zone transfer protection (AXFR/IXFR):
- `allow-transfer` requires TSIG (`xfr-key`).
- In the lab, the key is shared only with the toolbox client for demos.

Dynamic DNS updates (TSIG + policy):
- Authoritative child accepts updates only via TSIG `update-key`.
- Updates are restricted to the `dyn.example.test.` subtree.
- Example (from toolbox):
```bash
docker compose exec toolbox sh -lc "cat > /tmp/nsupdate.txt <<'EOF'
server 172.31.0.11
zone example.test
update add host1.dyn.example.test 300 A 10.10.0.55
send
EOF
nsupdate -y hmac-sha256:update-key:ZG5zdXBkYXRlLWtleS1sYWItdjE= /tmp/nsupdate.txt"
```

DNSSEC key management (automation helpers):
- Backup keys:
  - PowerShell: `.\scripts\backup_dnssec_keys.ps1`
  - bash: `./scripts/backup_dnssec_keys.sh`
- Force rollover (destructive; regenerates keys):
  - PowerShell: `.\scripts\force_dnssec_rollover.ps1 -Force`
  - bash: `./scripts/force_dnssec_rollover.sh --force`
  - This stops auth/resolvers, deletes keys + signed zones, restarts auth,
    recomputes DS, exports trust anchor, and restarts resolvers.

Panel/agent security (implemented):
- Lab API enforces `LAB_API_KEY` and rate limits requests.
- Client agents enforce `CLIENT_API_KEY` and rate limit.
- Audit log for privileged actions: `lab_api/log/audit.log`.
- Docker socket is removed from `lab_api` by default; endpoints that need
  Docker now return 503 unless `LAB_API_ALLOW_DOCKER=1` and the socket is mounted.

Quick checks:
```bash
# Split-horizon: trusted resolver (internal view)
dig @172.32.0.20 www.example.test A +dnssec

# External view via resolver_plain
dig @172.32.0.21 www.example.test A +dnssec

# AXFR with TSIG (from toolbox)
docker compose exec toolbox sh -lc "dig @172.31.0.11 example.test AXFR -y hmac-sha256:xfr-key:c3VwZXItbGFiLXhsZnIta2V5LW1vY2s="
```

### Availability and Abuse Resistance (Experiments, simple)
Keep these low-rate and local-only. Do not run high-volume tests against
external infrastructure.

### Flooding (metodyka i guardrails)
Metodyka bezpiecznych testow obciazeniowych DNS (przed "flooding")

**1) Izolacja i zakres testu**
- Testy wykonuj wylacznie w odizolowanej sieci laboratoryjnej (oddzielny bridge/VLAN Docker/GNS3).
- Ustal "scope": ktore IP sa generatorami ruchu (np. tylko client/netshoot) i ktore hosty sa celem (resolver/auth).
- Wlacz ACL na resolverze: rekursja tylko dla sieci lab (zeby nie stal sie open resolverem).
- Dowod do pracy: fragment konfiguracji ACL + zrzut logu "REFUSED" dla zapytania spoza dozwolonej podsieci.

**2) Limity testu (guardrails)**
- Ustal i zapisz w pracy stale ograniczenia, np.:
- Max QPS: 20-100 QPS (demo) lub 200 QPS (jesli lab stabilny).
- Ramp-up: stopniowo (np. 10 -> 20 -> 50 -> 100 QPS co 30-60 s).
- Czas trwania: 30-60 s na etap (zeby nie "rozjechac" cache i systemu).
- Max outstanding (zapytania "w locie"): 100-500.
- Stop conditions (warunki przerwania): packet loss / timeouts > 1-2%; latency p95 > np. 200 ms (dla laba); CPU resolvera > 85% przez 30 s; wzrost SERVFAIL ponad ustalony prog.
- Dowod do pracy: tabelka "Parametr - Wartosc - Uzasadnienie".

**3) Ograniczenia po stronie uslug (rate limiting / throttling)**
To jest wazne, bo pokazuje "ochrone dostepnosci":

Resolver (Unbound) - ogranicz wplyw naduzyc:
- limit rownoleglych klientow / zapytan (zeby jeden generator nie zabil procesu),
- limity "outgoing" (zeby resolver nie wysylal zbyt duzo upstream naraz),
- rozsadne cache/neg-cache (zeby NXDOMAIN nie niszczyl RAM).
(Nazwy opcji zaleza od wersji, ale ideowo: concurrency + outgoing + cache + ewentualny ratelimit odpowiedzi.)

Autorytatywny (BIND) - Response Rate Limiting (RRL):
- Wlacz rate-limit, zeby ograniczyc masowe odpowiedzi (szczegolnie na te same wzorce).
- W logach powinny byc widoczne "slip/limit" przy naduzyciach.

Warstwa HTTP (jesli DoH):
- Dla DoH najlepiej pokazac rate limiting w Nginx (limit_req/limit_conn).

Dowod do pracy: wycinek config + wykres/metryka "requests limited".

**4) Monitoring przed testem (zeby wynik byl wiarygodny)**
Zanim puscisz ruch:
- zbierz baseline (CPU/RAM/QPS/latency) przez 1-2 min,
- wlacz metryki:
  - liczba zapytan na resolverze,
  - cache hit ratio (jesli masz),
  - upstream QPS (resolver -> authoritative),
  - NXDOMAIN/SERVFAIL ratio,
  - p50/p95 latencji (dnsperf daje te statystyki).

Minimalny monitoring bez Prometheusa: tcpdump + logi Unbound/BIND + wynik dnsperf.
Lepszy (ladny do tezy): Prometheus/Grafana (wykresy "przed/po").

**5) Procedura testu (bezpieczna, powtarzalna)**
1. Reset/flush cache (albo restart resolvera) -> start od czystego stanu.
2. Warm-up (krotki test), zeby cache sie ustabilizowal.
3. Test wlasciwy z ramp-up i limitami QPS.
4. Zapis danych: wynik dnsperf + licznik upstream (pcap/metryka) + logi.
5. Cooldown: 1-2 min przerwy miedzy seriami.

Flood simulation (low-rate) from the client container:
```bash
docker compose exec client sh -lc "for i in $(seq 1 200); do dig @172.32.0.20 example.test A +tries=1 +time=1 >/dev/null; done"
```

Measure latency impact (client container):
```bash
docker compose exec client sh -lc "time sh -c 'for i in $(seq 1 200); do dig @172.32.0.20 example.test A +tries=1 +time=1 >/dev/null; done'"
```

Show how DNSSEC increases response size (authoritative):
```bash
dig @172.31.0.10 example.test A +stats
dig @172.31.0.10 example.test DNSKEY +dnssec +stats
```
Compare the `MSG SIZE rcvd` values. The DNSKEY + RRSIG response is typically
much larger and is a common source of amplification.

UI amplification test (implemented):
- Use the "DNSSEC Amplification / EDNS" card in the UI.
- Choose qtypes (DNSKEY, ANY, TXT, RRSIG) and EDNS sizes (1232 vs 4096).
- The results show TC% (truncation), TCP fallback %, p95 latency, and response
  sizes (UDP/TCP). This makes the DNSSEC size impact visible.

Mix-load test (implemented):
- Use "Mix Load" (80% A/AAAA, 10% NXDOMAIN, 10% DNSKEY).
- Use EDNS 1232 vs 4096 and compare TC% and TCP%.

Optional: If you have `dnsperf` installed, replace the loop with a low-rate
`dnsperf` run and compare latency and drops before/after enabling limits.

## Future Improvement
Option A: add a dedicated aggressive demo resolver that is authoritative for
`example.test` via auth-zone (using the signed zone file), and wire the UI
"Run Demo + Proof" to that resolver. Result: upstream queries drop to 0 (local
authoritative + cached NSEC/NSEC3), giving a clean, repeatable demo without
breaking the main resolver.

## Observability (Resolver DNS Metrics)
Unbound exports internal DNS stats via `unbound-control stats_noreset`, which are
scraped by Prometheus and visualized in Grafana.

What you get in Grafana:
- QPS per resolver
- Cache hit ratio
- NXDOMAIN and SERVFAIL rates

Details and exported dashboards:
- `docs/observability.md`

## Observability (Logging Baseline)
Unbound and BIND logs are formatted with consistent timestamps and identities to
support filtering of DNSSEC/SERVFAIL/NSEC events.

Log locations and example filters:
- `docs/observability.md`

## Observability (Kibana Logs)
Kibana provides centralized log search for resolver and authoritative logs.

Details and data view export:
- `docs/observability.md`

## Observability (Correlation)
Grafana dashboards link directly to Kibana Discover with the active time range.

Saved searches for validation failures and NXDOMAIN floods are included in:
- `observability/kibana/saved_objects.ndjson`

## Control Plane (Nodes Registry)
`lab_api` aggregates resolver/authoritative agent status into `/nodes`, providing
roles, IPs, and versions without Docker socket access.
