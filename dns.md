# DNSSEC Key Rotation Implementation

This document describes the key rotation behavior that is actually implemented in this lab, and how it is wired together. It focuses on DNSSEC KSK/ZSK rollover and the DS/trust-anchor updates that keep the chain of trust valid.

## Scope
- Authoritative parent: `test.` zone in BIND (`bind9_parent/named.conf`)
- Authoritative child: `example.test.` zone in BIND (`bind9/named.conf`)
- Validating resolver: Unbound with trust anchor for `test.` (`unbound/unbound.conf` + `anchors/test.key`)
- Non-validating resolver: Unbound without trust anchor (`unbound/unbound.plain.conf`)
- DS management: helper script + one-shot service (`scripts/recompute_ds.py`, `docker-compose.yml`)

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

## Future Improvement
Option A: add a dedicated aggressive demo resolver that is authoritative for
`example.test` via auth-zone (using the signed zone file), and wire the UI
"Run Demo + Proof" to that resolver. Result: upstream queries drop to 0 (local
authoritative + cached NSEC/NSEC3), giving a clean, repeatable demo without
breaking the main resolver.
