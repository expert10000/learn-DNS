# DNSSEC Key Rotation Implementation

This document describes the key rotation behavior that is actually implemented in this lab, and how it is wired together. It focuses on DNSSEC KSK/ZSK rollover and the DS/trust-anchor updates that keep the chain of trust valid.

## Scope
- Authoritative parent: `test.` zone in BIND (`bind9_parent/named.conf`)
- Authoritative child: `example.test.` zone in BIND (`bind9/named.conf`)
- Validating resolver: Unbound with trust anchor for `test.` (`unbound/unbound.conf` + `anchors/test.key`)
- Non-validating resolver: Unbound without trust anchor (`unbound/unbound.plain.conf`)
- DS management: helper script + one-shot service (`scripts/recompute_ds.py`, `docker-compose.yml`)

## What We Actually Implement
- **BIND auto-signing with the default DNSSEC policy** for both parent and child zones:
  - `dnssec-policy default;`
  - `inline-signing yes;`
  - BIND generates and rolls keys according to its built-in defaults.
- **Automatic DS recompute on startup** for child KSK changes:
  - `ds_recompute` runs during `docker compose up -d`.
  - It computes the child’s current KSK DS and patches the parent zone if needed.
- **Trust anchor export on startup** for parent KSK:
  - `anchor_export` writes the parent KSK DNSKEY to `anchors/test.key`.
  - Unbound waits for this file before starting.
- **Unbound validation wiring**:
  - `module-config: "validator iterator"` (validator must come first).
  - `local-zone: "test." nodefault` to override Unbound’s built-in RFC 2606 `.test` local-zone.

There is **no periodic scheduler** for DS or trust-anchor refresh while the stack is running. If a rollover happens while containers are already up, you must run the recompute/export steps manually (details below).

## Where Keys Live
- Parent keys: `bind9_parent/keys/`
- Child keys: `bind9/keys/`
- Parent zone file: `bind9_parent/zones/db.test`
- Child zone file: `bind9/zones/db.example.test`
- Unbound trust anchor: `anchors/test.key`

BIND stores DNSSEC key material under each `key-directory`, and inline-signs the zone with the active keys.

## Child KSK Rotation and DS Update Flow
When the **child KSK changes**, the parent DS must be updated. Our implementation is:

1. `ds_recompute` runs `python scripts/recompute_ds.py --wait 120 --exit-code-on-change`
2. `recompute_ds.py`:
   - Scans `bind9/keys` for a **KSK** record (`DNSKEY 257`) for `example.test`
   - Computes DS using **SHA-256** (digest type 2)
   - Updates the DS record in `bind9_parent/zones/db.test`
   - Bumps the SOA serial
   - Exits with code `10` if the DS changed
3. The `ds_recompute` service restarts `dns_authoritative_parent` **only if the DS changed**.

This is the only automated DS update path in the lab.

### DS Computation Details (from `scripts/recompute_ds.py`)
- **Keytag calculation**: computed from the DNSKEY RDATA.
- **Digest**: SHA-256 over the owner name wire format + DNSKEY RDATA.
- **Record format** inserted/updated:
  ```
  example  IN DS  <keytag> <alg> 2 <digest>
  ```
- If no DS line is found, the script inserts it after the `example IN NS` line.

## Parent KSK Rotation and Trust Anchor Export
Unbound needs a trust anchor for `test.`. The implementation is:

- `anchor_export` waits for a parent KSK (`Ktest.+013+*.key` containing `DNSKEY 257`) and copies it to `anchors/test.key`.
- `unbound/start.sh` waits for `anchors/test.key` before launching Unbound.

If the parent KSK changes while the stack is already running, the **validating** resolver will **not** automatically refresh the trust anchor. You must re-export and restart it (details below).

## Manual Rotation Procedures (What We Support)
These steps match the lab’s current implementation. They assume you want to force a new keyset and keep the chain of trust intact.

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
- **No periodic DS recompute** while the lab is running.
  - `ds_recompute` runs on `docker compose up -d` or when manually invoked.
- **No automatic trust-anchor refresh** for parent KSK rollover.
  - `anchor_export` runs on `docker compose up -d` or when manually invoked.
- **Key rollover schedule** is controlled by BIND’s built-in `dnssec-policy default`.
  - We do not override timing or lifecycle parameters in this lab.

## Architecture Confirmation (As Implemented)
The lab is built exactly as follows:
- **Two authoritative servers**:
  - `authoritative_parent` serves `test.` (signed)
  - `authoritative_child` serves `example.test.` (signed)
- **Delegation + DS**:
  - `test.` delegates `example.test.` with `NS` + `DS(example.test)`
- **Child NS name**:
  - Delegation uses an in-parent NS name (`ns-child.test.`) to avoid unsigned glue.
- **Two resolvers**:
  - `resolver` (validating) trusts **only** `test.` via `anchors/test.key`
  - `resolver_plain` (non-validating) has no trust anchor and runs `module-config: "iterator"`

## Scheduled Workflow (Optional)
If you want a recurring refresh to catch KSK rollovers while the lab stays up, schedule these two operations:
- `ds_recompute` (child KSK -> parent DS update)
- `anchor_export` + `resolver` restart (parent KSK -> trust anchor refresh)

This does **not** change BIND’s rollover timing; it just keeps the parent DS and resolver trust anchor in sync.

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
- If you want more frequent checks, shorten the schedule (e.g., every 6 hours).
