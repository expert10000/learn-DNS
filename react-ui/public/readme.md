# DNS Security Protocol Lab (Starter)

This starter spins up an isolated DNS lab with:
- Authoritative BIND9 parent for `test.` (DNSSEC auto-signing enabled)
- Authoritative BIND9 child for `example.test.` (DNSSEC auto-signing enabled)
- Unbound **validating** resolver (DNSSEC validation enabled)
- Unbound **plain** resolver (no DNSSEC validation)
- A trusted client network and an untrusted network

The resolvers only allow recursion from the trusted and mgmt subnets.

## Services
- `authoritative_parent` (BIND9): serves `test.` and delegates `example.test.` with DS.
- `authoritative_child` (BIND9): serves `example.test.` and auto-signs with DNSSEC.
- `resolver` (Unbound): validates DNSSEC and answers only for allowed subnets.
- `resolver_plain` (Unbound): non-validating resolver, same ACLs.
- `client`: trusted client API (FastAPI) that runs `dig` from the trusted segment.
- `untrusted`: untrusted client API (FastAPI) that runs `dig` from the untrusted segment.
- `mgmt_client`: management client API (FastAPI) for the mgmt segment.
- `toolbox`: optional netshoot container for troubleshooting.
- `mailserver`: Docker Mailserver for `example.test` (SMTP/IMAP for mail lab).
- `swaks`: test client for sending mail inside the lab (local build in `swaks/`).
- `lab_api`: management API (FastAPI) for logs and optional dig execution.
- Packet capture runs via `tcpdump` inside the resolver and authoritative child containers (triggered by `lab_api`).
- `anchor_export`: one-shot helper that writes the parent trust anchor to `anchors/test.key`.
- `react_ui`: React UI (Nginx) that talks to per-client APIs and the lab API.

## Topology
- Authoritative (parent/test): `172.31.0.10`
- Authoritative (child/example.test): `172.31.0.11`
- Resolver (valid/trusted): `172.32.0.20`
- Resolver (valid/untrusted): `172.33.0.20`
- Resolver (valid/mgmt): `172.30.0.20`
- Resolver (plain/trusted): `172.32.0.21`
- Resolver (plain/untrusted): `172.33.0.21`
- Resolver (plain/mgmt): `172.30.0.21`

## Ports
- Validating resolver is published to host localhost only: `127.0.0.1:5300` (TCP/UDP 53).
- Plain resolver is published to host localhost only: `127.0.0.1:5301` (TCP/UDP 53).
- React UI is published to host: `http://localhost:5173`.
- Mailserver is published to host localhost only:
  - SMTP: `127.0.0.1:2525`
  - Submission: `127.0.0.1:1587`
  - SMTPS: `127.0.0.1:1465`
  - IMAP: `127.0.0.1:1143`
  - IMAPS: `127.0.0.1:1993`

## Mail Lab (MX/SPF/DKIM)
This lab also includes a self-contained mail flow for `example.test`:
- DNS: `MX`, `SPF`, and `DKIM` are published in the `example.test` zone.
- SMTP server: Docker Mailserver (`mail.example.test`).
- Test sender: `swaks` container.
- UI: Email tab can send and inspect DKIM logs.

Quick start:
1. `docker compose up -d --build mailserver swaks`
2. Create mailbox:
   `docker compose exec mailserver setup email add user@example.test`
3. Open `http://localhost:5173` → Email tab:
   - From/To: `user@example.test`
   - Server: `mail.example.test`, Port: `25`, TLS: `None`
   - Click **Send Email** and **Load DKIM Logs**
4. Optional IMAP check (message delivery):
   `openssl s_client -connect 127.0.0.1:1993 -crlf`
   Then:
   `a login user@example.test <password>`
   `a select INBOX`
   `a fetch 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)])`
   `a logout`

CLI alternative (inside the swaks container):
```bash
docker compose exec swaks swaks \
  --to user@example.test \
  --from user@example.test \
  --server mail.example.test \
  --port 25 \
  --header "Subject: DNS lab test" \
  --body "Hello from the DNS lab."
```

Notes:
- On Windows hosts, Postfix queue state should be stored in a named volume
  (see `mailserver_state` in `docker-compose.yml`) to avoid “queue file write error”.

## API & UI (New Architecture)
- Per-client FastAPI agents run inside the segmented networks.
- `client` (trusted) -> validating resolver at `172.32.0.20`.
- `untrusted` -> validating resolver at `172.33.0.20`.
- `mgmt_client` -> validating resolver at `172.30.0.20`.
- The React UI talks to these agents via Nginx proxy paths.
- `/api/trusted`, `/api/untrusted`, `/api/mgmt`.
- The lab API is proxied for logs and optional dig execution.
- `/lab-api` (requires `LAB_API_KEY` / `VITE_LAB_API_KEY`).
- The UI also includes a config viewer with tabs for `authoritative` (BIND) and
  `resolver` (Unbound) files, served via the lab API.
- The UI includes packet capture controls and a capture download list, served via the lab API.

## Quick Start
1. `docker compose up -d`
2. Wait 1-2 minutes for BIND to generate DNSSEC keys and sign the zones.
3. The resolver waits until `anchor_export` writes `anchors/test.key`.

## Checks
From the trusted client:
1. `docker compose exec client sh`
2. `dig @172.32.0.20 example.test +dnssec +multi`
3. `dig @172.32.0.20 www.example.test +dnssec`

From the untrusted client (should be refused):
1. `docker compose exec untrusted sh`
2. `dig @172.33.0.20 example.test`

From the host (mapped to localhost port 5300):
1. `dig @127.0.0.1 -p 5300 example.test +dnssec`

## NSEC vs NSEC3 + Aggressive NSEC
- Default mode is **inline NSEC** (BIND auto-signing).
- Optional **offline NSEC3** signing is supported via `dnssec-signzone -3`.
- The validating resolver (`resolver`) uses **aggressive NSEC** to synthesize
  NXDOMAIN answers from cached proofs (works with NSEC or NSEC3, but the lab
  demos are written for NSEC3).

### Switch to offline NSEC3 (Windows PowerShell)
```powershell
.\scripts\set_signing_mode.ps1 -Mode nsec3 -RunSigner
docker compose restart authoritative_parent authoritative_child
docker compose run --rm ds_recompute
docker compose run --rm anchor_export
docker compose restart resolver
```

### Switch to offline NSEC3 (Linux/macOS)
```bash
./scripts/set_signing_mode.sh nsec3 --run-signer
docker compose restart authoritative_parent authoritative_child
docker compose run --rm ds_recompute
docker compose run --rm anchor_export
docker compose restart resolver
```

### Switch back to inline NSEC
```powershell
.\scripts\set_signing_mode.ps1 -Mode nsec
docker compose restart authoritative_parent authoritative_child
```

### Switch back to inline NSEC (Linux/macOS)
```bash
./scripts/set_signing_mode.sh nsec
docker compose restart authoritative_parent authoritative_child
```

### UI switcher
The React UI includes buttons to switch modes online (Lab API key required).
After switching, verify the indicator and run the NSEC3 proof query.

### Aggressive NSEC proof (UI)
Use "Run Demo + Proof" to capture authoritative traffic while the demo runs.
The UI reports how many upstream queries reached the authoritative server.
Enable "Restart resolver (clear cache)" for a clean proof.

### Verify NSEC3 on the child zone (offline NSEC3 mode)
```bash
dig @172.31.0.11 nope1.example.test A +dnssec +multi
```
**Expected:** `status: NXDOMAIN` and `NSEC3` / `NSEC3PARAM` in the authority section.

### Verify aggressive NSEC on the resolver
```bash
dig @172.32.0.20 nope1.example.test A +dnssec
dig @172.32.0.20 nope2.example.test A +dnssec
```
**Expected:** the second NXDOMAIN can be answered from cached proofs, which reduces
authoritative queries (confirm via tcpdump or logs if needed).

## Files
- `docker-compose.yml`: lab topology and networks.
- `bind9_parent/named.conf`: BIND9 configuration (parent/test).
- `bind9_parent/zones/db.test`: parent zone file (includes DS for child).
- `bind9/named.conf`: BIND9 configuration (child/example.test).
- `bind9/zones/db.example.test`: child zone file.
- `bind9_parent/keys` and `bind9/keys`: DNSSEC keys generated by BIND.
- `unbound/unbound.conf`: validating resolver config and ACLs.
- `unbound/unbound.plain.conf`: non-validating resolver config and ACLs.
- `anchors/test.key`: Unbound trust anchor for `test.` (exported by `anchor_export`).

## Logs
- BIND: `bind9/log/named.log`
- Unbound: `unbound/log/unbound.log`

## Captures
- PCAP files are stored under `captures/`.
- The lab API needs access to Docker for start/stop operations (via `/var/run/docker.sock`).

## Notes
- The lab networks are internal-only. The resolver will only answer for
  `example.test` (stub to the authoritative server). It cannot reach the public
  internet unless you change the Docker networks to non-internal and add a
  `forward-zone`.
- DNSSEC keys and signed zone data are stored in `bind9/keys` and
  `bind9/zones`. Delete those files to force re-generation.
  For the parent, delete `bind9_parent/keys` to re-generate and let
  `anchor_export` rewrite `anchors/test.key`.

## DS Recompute (after child key rotation)
If the child KSK changes, recompute the DS in the parent zone:
```bash
python scripts/recompute_ds.py --wait 120
docker compose restart authoritative_parent
```

## DS Recompute (service)
Runs automatically on `docker compose up -d`. You can also run it manually:
```bash
docker compose run --rm ds_recompute
docker compose restart authoritative_parent
```
Notes:
- The service restarts `authoritative_parent` only when the DS changes.
- It uses the Docker socket to restart the container.
