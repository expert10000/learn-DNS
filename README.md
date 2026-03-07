# DNS Security 
This starter spins up an isolated DNS with:
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

docker compose up -d --build

Quick start:
1. `docker compose up -d --build`
