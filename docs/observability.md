# Observability

This lab includes a minimal observability stack (Prometheus + Grafana + cAdvisor) on a dedicated Docker network.

## Stack Overview
- `prometheus` scrapes cAdvisor for container metrics.
- `grafana` auto-provisions the Prometheus datasource and a starter dashboard.
- `cadvisor` exposes container CPU/memory/network metrics.

## Networks
- Observability runs on `observability_net` (`172.35.0.0/24`).
- Metrics are collected from the Docker host via the cAdvisor socket mount; no app containers need to expose metrics.

## Access
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000`
  - user: `admin`
  - pass: `admin`

## Dashboards
Grafana provisions a folder named **DNS Lab** with a dashboard:
- **DNS Lab Containers** – CPU, memory working set, and network throughput for:
  - `dns_resolver`
  - `dns_resolver_plain`
  - `dns_lab_api`
  - `dns_react_ui`

Dashboard JSON is stored at:
- `observability/grafana/dashboards/dns-lab-containers.json`

## Unbound Metrics (Resolver DNS Stats)
Two sidecar exporters expose Unbound stats via `unbound-control stats_noreset`:
- `dns_unbound_exporter` (validating resolver)
- `dns_unbound_exporter_plain` (plain resolver)

Prometheus job: `unbound` (targets `172.30.0.20:9167`, `172.30.0.21:9167`).

Grafana dashboard:
- **Resolver DNS Stats** – QPS, cache hit ratio, NXDOMAIN/SERVFAIL

Dashboard JSON:
- `observability/grafana/dashboards/dns-unbound-stats.json`

## BIND Metrics (Authoritative Stats)
Authoritative servers export stats via `rndc stats` to `named.stats` and a
lightweight exporter parses the file.

Exporters:
- `dns_bind_exporter_parent` (authoritative parent)
- `dns_bind_exporter_child` (authoritative child)

Prometheus job: `bind` (targets `172.30.0.13:9119`, `172.30.0.14:9119`).

Grafana dashboard:
- **Authoritative Stats** – queries per second and response codes.

Dashboard JSON:
- `observability/grafana/dashboards/dns-bind-authoritative.json`

## Logging Baseline (DNSSEC / SERVFAIL / NSEC)
Log locations:
- Unbound (validating): `unbound/log/unbound.log`
- Unbound (plain): `unbound/log_plain/unbound.log`
- BIND parent: `bind9_parent/log/named.log`
- BIND child: `bind9/log/named.log`

Suggested filters:
- DNSSEC / validation: `grep -Ei "dnssec|validation|trust anchor|key"`  
- SERVFAIL: `grep -Ei "servfail"`  
- NSEC / NSEC3: `grep -Ei "nsec|nsec3|aggressive"`  

Example (representative) lines you should see after running validation tests:
```
2026-03-07T19:41:12Z dns_resolver[24]: info: validation success example.test. A
2026-03-07T19:41:14Z dns_resolver[24]: info: SERVFAIL for bad.example.test. (validation failure)
2026-03-07T19:41:15Z dns_authoritative_child[1]: info: client @0x7f... query: nope.example.test IN A +E(0)K (NSEC)
```

## Quick Start
1. `docker compose up -d --build`
2. Open Grafana and verify the **DNS Lab Containers** dashboard is populated.

## Notes
- Observability ports are bound to localhost only.
- Container labels (`com.dns.*`) are used to filter metrics in Grafana.
- Prometheus is attached to `mgmt_net` to reach the Unbound exporters.
