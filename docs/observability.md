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
  - pass: value from `observability/observability.env` (`GF_SECURITY_ADMIN_PASSWORD`)

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

## Security Hardening
- Credentials are stored in `observability/observability.env` (change them before sharing the lab).
- Elasticsearch security is enabled (basic auth); Kibana uses the same credentials to connect.
- Prometheus, Grafana, and Kibana are published to `127.0.0.1` only.
- `observability_net` is internal to keep the stack isolated from other Docker networks.
- `obs_access` is a dedicated bridge network used only to allow localhost port publishing.

### Kibana system user
Kibana must use the `kibana_system` user (the `elastic` superuser is rejected).
Set its password once and update `observability/observability.env`:
1. `docker compose exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -b`
2. Copy the generated password into `KIBANA_SYSTEM_PASSWORD` in `observability/observability.env`.
3. `docker compose up -d kibana`

## ELK (Logs in Kibana)
Minimal single-node ELK stack:
- `elasticsearch` (single-node, memory limited)
- `kibana`
- `filebeat` (reads DNS logs and ships to Elasticsearch)

Access:
- Elasticsearch: `http://127.0.0.1:9200`
- Kibana: `http://127.0.0.1:5601`
  - user: `kibana_system`
  - pass: value from `observability/observability.env` (`KIBANA_SYSTEM_PASSWORD`)

Log inputs (via Filebeat):
- BIND parent/child: `bind9_parent/log/*.log`, `bind9/log/*.log`
- Unbound valid/plain: `unbound/log/unbound.log`, `unbound/log_plain/unbound.log`
- Lab API: `lab_api/log/*.log`

Kibana saved objects export:
- `observability/kibana/saved_objects.ndjson` (data view `dns-lab-logs-*`)

Import it in Kibana:
1. Stack Management → Saved Objects → Import.
2. Select `observability/kibana/saved_objects.ndjson`.
3. Open Discover and choose the `dns-lab-logs-*` data view.

## Correlation (Grafana → Kibana)
Grafana dashboards include links that preserve the current time range and open
Kibana Discover:
- Resolver dashboard links to resolver logs.
- Authoritative dashboard links to parent/child logs.

Saved searches (imported from the same NDJSON):
- **DNSSEC Validation Failures**
- **NXDOMAIN Flood**

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
- `observability_net` is internal and isolated from other Docker networks.
- Container labels (`com.dns.*`) are used to filter metrics in Grafana.
- Prometheus is attached to `mgmt_net` to reach the Unbound exporters.
