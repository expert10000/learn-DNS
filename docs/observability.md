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

## Quick Start
1. `docker compose up -d --build`
2. Open Grafana and verify the **DNS Lab Containers** dashboard is populated.

## Notes
- Observability ports are bound to localhost only.
- Container labels (`com.dns.*`) are used to filter metrics in Grafana.