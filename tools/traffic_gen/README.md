# DNS Traffic Generator

This tool generates DNS queries at a controlled QPS for demos (NXDOMAIN bursts,
aggressive NSEC, cache warmup).

Build image:
```bash
docker build -t dns-traffic-gen ./tools/traffic_gen
```

Run against the validating resolver (trusted net):
```bash
docker run --rm --network dns-security-lab_client_net dns-traffic-gen \
  --server 172.32.0.20 --mode nxdomain --qps 100 --duration 30 --zone example.test
```

Run a mixed load (70% NXDOMAIN, 30% valid):
```bash
docker run --rm --network dns-security-lab_client_net dns-traffic-gen \
  --server 172.32.0.20 --mode mix --nxdomain-ratio 0.7 --qps 80 --duration 60
```

Notes:
- For plain resolver, use `--server 172.32.0.21`.
- Increase `--qps` gradually to avoid overload.
