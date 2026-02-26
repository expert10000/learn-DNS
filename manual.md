# DNS Security Lab (Docker) — Network View + Tests (All-in-One)

This single Markdown document contains:
- **Topology inspection** (networks, IPs, attachments)
- **Live traffic viewing** (tcpdump + PCAP for Wireshark)
- **Behavior tests** (recursion, segmentation, DNSSEC, host exposure)
- **PASS/FAIL smoke-test script**
- **Thesis evidence checklist**

---

## 0) Assumptions (adjust names if different)

### Containers
- `dns_authoritative` — BIND9 authoritative for `example.test` (DNSSEC auto-signing enabled)
- `dns_resolver` — Unbound recursive resolver with DNSSEC validation
- `dns_client` — trusted test box with `dig`
- `dns_untrusted` — untrusted test box with `dig`
- `dns_toolbox` — optional netshoot container for troubleshooting

### IP plan (example)
- Authoritative: `172.31.0.10`
- Resolver (trusted iface): `172.32.0.20`
- Resolver (untrusted iface): `172.33.0.20`
- Resolver (mgmt iface): `172.30.0.20`

### Host exposure
- Resolver is published to host **localhost only**:
  - `127.0.0.1:5300` (TCP/UDP 53)

---

## 1) Docker “network viewer” (topology + IPs)

### 1.1 List networks
```bash
docker network ls
```

### 1.2 Inspect each network (subnet + connected containers + assigned IPs)

Replace network names with your actual ones if Compose prefixes them (e.g. `dns-security-lab_client_net`).

```bash
docker network inspect dns-security-lab_client_net
docker network inspect dns-security-lab_untrusted_net
docker network inspect dns-security-lab_dns_core
docker network inspect dns-security-lab_mgmt_net
```

### 1.3 Show each container’s IP on every attached network
```bash
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_resolver
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_authoritative
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_client
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_untrusted
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_toolbox
```

### 1.4 (Optional) UI “viewers” for screenshots
- **Portainer CE** — easy network/containers view
- **lazydocker** / **ctop** — terminal dashboards

---

## 2) Live traffic capture (“viewer” of DNS packets)

### 2.1 tcpdump inside the resolver (quick live view)
```bash
docker exec -it dns_resolver sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || true; tcpdump -ni any port 53"
```

### 2.2 Capture PCAP and open in Wireshark (best for thesis evidence)
```bash
# capture to file inside resolver
docker exec -it dns_resolver sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || true; tcpdump -ni any -w /tmp/dns.pcap port 53"

# copy PCAP to host
docker cp dns_resolver:/tmp/dns.pcap ./dns.pcap

# open ./dns.pcap in Wireshark on the host
```

### 2.3 Use toolbox (netshoot) for network debugging (optional)
```bash
docker exec -it dns_toolbox bash
ip a
ip route
ss -lunpt
tcpdump -ni any port 53
```

---

## 3) Behavior tests (prove security + correctness)

### Test 1 — Trusted recursion works
```bash
docker exec -it dns_client sh
dig @172.32.0.20 example.test A
dig @172.32.0.20 www.example.test A
```
**Expected:** `status: NOERROR` and an answer section.

---

### Test 2 — Untrusted recursion is blocked (no open resolver)
```bash
docker exec -it dns_untrusted sh
dig @172.33.0.20 example.test A
```
**Expected:** `REFUSED` (preferred) OR no recursion (RA flag off) OR timeout (policy-dependent).  
This is your key “no open resolver” proof.

---

### Test 3 — Authoritative is not reachable from client LAN (segmentation)
```bash
docker exec -it dns_client sh
dig @172.31.0.10 example.test SOA +time=1 +tries=1
```
**Expected:** timeout / unreachable (client is not attached to authoritative’s network).

---

### Test 4 — Resolver can reach authoritative (internal resolution path works)
```bash
docker exec -it dns_resolver sh
# direct query to authoritative should work
drill @172.31.0.10 example.test SOA || true

# local query against resolver should work
drill @127.0.0.1 example.test A || true
```
**Expected:** resolver can query authoritative via `dns_core` and answer client queries.

---

### Test 5 — DNSSEC validation works (if enabled)
```bash
docker exec -it dns_client sh
dig @172.32.0.20 example.test A +dnssec
```
**Look for:** `ad` flag (Authenticated Data) and/or `RRSIG` depending on config.

Better (explicit validation report):
```bash
docker exec -it dns_client sh -lc "apk add --no-cache bind-tools >/dev/null 2>&1 || true; delv @172.32.0.20 example.test A"
```
**Expected:** `delv` reports validation success.

---

### Test 6 — Host exposure is safe (localhost-only publish)
From the host OS (not in Docker):
```bash
dig @127.0.0.1 -p 5300 example.test A
```
**Expected:** works on the host.  
**Security expectation:** it should NOT be reachable from other machines (bound to `127.0.0.1` only).

---

## 4) Smoke test script (PASS/FAIL)

### 4.1 Save on host as `smoke_test_dns_lab.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail

RES_TRUSTED="172.32.0.20"
RES_UNTRUSTED="172.33.0.20"
AUTH="172.31.0.10"

pass(){ echo "✅ PASS: $1"; }
fail(){ echo "❌ FAIL: $1"; exit 1; }

echo "[1] Trusted recursion should work..."
out1="$(docker exec dns_client sh -lc "dig +time=1 +tries=1 @${RES_TRUSTED} example.test A" || true)"
echo "$out1" | grep -q "status: NOERROR" && pass "trusted recursion" || fail "trusted recursion"

echo "[2] Untrusted recursion should be blocked..."
out2="$(docker exec dns_untrusted sh -lc "dig +time=1 +tries=1 @${RES_UNTRUSTED} example.test A" || true)"
echo "$out2" | grep -Eq "status: REFUSED|connection timed out|no servers could be reached" \
  && pass "untrusted recursion blocked" || fail "untrusted recursion blocked"

echo "[3] Client should not reach authoritative directly (segmentation)..."
out3="$(docker exec dns_client sh -lc "dig +time=1 +tries=1 @${AUTH} example.test SOA" || true)"
echo "$out3" | grep -Eq "connection timed out|no servers could be reached" \
  && pass "auth isolated from client_net" || fail "auth isolated from client_net"

echo "All smoke tests completed."
```

### 4.2 Run it
```bash
chmod +x smoke_test_dns_lab.sh
./smoke_test_dns_lab.sh
```

---

## 5) Thesis evidence checklist (what to screenshot / include)

### 5.1 Topology proof
- Output (screenshot) of:
  - `docker network inspect ...` (shows networks + attachments + IPs)
  - container IP listing (section 1.3)

### 5.2 Traffic proof
- Wireshark screenshot from `dns.pcap` showing:
  - client → resolver query
  - resolver → authoritative query
  - authoritative → resolver response
  - resolver → client response

### 5.3 Security behavior proof (table)
Create a table in the thesis:

| Test | Description | Command | Expected | Observed |
|---|---|---|---|---|
| T1 | Trusted recursion works | `dig @172.32.0.20 ...` | NOERROR | ... |
| T2 | Untrusted blocked | `dig @172.33.0.20 ...` | REFUSED/No-RA | ... |
| T3 | Authoritative isolated | `dig @172.31.0.10 ...` | timeout | ... |
| T4 | Resolver→Auth OK | `drill @172.31.0.10 ...` | OK | ... |
| T5 | DNSSEC validation | `delv ...` | validated | ... |
| T6 | Localhost-only publish | `dig @127.0.0.1 -p 5300 ...` | OK local | ... |

---




docker pull internetsystemsconsortium/bind9:9.18
docker pull mvance/unbound:1.20.0
docker pull alpine:3.20
docker pull nicolaka/netshoot:latest