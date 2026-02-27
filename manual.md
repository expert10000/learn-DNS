# DNS Security Lab (Docker) — Network View + Tests (All-in-One)

This single Markdown document contains:
- **Topology inspection** (networks, IPs, attachments)
- **Live traffic viewing** (tcpdump + PCAP for Wireshark)
- **Behavior tests** (recursion, segmentation, DNSSEC, host exposure)
- **PASS/FAIL smoke-test script**
- ** evidence checklist**

---

## 0) Assumptions (adjust names if different)

### Containers
- `dns_authoritative_parent` — BIND9 authoritative for `test.` (DNSSEC auto-signing enabled)
- `dns_authoritative_child` — BIND9 authoritative for `example.test.` (DNSSEC auto-signing enabled)
- `dns_resolver` — Unbound recursive resolver with DNSSEC validation (validating)
- `dns_resolver_plain` — Unbound recursive resolver without DNSSEC validation (plain)
- `dns_client` — trusted test box with `dig`
- `dns_untrusted` — untrusted test box with `dig`
- `dns_toolbox` — optional netshoot container for troubleshooting

### IP plan (example)
- Authoritative (parent/test): `172.31.0.10`
- Authoritative (child/example.test): `172.31.0.11`
- Resolver (valid/trusted): `172.32.0.20`
- Resolver (valid/untrusted): `172.33.0.20`
- Resolver (valid/mgmt): `172.30.0.20`
- Resolver (plain/trusted): `172.32.0.21`
- Resolver (plain/untrusted): `172.33.0.21`
- Resolver (plain/mgmt): `172.30.0.21`

### Host exposure
- Validating resolver is published to host **localhost only**: `127.0.0.1:5300` (TCP/UDP 53)
- Plain resolver is published to host **localhost only**: `127.0.0.1:5301` (TCP/UDP 53)

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
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_resolver_plain
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_authoritative_parent
docker inspect -f '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}| {{$k}}={{$v.IPAddress}} {{end}}' dns_authoritative_child
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

### 2.1b tcpdump inside the plain resolver (quick live view)
```bash
docker exec -it dns_resolver_plain sh -lc "apk add --no-cache tcpdump >/dev/null 2>&1 || true; tcpdump -ni any port 53"
```

### 2.2 Capture PCAP and open in Wireshark (best for  evidence)
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
dig @172.31.0.10 test SOA +time=1 +tries=1
dig @172.31.0.11 example.test SOA +time=1 +tries=1
```
**Expected:** timeout / unreachable (client is not attached to authoritative’s network).

---

### Test 4 — Resolver can reach authoritative (internal resolution path works)
```bash
docker exec -it dns_resolver sh
# direct query to parent and child should work
drill @172.31.0.10 test SOA || true
drill @172.31.0.11 example.test SOA || true

# local query against resolver should work
drill @127.0.0.1 example.test A || true
```
**Expected:** resolver can query both parent and child via `dns_core` and answer client queries.

---

### Test 5a — DNSSEC validation works (validating resolver)
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

### Test 5b — DNSSEC validation is NOT enforced (plain resolver)
```bash
docker exec -it dns_client sh
dig @172.32.0.21 example.test A +dnssec
```
**Look for:** no `ad` flag (no validation), though `RRSIG` may still appear in the answer.

### Test 5c — NSEC3 proof (child zone)
```bash
docker exec -it dns_client sh
dig @172.31.0.11 nope1.example.test A +dnssec +multi
```
**Expected:** `status: NXDOMAIN` and `NSEC3` / `NSEC3PARAM` records in the authority section.

### Test 5d — Aggressive NSEC (validating resolver)
```bash
docker exec -it dns_client sh
dig @172.32.0.20 nope1.example.test A +dnssec
dig @172.32.0.20 nope2.example.test A +dnssec
```
**Expected:** the second NXDOMAIN can be synthesized from cached NSEC3 proofs.
For evidence, watch upstream queries with tcpdump (section 2) or check authoritative logs.

#### DNSSEC chain of trust (private lab, parent + child)
- **Authoritative #1 (parent):** serves `test.`
- **Authoritative #2 (child):** serves `example.test.` (signed)
- **Resolver (validating Unbound):** trust-anchor = `test.` and validates `www.example.test` via:
  `test (TA) -> DS(example.test) -> DNSKEY(example.test) -> RRSIG(A)`

Implementation note:
- `anchors/test.key` is written by the `anchor_export` service from the parent KSK.
- If you delete `bind9_parent/keys`, restart the lab so `anchor_export` rewrites `anchors/test.key`.
- If the child KSK changes, run DS recompute and restart the parent:
  `docker compose run --rm ds_recompute`
  `docker compose restart authoritative_parent`
  The `ds_recompute` service runs automatically on `docker compose up -d` and
  restarts the parent only if the DS changes.

---

### Test 6 — Host exposure is safe (localhost-only publish)
From the host OS (not in Docker):
```bash
dig @127.0.0.1 -p 5300 example.test A
dig @127.0.0.1 -p 5301 example.test A
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
RES_TRUSTED_PLAIN="172.32.0.21"
AUTH_PARENT="172.31.0.10"
AUTH_CHILD="172.31.0.11"

pass(){ echo "✅ PASS: $1"; }
fail(){ echo "❌ FAIL: $1"; exit 1; }

echo "[1] Trusted recursion should work..."
out1="$(docker exec dns_client sh -lc "dig +time=1 +tries=1 @${RES_TRUSTED} example.test A" || true)"
echo "$out1" | grep -q "status: NOERROR" && pass "trusted recursion" || fail "trusted recursion"

echo "[2] Untrusted recursion should be blocked..."
out2="$(docker exec dns_untrusted sh -lc "dig +time=1 +tries=1 @${RES_UNTRUSTED} example.test A" || true)"
echo "$out2" | grep -Eq "status: REFUSED|connection timed out|no servers could be reached" \
  && pass "untrusted recursion blocked" || fail "untrusted recursion blocked"

echo "[3] Client should not reach parent authoritative (segmentation)..."
out3="$(docker exec dns_client sh -lc "dig +time=1 +tries=1 @${AUTH_PARENT} test SOA" || true)"
echo "$out3" | grep -Eq "connection timed out|no servers could be reached" \
  && pass "parent auth isolated from client_net" || fail "parent auth isolated from client_net"

echo "[4] Client should not reach child authoritative (segmentation)..."
out4="$(docker exec dns_client sh -lc "dig +time=1 +tries=1 @${AUTH_CHILD} example.test SOA" || true)"
echo "$out4" | grep -Eq "connection timed out|no servers could be reached" \
  && pass "child auth isolated from client_net" || fail "child auth isolated from client_net"

echo "[5] Plain resolver should NOT set AD flag..."
out5="$(docker exec dns_client sh -lc "dig +time=1 +tries=1 @${RES_TRUSTED_PLAIN} www.example.test A +dnssec" || true)"
echo "$out5" | grep -Eq "flags: .* ad" \
  && fail "plain resolver should not validate" || pass "plain resolver no AD"

echo "All smoke tests completed."
```

### 4.2 Run it
```bash
chmod +x smoke_test_dns_lab.sh
./smoke_test_dns_lab.sh
```

---

## 5)  evidence checklist 

### 5.1 Topology proof
- Output (screenshot) of `docker network inspect ...` (shows networks + attachments + IPs)
- Output (screenshot) of container IP listing (section 1.3)

### 5.2 Traffic proof
- Wireshark screenshot from `dns.pcap` showing client → resolver query
- Wireshark screenshot from `dns.pcap` showing resolver → authoritative query
- Wireshark screenshot from `dns.pcap` showing authoritative → resolver response
- Wireshark screenshot from `dns.pcap` showing resolver → client response

### 5.3 Security behavior proof (table)
Create a table in the :

| Test | Description | Command | Expected | Observed |
|---|---|---|---|---|
| T1 | Trusted recursion works | `dig @172.32.0.20 ...` | NOERROR | ... |
| T2 | Untrusted blocked | `dig @172.33.0.20 ...` | REFUSED/No-RA | ... |
| T3 | Authoritative isolated | `dig @172.31.0.10 ...` | timeout | ... |
| T4 | Resolver→Auth OK | `drill @172.31.0.10 ...` | OK | ... |
| T5a | DNSSEC validation (validating) | `delv ...` | validated | ... |
| T5b | DNSSEC no validation (plain) | `dig @172.32.0.21 ... +dnssec` | no `ad` | ... |
| T6a | Localhost-only publish (valid) | `dig @127.0.0.1 -p 5300 ...` | OK local | ... |
| T6b | Localhost-only publish (plain) | `dig @127.0.0.1 -p 5301 ...` | OK local | ... |

---




docker pull internetsystemsconsortium/bind9:9.18
docker pull mvance/unbound:1.20.0
docker pull alpine:3.20
docker pull nicolaka/netshoot:latest
