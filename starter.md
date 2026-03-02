# starter.md

Generated: 2026-02-26 15:08:02

## Compose Up (api profile)

**Command**

```bash
docker compose --profile api up -d
```
**Output**

```
time="2026-02-26T15:08:02+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
 Container dns_untrusted Running 
 Container dns_client Running 
 Container dns_portainer Running 
 Container dns_lab_api Running 
 Container dns_authoritative Running 
 Container dns_toolbox Running 
 Container dns_resolver Running
 Container dns_resolver_plain Running
```

## Compose Status

**Command**

```bash
docker compose ps
```
**Output**

```
time="2026-02-26T15:08:03+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
NAME                IMAGE                                  COMMAND                  SERVICE         CREATED          STATUS                    PORTS
dns_authoritative   internetsystemsconsortium/bind9:9.18   "/usr/sbin/named -u …"   authoritative   20 hours ago     Up 45 minutes             53/tcp, 443/tcp, 853/tcp, 953/tcp, 53/udp
dns_client          dns-client-tools:latest                "sh -lc 'sleep infin…"   client          24 minutes ago   Up 23 minutes             
dns_lab_api         dns-security-lab-lab_api               "uvicorn app.main:ap…"   lab_api         45 minutes ago   Up 44 minutes             8000/tcp
dns_portainer       portainer/portainer-ce:latest          "/portainer"             portainer       45 minutes ago   Up 44 minutes             9000/tcp, 9443/tcp
dns_resolver        mvance/unbound:1.20.0                  "/unbound.sh"            resolver        24 minutes ago   Up 23 minutes (healthy)   53/tcp, 53/udp
dns_resolver_plain  mvance/unbound:1.20.0                  "/unbound.sh"            resolver_plain  24 minutes ago   Up 23 minutes (healthy)   53/tcp, 53/udp
dns_toolbox         nicolaka/netshoot:latest               "sh -lc 'sleep infin…"   toolbox         20 hours ago     Up 44 minutes             
dns_untrusted       dns-client-tools:latest                "sh -lc 'sleep infin…"   untrusted       24 minutes ago   Up 23 minutes
```

## Trusted Recursion (example.test)

**Command**

```bash
docker compose exec -T client dig @172.32.0.20 example.test A +noall +answer +comments
```
**Output**

```
time="2026-02-26T15:08:06+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20609
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
```

## Trusted Recursion (example.test, plain resolver)

**Command**

```bash
docker compose exec -T client dig @172.32.0.21 example.test A +noall +answer +comments
```
**Expected**

```
status: NOERROR
flags: qr rd ra
```

## Trusted Recursion (www.example.test)

**Command**

```bash
docker compose exec -T client dig @172.32.0.20 www.example.test A +noall +answer +comments
```
**Output**

```
time="2026-02-26T15:08:06+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3094
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
www.example.test.	300	IN	A	172.31.0.11
```

## Untrusted Recursion Blocked

**Command**

```bash
docker compose exec -T untrusted dig @172.33.0.20 example.test A +noall +answer +comments
```
**Output**

```
time="2026-02-26T15:08:06+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 25335
;; flags: qr rd ad; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available
```

## Client Cannot Reach Authoritative

**Command**

```bash
docker compose exec -T client dig @172.31.0.10 example.test SOA +time=1 +tries=1 +noall +answer +comments
```
**Output**

```
time="2026-02-26T15:08:06+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
;; UDP setup with 172.31.0.10#53(172.31.0.10) for example.test failed: network unreachable.
;; no servers could be reached
```

## Resolver -> Authoritative

**Command**

```bash
docker compose exec -T resolver sh -lc "drill @172.31.0.10 example.test SOA"
```
**Output**

```
time="2026-02-26T15:08:07+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 63803
;; flags: qr aa rd ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0 
;; QUESTION SECTION:
;; example.test.	IN	SOA

;; ANSWER SECTION:
example.test.	300	IN	SOA	ns-child.test. admin.example.test. 2026022504 3600 900 604800 300

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; Query time: 0 msec
;; SERVER: 172.31.0.10
;; WHEN: Thu Feb 26 14:07:40 2026
;; MSG SIZE  rcvd: 76
```

## Plain Resolver -> Authoritative

**Command**

```bash
docker compose exec -T resolver_plain sh -lc "drill @172.31.0.10 example.test SOA"
```
**Expected**

```
status: NOERROR
```

## Resolver Local Answer

**Command**

```bash
docker compose exec -T resolver sh -lc "drill @127.0.0.1 www.example.test A"
```
**Output**

```
time="2026-02-26T15:08:10+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 18161
;; flags: qr rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0 
;; QUESTION SECTION:
;; www.example.test.	IN	A

;; ANSWER SECTION:
www.example.test.	293	IN	A	172.31.0.11

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; Query time: 0 msec
;; SERVER: 127.0.0.1
;; WHEN: Thu Feb 26 14:07:43 2026
;; MSG SIZE  rcvd: 50
```

## Plain Resolver Local Answer

**Command**

```bash
docker compose exec -T resolver_plain sh -lc "drill @127.0.0.1 www.example.test A"
```
**Expected**

```
status: NOERROR
```

## DNSSEC Validation (AD flag)

**Command**

```bash
docker compose exec -T client dig @172.32.0.20 www.example.test A +dnssec +noall +answer +comments
```
**Output**

```
time="2026-02-26T15:08:13+01:00" level=warning msg="G:\\Applications-2026-02-25-aspirepl2\\docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4522
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; ANSWER SECTION:
www.example.test.	293	IN	A	172.31.0.11
www.example.test.	293	IN	RRSIG	A 13 3 300 20260311114008 20260225171235 2860 example.test. BGwk9cxUkTtA5SLyO1+LGPDZWvehakDsh4GQrweo3z2Xw5Pitfw23bdj Ij8VuGhwI49D7jM9N9ZkIpKQZu9jKg==
```

## DNSSEC Validation (plain resolver, no AD flag)

**Command**

```bash
docker compose exec -T client dig @172.32.0.21 www.example.test A +dnssec +noall +answer +comments
```
**Expected**

```
status: NOERROR
flags: qr rd ra
```

## Architecture Update (Per-client APIs + Lab API + React UI)
- Per-client FastAPI agents run inside the segmented networks.
- `client` (trusted) queries validating resolver at `172.32.0.20`.
- `untrusted` queries validating resolver at `172.33.0.20`.
- `mgmt_client` queries validating resolver at `172.30.0.20`.
- Plain resolver (trusted) for manual tests: `172.32.0.21`.
- Plain resolver (untrusted) for manual tests: `172.33.0.21`.
- Plain resolver (mgmt) for manual tests: `172.30.0.21`.
- React UI proxies to client APIs via `/api/trusted`, `/api/untrusted`, `/api/mgmt`.
- Lab API is proxied at `/lab-api` for logs and optional dig execution.
- Run with `docker compose up -d --build`.


Co dalej (testy)

Przepisz strefę na podpisaną (BIND używa db.example.test.signed):
docker compose run --rm signer
Uruchom mailserver:
docker compose up -d mailserver
Uruchom swaks (test sender):
docker compose up -d --build swaks
Dodaj konto (DMS preferuje setup email add, a bez konta startuje i po chwili restartuje):
docker compose exec mailserver setup email add user@example.test
(docker-mailserver.github.io)
(Opcjonalnie) Jeśli chcesz wygenerować nowe klucze DKIM z poziomu DMS, użyj:
docker compose exec mailserver setup config dkim
Klucze wylądują w /tmp/docker-mailserver/opendkim/. (docker-mailserver.github.io)

UI (React) — Email:
- Otwórz http://localhost:5173 → zakładka Email.
- Ustaw From/To (np. user@example.test), Server=mail.example.test, Port=25.
- Kliknij “Send Email”, potem “Load DKIM Logs” żeby zobaczyć wynik w logach.
Oczekiwane:
- SMTP: `250 2.0.0 Ok: queued as ...`
- DKIM: `DKIM-Signature field added (s=mail, d=example.test)`
Opcjonalnie sprawdz IMAP (czy wiadomosc dotarla do skrzynki):
openssl s_client -connect 127.0.0.1:1993 -crlf
Nastepnie:
a login user@example.test <password>
a select INBOX
a fetch 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)])
a logout


2) Test commands (minimal flow)

Re‑sign zone (so db.example.test.signed contains MX/SPF/DKIM):

docker compose run --rm signer
Restart authoritative child so it reloads the signed zone:

docker compose restart authoritative_child
Start mailserver:

docker compose up -d mailserver
Start swaks (test sender):

docker compose up -d --build swaks
Create a test mailbox:

docker compose exec mailserver setup email add user@example.test
Send a test mail (if swaks is available on your host):

swaks --to user@example.test --from user@example.test --server 127.0.0.1 --port 2525 --data "Subject: test\r\n\r\nhello"
Check DKIM results in logs:

docker compose exec mailserver tail -n 200 /var/log/mail/

Note (Windows):
- Używamy named volume `mailserver_state` dla `/var/mail-state` (Postfix queue),
  bo bind mount na NTFS potrafi powodować `queue file write error`.


===

Send a test mail from inside the swaks container

docker compose exec swaks swaks \
  --to user@example.test \
  --from user@example.test \
  --server mail.example.test \
  --port 25 \
  --header "Subject: test" \
  --body "hello"

docker compose exec mailserver setup email add user@example.test
