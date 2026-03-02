# dns-security-lab `lab_api`

A single management API (FastAPI) meant to be used with the docker-compose design:

- Joins `client_net`, `untrusted_net`, `mgmt_net`
- Runs **allow-listed** diagnostics (`dig`) against the resolver from the chosen segment
- Optionally reads logs from bind/unbound via read-only volume mounts

## Build/run (via compose)

Enable the `api` profile:

```bash
docker compose --profile api up -d --build
```

The API is published only on the VM localhost:

- `127.0.0.1:8000`

Use an SSH tunnel from Windows:

```bash
ssh -L 8000:127.0.0.1:8000 gns3@<VM_IP>
```

## Example requests

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:8000/dig \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change_me_long_random" \
  -d '{"profile":"trusted","resolver":"valid","name":"example.org","qtype":"A"}'

# Plain resolver (no DNSSEC validation)
curl -s http://localhost:8000/dig \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change_me_long_random" \
  -d '{"profile":"trusted","resolver":"plain","name":"example.org","qtype":"A"}'

# Send a test email (requires mailserver + swaks containers running)
curl -s http://localhost:8000/email/send \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change_me_long_random" \
  -d '{"to":"user@example.test","from":"user@example.test","subject":"test","body":"hello","server":"mail.example.test","port":25}'

# Tail mail logs (DKIM/SPF)
curl -s "http://localhost:8000/email/logs?tail=200&grep=dkim" \
  -H "X-API-Key: change_me_long_random"

# IMAP check (read headers)
curl -s http://localhost:8000/email/imap-check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change_me_long_random" \
  -d '{"user":"user@example.test","mailbox":"INBOX","limit":40}'
```

## Security notes

- Do **not** add any endpoint that runs arbitrary shell strings.
- Keep this service bound to VM localhost and reach it via SSH tunnel.
- Email endpoints require `LAB_API_ALLOW_DOCKER=1` (already set in compose).
