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
  -d '{"profile":"trusted","name":"example.org","qtype":"A"}'
```

## Security notes

- Do **not** add any endpoint that runs arbitrary shell strings.
- Keep this service bound to VM localhost and reach it via SSH tunnel.
