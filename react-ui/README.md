# React UI (Win11)

## Setup
1. Copy env template:
   ```bash
   copy .env.example .env.local
   ```
2. Set `VITE_LAB_API_KEY` to match `LAB_API_KEY` in `docker-compose.yml` if you want
   Lab API features (logs, or execute dig via lab API).
3. (Optional) Adjust `VITE_API_BASE` if you are not using the default `/api` proxy.
4. (Optional) Adjust `VITE_LAB_API_BASE` if you are not using the default `/lab-api`
   proxy (for dev mode you can point it to `http://127.0.0.1:8000`).
5. Install deps:
   ```bash
   npm install
   ```
6. Start dev server:
   ```bash
   npm run dev
   ```

App runs at `http://localhost:5173` and uses:
- `/api/{client}` for the per-client FastAPI services
- `/lab-api` for the lab API (logs + optional dig)

## Notes
- Use `npm run dev -- --host` if you want LAN access.
- The API services are expected to be running via `docker compose up -d`.
- The UI includes a **Resolver** selector to target the validating or plain Unbound.
