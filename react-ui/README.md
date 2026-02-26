# React UI (Win11)

## Setup
1. Copy env template:
   ```bash
   copy .env.example .env.local
   ```
2. Set `VITE_LAB_API_KEY` to match `LAB_API_KEY` in `docker-compose.yml`.
3. Install deps:
   ```bash
   npm install
   ```
4. Start dev server:
   ```bash
   npm run dev
   ```

App runs at `http://localhost:5173` and proxies API calls to `http://127.0.0.1:8000`.

## Notes
- Use `npm run dev -- --host` if you want LAN access.
- The API is expected to be running via `docker compose --profile api up -d`.
