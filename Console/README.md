# VectorOne SOC Console

React + TypeScript + Vite analyst console for endpoint telemetry and queued response commands.

## Run locally

```bash
npm install
npm run dev
```

The console expects the Brain at `http://127.0.0.1:8000` by default. To use another address, create a `.env.local` file with:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000
```

The Brain allows local Vite origins on `localhost` and `127.0.0.1`, including when Vite selects a port other than `5173`.

## Analyst access

Analyst accounts are provisioned locally by an administrator; public registration is disabled. From `Brain/VectorOneBackend`, run:

```bash
venv/bin/python create_analyst.py
```

The script prompts for the analyst's email, full name, company, and password. Passwords must be at least 12 characters; only an scrypt password hash is stored. Sign-in sessions expire after 12 hours and are held in browser session storage.

## Agent credential

The Brain and Agent both read the same ignored file at `Brain/VectorOneBackend/.env`. Generate a random secret with `openssl rand -hex 32`, then configure:

```dotenv
VECTORONE_AGENT_TOKEN=replace-with-generated-secret
```

The Agent reads the token directly from that file and sends it as `X-Agent-Token` for telemetry, command polling, and command completion. No shell export is needed. Restart Uvicorn and the Agent after changing `.env` so each reloads the file.

## Response flow

Force Delete queues a `delete` command for the event filepath. The Agent polls pending commands every 10 seconds and acknowledges the command after the target is absent or deleted. Commands are not executed automatically from a detection verdict.
