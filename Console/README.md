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

The Agent reads the token directly from that file and sends it as `X-Agent-Token` for telemetry, heartbeats, command polling, and command completion. No shell export is needed. Restart Uvicorn and the Agent after changing `.env` so each reloads the file. Each Agent creates a persistent ID under the user's local application data directory (or falls back to the machine name if that location is not writable) and reports its hostname, best-effort local IP address, and OS version every 60 seconds. The Console marks agents offline after 3 minutes without a heartbeat.

The Agent connects to `http://127.0.0.1:8000` by default, matching the Brain and console. To use a different Brain address, add `VECTORONE_API_URL` to the same `.env` file with the full telemetry endpoint, for example `VECTORONE_API_URL=http://127.0.0.1:9000/api/telemetry`, then restart the Agent.

The Agent watches the current user's Downloads folder, platform temporary folders, and available startup/persistence folders (`/etc/init.d` on Linux and Startup folders on Windows). Hidden dotfiles, partial downloads, temporary/lock files, and common IDE/build cache directories are skipped before telemetry is sent. The Console tags malicious or suspicious file observations as MITRE ATT&CK `T1204.002` (User Execution / Execution); other verdicts remain unmapped unless telemetry supports an ATT&CK technique.

## Response flow

Force Delete queues a `delete` command for the event filepath. The Agent polls pending commands every 10 seconds and acknowledges the command after the target is absent or deleted. Commands are not executed automatically from a detection verdict.
