# VectorOne

[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/UI-React-149ECA?logo=react&logoColor=white)](https://react.dev/)
[![Vite](https://img.shields.io/badge/build-Vite-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![SQLite](https://img.shields.io/badge/storage-SQLite-003B57?logo=sqlite&logoColor=white)](https://sqlite.org/)

VectorOne is an open-source learning platform for exploring how endpoint agents, a security control plane, and threat-intelligence services work together. It is built for blue-teamers, SOC analysts, and security students who want a practical lab without enterprise licenses or a hosted cloud stack.

Many security labs teach log analysis well, but stop short of showing how endpoint telemetry is collected, evaluated, presented to analysts, and turned into a response action. VectorOne aims to bridge that gap: from static SSH or Wazuh exercises to hands-on, systems-level EDR engineering.

> “The community progresses when elders plant trees whose shade they won't sit under.”

## What VectorOne does

- Watches selected high-risk filesystem locations and reports new-file metadata, including SHA-256 hashes.
- Looks up file hashes with VirusTotal and Abuse.ch MalwareBazaar when credentials are configured, then caches results locally.
- Registers agents, tracks endpoint heartbeats, and marks agents offline after 180 seconds without a heartbeat.
- Presents telemetry, fleet status, threat-intelligence results, and response history in a local SOC console.
- Lets an authenticated analyst queue a response command for an agent to process.

> **Lab safety:** VectorOne is an educational project, not a hardened production EDR. The current agent executes both `delete` and `quarantine` commands using `File.Delete`; “quarantine” does **not** yet provide isolation or file recovery. Run it only on systems and files you are authorized to monitor, preferably in a disposable VM with test data.

## Architecture

VectorOne is a decoupled, three-tier monorepo. The Brain and Console communicate over HTTP; the Agent reports to the Brain and polls it for commands.

| Component | Path | Technology | Responsibility |
| --- | --- | --- | --- |
| **Agent** | [`Agent/VectorOne/`](./Agent/VectorOne/) | C# / .NET 8 Worker Service | Cross-platform background worker for Windows and Linux. Watches the current user's Downloads directory, temporary directories, and available startup-related locations; computes SHA-256 for newly created files; sends telemetry and 60-second heartbeats; polls for analyst commands every 10 seconds. |
| **Brain** | [`Brain/VectorOneBackend/`](./Brain/VectorOneBackend/) | Python / FastAPI / SQLite | Local control plane and REST API. Maintains the agent and analyst registries, event and command data in `vectorone_brain.db`, and cached threat-intelligence results. |
| **SOC Console** | [`Console/`](./Console/) | React 19 / TypeScript / Vite | Dark-mode analyst interface for detection events, endpoint fleet status, threat details, and response history. Styling is implemented in the project's CSS files; Tailwind is not currently configured. |

The Agent skips common partial-download and temporary files, hidden dotfiles, and selected development/cache directories. Response commands are accepted only for paths under the agent's watched locations. The Console and Brain refresh event, fleet, and history views periodically.

### Data and response flow

1. The Agent detects a new file in a watched directory and reports its path, metadata, device identity, and SHA-256 hash to the Brain.
2. The Brain queries configured threat-intelligence providers and stores a per-hash result in SQLite. Cached checks prevent repeating lookups for the same hash.
3. An authenticated analyst reviews events and fleet health in the Console.
4. An analyst can queue a response action; the Agent polls for it, checks that the target is in a watched directory, processes it, and acknowledges completion.

The current MITRE ATT&CK mapping associates malicious and suspicious file observations with **T1204.002**. This is a contextual learning aid, not a full technique-detection engine.

## API keys and local configuration

API credentials and the shared agent token are configured locally in `Brain/VectorOneBackend/.env`. The repository `.gitignore` excludes `.env`; **do not commit real credentials**. The provided template is [`Brain/VectorOneBackend/.env.example`](./Brain/VectorOneBackend/.env.example).

From the backend directory, copy the template and edit the new `.env` file with your own provider credentials and a newly generated random agent token:

```dotenv
VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
ABUSE_CH_API_KEY="your_abuse_ch_api_key_here"
VECTORONE_AGENT_TOKEN=generate_your_own_vectorone_agent_token_here
```

Replace every placeholder. `ABUSE_CH_API_KEY` is sent as the MalwareBazaar `Auth-Key` header. The Brain and Agent read `VECTORONE_AGENT_TOKEN` from this same file; they will not accept agent traffic if it is missing. For example, generate a token with:

```bash
openssl rand -hex 32
```

Then place its output in `.env` as the value of `VECTORONE_AGENT_TOKEN`. If a threat-intelligence key is not configured, that provider's lookup is unavailable; the backend can still run, but results will not include that source.

> Keep `.env.example` as a template with placeholders. The `.env` file is the local, ignored configuration file. Restart the Brain and Agent after changing credentials so both processes reload the file.

## Quick start

### Prerequisites

- Python 3.10 or newer
- Node.js and npm
- .NET 8 SDK
- Optional: API credentials for VirusTotal and Abuse.ch MalwareBazaar
- For safely testing response actions: a disposable VM or test machine with nonessential sample files

### 1. Configure and run the Brain

```bash
cd Brain/VectorOneBackend
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

In Windows PowerShell, activate the environment with `.\venv\Scripts\Activate.ps1` and copy the template with `Copy-Item .env.example .env`.

Edit `Brain/VectorOneBackend/.env` as described above, then start the API from `Brain/VectorOneBackend`:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The Brain initializes its SQLite tables in `vectorone_brain.db` when it starts. Keep this terminal running. The API documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

### 2. Create a local analyst account

Analyst registration is not exposed in the Console. In another terminal, create an account interactively:

```bash
cd Brain/VectorOneBackend
source venv/bin/activate
python create_analyst.py
```

Enter the requested identity details and a password of at least 12 characters. Sign in with this account in the Console.

### 3. Run the SOC Console

In another terminal:

```bash
cd Console
npm install
npm run dev
```

Open the local URL printed by Vite (typically [http://localhost:5173](http://localhost:5173)) and sign in. By default, the Console uses the Brain at `http://127.0.0.1:8000`. To point it elsewhere, create `Console/.env.local`:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000
```

### 4. Build and run the Agent

Start the Agent from the repository root so it can locate the shared `Brain/VectorOneBackend/.env` file:

```bash
dotnet run --project Agent/VectorOne/VectorOne.csproj
```

The Agent requires `VECTORONE_AGENT_TOKEN` to be set in that shared `.env` file. It connects to `http://127.0.0.1:8000` by default. To use another Brain address, add the full telemetry endpoint to the same `.env` file and restart the Agent:

```dotenv
VECTORONE_API_URL=http://127.0.0.1:8000/api/telemetry
```

The Agent derives its command and heartbeat endpoints from that URL's origin. It creates a persistent agent ID in the user's application-data directory when possible. Keep the Agent running to see heartbeats and file events appear in the Console.

### Optional build and test commands

Run the Agent commands from the repository root:

```bash
# Build the Agent and its tests
dotnet build Agent/VectorOne.sln
dotnet test Agent/VectorOne.sln
```

Run the Console checks from `Console/`:

```bash
cd Console
npm run build
npm run lint
```

Run the Brain tests from `Brain/VectorOneBackend/` with its virtual environment activated:

```bash
cd Brain/VectorOneBackend
source venv/bin/activate
python -m unittest discover -s tests
```

## Design philosophy

### Deterministic path targeting

VectorOne favors transparent, reproducible collection over complex AI/ML scoring. The Agent watches known locations such as Downloads, temporary directories, and available startup-related directories. This keeps the learning loop approachable: analysts can see which file activity produced an event and trace its hash through the system.

### A simple, observable control plane

The Brain is local-first. SQLite keeps event, endpoint, analyst-session, command, and threat-intelligence data in a single file, making the system easier to run and inspect without provisioning a cloud database.

### Rate-conscious threat intelligence

Hash lookups are made against VirusTotal and MalwareBazaar when their API keys are configured. Results are cached by file hash in the local database, limiting repeat provider calls and making free-tier API usage more practical.

### Clear fleet liveness

Agents send heartbeats every 60 seconds. The Brain and Console use a 180-second timeout to classify a registered agent as offline, giving the UI a clear and understandable liveness rule.

## Roadmap: v1.1+

These are planned directions for community contributions, not all shipped features:

- Expand MITRE ATT&CK coverage and add richer technique/tactic context beyond the current T1204.002 mapping.
- Implement true encrypted file isolation, with explicit restore workflows and audit history; replace the current destructive “quarantine” behavior.
- Add YARA and Sigma detection-rule parsing and explainable rule matches.
- Improve setup, packaging, and cross-platform service installation for lab deployments.
- Add more provider integrations and configurable cache-expiration policies.

## Contributing

Contributions that improve portability, detection transparency, safe response workflows, documentation, or tests are welcome. Please open an issue to discuss a larger feature before starting implementation. When contributing, include the steps needed to reproduce behavior and tests for changes where practical.

## Contact

You can also reach me via the following social media pages:

[X (formerly Twitter)](https://x.com/thatboringbro)

[LinkedIn](https://www.linkedin.com/in/gbolahan-joel-adeoye-0551bb2a1/)
