from datetime import datetime, timezone
import hmac
from pathlib import Path
import sqlite3

from dotenv import dotenv_values
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from Controllers import analyzeArtifact
from Models.payload import AnalystLogin, CommandRequest, EndpointHeartbeat, Payload
from security import (
    authenticate_analyst,
    create_session,
    get_session_analyst,
    initialize_auth_database,
    revoke_session,
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vectorone_brain.db"
AGENT_TOKEN = (dotenv_values(BASE_DIR / ".env").get("VECTORONE_AGENT_TOKEN") or "").strip()

app = FastAPI(title="VectorOne Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1):\d+",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Agent-Token"],
)

analyzeArtifact.initialize_database()
initialize_auth_database(DB_PATH)
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_analyst(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Analyst authentication required")
    analyst = get_session_analyst(DB_PATH, credentials.credentials)
    if analyst is None:
        raise HTTPException(status_code=401, detail="Analyst session is invalid or expired")
    return analyst


def require_agent_token(x_agent_token: str | None = Header(default=None)) -> None:
    if not AGENT_TOKEN:
        raise HTTPException(status_code=503, detail="Agent authentication is not configured")
    if x_agent_token is None or not hmac.compare_digest(x_agent_token, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="Agent authentication failed")


@app.post("/api/auth/login")
def login(credentials: AnalystLogin):
    analyst = authenticate_analyst(DB_PATH, credentials.email, credentials.password)
    if analyst is None:
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    token, expires_at = create_session(DB_PATH, analyst["id"])
    return {"access_token": token, "token_type": "bearer", "expires_at": expires_at, "analyst": analyst}


@app.get("/api/auth/me")
def current_analyst(analyst: dict = Depends(get_current_analyst)):
    return analyst


@app.post("/api/auth/logout")
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    analyst: dict = Depends(get_current_analyst),
):
    del analyst
    revoke_session(DB_PATH, credentials.credentials)
    return {"status": "signed_out"}


@app.post("/api/telemetry")
def receive_telemetry(payload: Payload, _: None = Depends(require_agent_token)):
    try:
        verdict = analyzeArtifact.analyze(payload.filehash)
        with sqlite3.connect(DB_PATH) as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO file_events
                    (filename, username, filetype, datecreated, filehash, filepath, device_name, device_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.filename,
                    payload.username,
                    payload.filetype,
                    payload.datecreated,
                    payload.filehash,
                    payload.filepath,
                    payload.device_name,
                    payload.device_id,
                ),
            )
            inserted = cursor.rowcount > 0
            if not inserted and (payload.filepath or payload.device_name or payload.device_id):
                connection.execute(
                    """
                    UPDATE file_events
                    SET filepath = CASE WHEN filepath IS NULL OR filepath = '' THEN ? ELSE filepath END,
                        device_name = CASE WHEN device_name IS NULL OR device_name = '' THEN ? ELSE device_name END,
                        device_id = CASE WHEN device_id IS NULL OR device_id = '' THEN ? ELSE device_id END
                    WHERE filehash = ?
                      AND ((filepath IS NULL OR filepath = '')
                           OR (device_name IS NULL OR device_name = '')
                           OR (device_id IS NULL OR device_id = ''))
                    """,
                    (payload.filepath, payload.device_name, payload.device_id, payload.filehash),
                )

        return {
            "status": "success",
            "verdict": verdict,
            "action": "logged" if inserted else "duplicate",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


@app.get("/api/events")
def list_events(_: dict = Depends(get_current_analyst)):
    with sqlite3.connect(DB_PATH) as connection:
        missing_checks = connection.execute(
            """
            SELECT event.filehash
            FROM file_events AS event
            LEFT JOIN integrity_checks AS checks ON checks.filehash = event.filehash
            WHERE checks.filehash IS NULL
            ORDER BY event.id DESC
            LIMIT 50
            """
        ).fetchall()
    for (file_hash,) in missing_checks:
        analyzeArtifact.ensure_integrity_check(file_hash)

    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT event.id, event.filename, event.username, event.filetype,
                   event.datecreated, event.filehash, event.filepath, event.device_name,
                   COALESCE(checks.verdict, 'unknown') AS verdict,
                   checks.virustotal_result, checks.abuse_ch_result,
                   (
                       SELECT command.status
                       FROM pending_commands AS command
                       WHERE command.filepath = event.filepath
                         AND command.action IN ('delete', 'quarantine')
                       ORDER BY command.id DESC
                       LIMIT 1
                   ) AS response_status
            FROM file_events AS event
            LEFT JOIN integrity_checks AS checks ON checks.filehash = event.filehash
            ORDER BY event.id DESC
            LIMIT 1000
            """
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/endpoints")
def list_endpoints(_: dict = Depends(get_current_analyst)):
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT asset.device_id, asset.device_name, asset.username, asset.os_version,
                   asset.domain_name, asset.first_seen, asset.last_seen,
                   COALESCE(stats.event_count, 0) AS event_count,
                   COALESCE(stats.malicious_count, 0) AS malicious_count,
                   COALESCE(stats.suspicious_count, 0) AS suspicious_count,
                   COALESCE(stats.observed_files, 0) AS observed_files
            FROM endpoint_assets AS asset
            LEFT JOIN (
                SELECT event.device_id,
                       COUNT(*) AS event_count,
                       SUM(CASE WHEN checks.verdict = 'malicious' THEN 1 ELSE 0 END) AS malicious_count,
                       SUM(CASE WHEN checks.verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
                       COUNT(DISTINCT event.filehash) AS observed_files
                FROM file_events AS event
                LEFT JOIN integrity_checks AS checks ON checks.filehash = event.filehash
                WHERE event.device_id <> ''
                GROUP BY event.device_id
            ) AS stats ON stats.device_id = asset.device_id
            ORDER BY asset.last_seen DESC
            LIMIT 1000
            """
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/endpoints/heartbeat")
def endpoint_heartbeat(heartbeat: EndpointHeartbeat, _: None = Depends(require_agent_token)):
    device_id = heartbeat.device_id.strip()
    device_name = heartbeat.device_name.strip()
    if not device_id or not device_name:
        raise HTTPException(status_code=422, detail="device_id and device_name are required")

    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT INTO endpoint_assets
                (device_id, device_name, username, os_version, domain_name, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name = excluded.device_name,
                username = excluded.username,
                os_version = excluded.os_version,
                domain_name = excluded.domain_name,
                last_seen = excluded.last_seen
            """,
            (
                device_id,
                device_name,
                heartbeat.username.strip(),
                heartbeat.os_version.strip(),
                heartbeat.domain_name.strip(),
                now,
                now,
            ),
        )
    return {"status": "registered", "device_id": device_id, "last_seen": now}


@app.post("/api/commands/issue", status_code=201)
def issue_command(command: CommandRequest, analyst: dict = Depends(get_current_analyst)):
    filepath = command.filepath.strip()
    if not filepath:
        raise HTTPException(status_code=422, detail="filepath must not be empty")
    if command.action not in {"delete", "quarantine"}:
        raise HTTPException(status_code=422, detail="unsupported action")

    created_at = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.execute(
            """
            INSERT INTO pending_commands (filepath, action, status, created_at, requested_by)
            VALUES (?, ?, 'pending', ?, ?)
            """,
            (filepath, command.action, created_at, analyst["id"]),
        )
        command_id = cursor.lastrowid

    return {
        "id": command_id,
        "filepath": filepath,
        "action": command.action,
        "status": "pending",
        "created_at": created_at,
    }


@app.get("/api/commands/pending")
def list_pending_commands(_: None = Depends(require_agent_token)):
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, filepath, action, status, created_at
            FROM pending_commands
            WHERE status = 'pending'
            ORDER BY id ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/commands/history")
def list_command_history(_: dict = Depends(get_current_analyst)):
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
                 SELECT command.id, command.filepath, command.action, command.status,
                     command.created_at, command.requested_by,
                     analyst.full_name AS requested_by_name,
                     analyst.email AS requested_by_email,
                   event.filename, event.username, event.filehash,
                   COALESCE(checks.verdict, 'unknown') AS verdict
            FROM pending_commands AS command
                 LEFT JOIN analysts AS analyst ON analyst.id = command.requested_by
            LEFT JOIN file_events AS event ON event.filepath = command.filepath
            LEFT JOIN integrity_checks AS checks ON checks.filehash = event.filehash
            ORDER BY command.id DESC
            LIMIT 1000
            """
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/commands/complete/{command_id}")
def complete_command(command_id: int, _: None = Depends(require_agent_token)):
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.execute(
            "UPDATE pending_commands SET status = 'completed' WHERE id = ? AND status = 'pending'",
            (command_id,),
        )
        if cursor.rowcount == 0:
            row = connection.execute(
                "SELECT status FROM pending_commands WHERE id = ?",
                (command_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="command not found")
    return {"id": command_id, "status": "completed"}

