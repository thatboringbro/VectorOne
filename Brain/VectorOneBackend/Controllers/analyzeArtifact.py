import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib import error, request
from dotenv import dotenv_values

BASE_DIR = Path(__file__).resolve().parents[1]
DOTENV_SETTINGS = dotenv_values(BASE_DIR / ".env")
DB_PATH = BASE_DIR / "vectorone_brain.db"
MITRE_MAPPING = {
    "malicious": ("T1204.002", "Execution"),
    "suspicious": ("T1204.002", "Execution"),
}


def initialize_database() -> None:
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                username TEXT,
                filetype TEXT,
                datecreated TEXT,
                filehash TEXT UNIQUE,
                mitre_id TEXT DEFAULT 'T1204.002',
                mitre_tactics TEXT DEFAULT 'Execution'
            )
            """
        )
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(file_events)")
        }
        if "filepath" not in columns:
            connection.execute("ALTER TABLE file_events ADD COLUMN filepath TEXT NOT NULL DEFAULT ''")
        if "device_name" not in columns:
            connection.execute("ALTER TABLE file_events ADD COLUMN device_name TEXT NOT NULL DEFAULT ''")
        if "device_id" not in columns:
            connection.execute("ALTER TABLE file_events ADD COLUMN device_id TEXT NOT NULL DEFAULT ''")
        mitre_columns_missing = "mitre_id" not in columns or "mitre_tactics" not in columns
        if "mitre_id" not in columns:
            connection.execute("ALTER TABLE file_events ADD COLUMN mitre_id TEXT DEFAULT 'T1204.002'")
        if "mitre_tactics" not in columns:
            connection.execute("ALTER TABLE file_events ADD COLUMN mitre_tactics TEXT DEFAULT 'Execution'")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS integrity_checks (
                filehash TEXT PRIMARY KEY,
                virustotal_result TEXT NOT NULL,
                abuse_ch_result TEXT NOT NULL,
                verdict TEXT NOT NULL,
                checked_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filepath TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            )
            """
        )
        command_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(pending_commands)")
        }
        if "requested_by" not in command_columns:
            connection.execute("ALTER TABLE pending_commands ADD COLUMN requested_by INTEGER")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS endpoint_assets (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                os_version TEXT NOT NULL DEFAULT '',
                domain_name TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                os_version TEXT NOT NULL,
                status TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        mitre_backfill_filter = (
            ""
            if mitre_columns_missing
            else "WHERE event.mitre_id IS NULL OR event.mitre_tactics IS NULL"
        )
        default_mitre_id, default_mitre_tactic = MITRE_MAPPING["malicious"]
        connection.execute(
            f"""
            UPDATE file_events AS event
            SET mitre_id = (
                    SELECT CASE WHEN checks.verdict IN ('malicious', 'suspicious')
                                THEN ? ELSE NULL END
                    FROM integrity_checks AS checks
                    WHERE checks.filehash = event.filehash
                ),
                mitre_tactics = (
                    SELECT CASE WHEN checks.verdict IN ('malicious', 'suspicious')
                                THEN ? ELSE NULL END
                    FROM integrity_checks AS checks
                    WHERE checks.filehash = event.filehash
                )
            {mitre_backfill_filter}
            """,
            (default_mitre_id, default_mitre_tactic),
        )


def mitre_metadata_for_verdict(verdict: str) -> tuple[str | None, str | None]:
    """Map threat verdicts to ATT&CK metadata supported by file telemetry."""
    return MITRE_MAPPING.get(verdict.casefold(), (None, None))


def _get_api_key(*names: str) -> str | None:
    for name in names:
        value = DOTENV_SETTINGS.get(name)
        if value and value.strip():
            return value.strip()
    return None


def _request_json(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    payload: dict | None = None,
    form_payload: bool = False,
):
    data = None
    if payload is not None:
        if form_payload:
            data = urlencode(payload).encode("utf-8")
        else:
            data = json.dumps(payload).encode("utf-8")

    req = request.Request(url, data=data, headers=headers or {}, method=method)

    try:
        with request.urlopen(req, timeout=15) as response:
            response_text = response.read().decode("utf-8")
            body = json.loads(response_text) if response_text else {}
            return {"ok": True, "data": body}
    except error.HTTPError as exc:
        response_text = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(response_text) if response_text else {}
        except json.JSONDecodeError:
            parsed = {"error": response_text}
        return {"ok": False, "status_code": exc.code, "error": parsed}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def check_virustotal(file_hash: str) -> dict:
    """Check the file hash against VirusTotal when an API key is configured."""
    api_key = _get_api_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"available": False, "malicious": 0, "suspicious": 0, "error": "missing VIRUSTOTAL_API_KEY"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = _request_json(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="GET",
    )

    if not response.get("ok"):
        return {"available": False, "malicious": 0, "suspicious": 0, "error": response.get("error")}

    attrs = response["data"].get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    return {"available": True, "malicious": malicious, "suspicious": suspicious, "stats": stats}


def check_abuse_ch(file_hash: str) -> dict:
    """Check the file hash against abuse.ch MalwareBazaar when an API key is configured."""
    api_key = _get_api_key("ABUSE_CH_API_KEY", "ABUSECH_API_KEY")
    if not api_key:
        return {"available": False, "malicious": False, "error": "missing ABUSE_CH_API_KEY"}

    url = "https://mb-api.abuse.ch/api/v1/"
    response = _request_json(
        url,
        headers={"Auth-Key": api_key, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
        payload={"query": "get_info", "hash": file_hash},
        form_payload=True,
    )

    if not response.get("ok"):
        return {"available": False, "malicious": False, "error": response.get("error")}

    payload = response["data"]
    query_status = payload.get("query_status")
    if query_status in {"hash_not_found", "no_result"}:
        return {
            "available": True,
            "malicious": False,
            "query_status": query_status,
            "results": [],
        }
    if query_status != "ok":
        return {
            "available": False,
            "malicious": False,
            "query_status": query_status,
            "error": f"Unexpected MalwareBazaar query status: {query_status or 'missing'}",
        }

    data = payload.get("data") or payload.get("results") or []
    matches = data if isinstance(data, list) else [data] if data else []
    normalized_hash = file_hash.casefold()
    malicious = bool(
        matches
        and any(
            str(item.get("sha256_hash", "")).casefold() == normalized_hash
            for item in matches
            if isinstance(item, dict)
        )
    )
    return {
        "available": True,
        "malicious": malicious,
        "query_status": query_status,
        "results": matches,
    }


def analyze(file_hash: str) -> str:
    """Return a verdict based on local records and available external telemetry sources."""
    if not file_hash:
        return "unknown"

    initialize_database()
    with sqlite3.connect(DB_PATH) as connection:
        cached = connection.execute(
            "SELECT verdict FROM integrity_checks WHERE filehash = ?",
            (file_hash,),
        ).fetchone()
        if cached is not None and cached[0] == "malicious":
            return cached[0]

        row = connection.execute(
            "SELECT 1 FROM file_events WHERE filehash = ? LIMIT 1",
            (file_hash,),
        ).fetchone()
        if row is not None:
            return "duplicate"

        if cached is not None:
            return cached[0]

    return _run_and_store_integrity_checks(file_hash)


def ensure_integrity_check(file_hash: str) -> None:
    """Fetch and cache both CTI providers only when no snapshot exists for a hash."""
    if not file_hash:
        return
    initialize_database()
    with sqlite3.connect(DB_PATH) as connection:
        cached = connection.execute(
            "SELECT 1 FROM integrity_checks WHERE filehash = ?",
            (file_hash,),
        ).fetchone()
    if cached is None:
        _run_and_store_integrity_checks(file_hash)


def _run_and_store_integrity_checks(file_hash: str) -> str:
    vt = check_virustotal(file_hash)
    abuse = check_abuse_ch(file_hash)

    if vt.get("malicious", 0) > 0 or abuse.get("malicious") is True:
        verdict = "malicious"

    elif vt.get("suspicious", 0) > 0:
        verdict = "suspicious"
    else:
        verdict = "new"

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO integrity_checks
                (filehash, virustotal_result, abuse_ch_result, verdict, checked_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                file_hash,
                json.dumps(vt),
                json.dumps(abuse),
                verdict,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    return verdict


def check_virustotal_status():
    """Compatibility wrapper kept for older call sites."""
    return check_virustotal