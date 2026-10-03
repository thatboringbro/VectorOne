import json
import os
import sqlite3
from pathlib import Path
from urllib import error, request

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "vectorone_brain.db"


def _get_api_key(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


def _request_json(url: str, headers: dict[str, str] | None = None, method: str = "GET", payload: dict | None = None):
    data = None
    if payload is not None:
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
        headers={"Auth-Key": api_key, "Content-Type": "application/json"},
        method="POST",
        payload={"query": "get_info", "hash": file_hash},
    )

    if not response.get("ok"):
        return {"available": False, "malicious": False, "error": response.get("error")}

    payload = response["data"]
    query_status = payload.get("query_status")
    if query_status in {"hash_not_found", "ok", "no_result"}:
        data = payload.get("data") or payload.get("results") or []
        matches = data if isinstance(data, list) else [data] if data else []
        malicious = bool(matches and any(item.get("sha256_hash") == file_hash for item in matches if isinstance(item, dict)))
        return {"available": True, "malicious": malicious, "results": matches}

    return {"available": True, "malicious": False, "results": []}


def analyze(file_hash: str) -> str:
    """Return a verdict based on local records and available external telemetry sources."""
    if not file_hash:
        return "unknown"

    try:
        with sqlite3.connect(DB_PATH) as connection:
            row = connection.execute(
                "SELECT 1 FROM file_events WHERE filehash = ? LIMIT 1",
                (file_hash,),
            ).fetchone()
    except Exception:
        row = None

    if row is not None:
        return "duplicate"

    vt = check_virustotal(file_hash)
    abuse = check_abuse_ch(file_hash)

    if vt.get("malicious", 0) > 0 or abuse.get("malicious") is True:
        return "malicious"

    if vt.get("suspicious", 0) > 0:
        return "suspicious"

    return "new"


def check_virustotal_status():
    """Compatibility wrapper kept for older call sites."""
    return check_virustotal