import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

SESSION_LIFETIME = timedelta(hours=12)
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def initialize_auth_database(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analysts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                company_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_sessions (
                token_hash TEXT PRIMARY KEY,
                analyst_id INTEGER NOT NULL REFERENCES analysts(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            )
            """
        )


def _hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = encoded.split("$", maxsplit=5)
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_analyst(db_path: Path, email: str, password: str, full_name: str, company_name: str) -> None:
    normalized_email = email.strip().casefold()
    normalized_name = full_name.strip()
    normalized_company = company_name.strip()
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("A valid email address is required")
    if not normalized_name or not normalized_company:
        raise ValueError("Full name and company name are required")

    password_hash = _hash_password(password)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO analysts (email, password_hash, full_name, company_name, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                normalized_email,
                password_hash,
                normalized_name,
                normalized_company,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def authenticate_analyst(db_path: Path, email: str, password: str) -> dict | None:
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT id, email, password_hash, full_name, company_name FROM analysts WHERE email = ?",
            (email.strip().casefold(),),
        ).fetchone()

    if row is None or not _verify_password(password, row["password_hash"]):
        return None
    return {key: row[key] for key in ("id", "email", "full_name", "company_name")}


def create_session(db_path: Path, analyst_id: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + SESSION_LIFETIME).isoformat()
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO analyst_sessions (token_hash, analyst_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, analyst_id, expires_at),
        )
    return token, expires_at


def get_session_analyst(db_path: Path, token: str) -> dict | None:
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = datetime.now(timezone.utc)
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT analysts.id, analysts.email, analysts.full_name, analysts.company_name,
                   analyst_sessions.expires_at
            FROM analyst_sessions
            JOIN analysts ON analysts.id = analyst_sessions.analyst_id
            WHERE analyst_sessions.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= now:
            connection.execute("DELETE FROM analyst_sessions WHERE token_hash = ?", (token_hash,))
            return None
        return {key: row[key] for key in ("id", "email", "full_name", "company_name")}


def revoke_session(db_path: Path, token: str) -> None:
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with sqlite3.connect(db_path) as connection:
        connection.execute("DELETE FROM analyst_sessions WHERE token_hash = ?", (token_hash,))
