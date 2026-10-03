from pathlib import Path
import sqlite3

from fastapi import FastAPI

from Controllers import analyzeArtifact
from Models.payload import Payload

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vectorone_brain.db"

app = FastAPI(title="VectorOne Backend")

connection = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = connection.cursor()

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        username TEXT,
        filetype TEXT,
        datecreated TEXT,
        filehash TEXT UNIQUE
    )
    """
)
connection.commit()


@app.post("/api/telemetry")
def receive_telemetry(payload: Payload):
    verdict = analyzeArtifact.analyze(payload.filehash)

    try:
        cursor.execute(
            """
            INSERT OR IGNORE INTO file_events (filename, username, filetype, datecreated, filehash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                payload.filename,
                payload.username,
                payload.filetype,
                payload.datecreated,
                payload.filehash,
            ),
        )
        connection.commit()

        inserted = cursor.rowcount > 0
        print(f"Logged new event for hash: {payload.filehash}")

        return {
            "status": "success",
            "verdict": verdict,
            "action": "logged" if inserted else "duplicate",
        }

    except Exception as e:
        return {"status": "error", "message": str(e), "verdict": verdict}

