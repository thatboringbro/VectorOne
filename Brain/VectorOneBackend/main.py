from fastapi import FastAPI
import sqlite3
from Models.payload import Payload
from Controllers import analyzeArtifact

app = FastAPI()

# model moved to Models/model.py

connection = sqlite3.connect('vectorone_brain.db', check_same_thread=False)
cursor = connection.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        username TEXT,
        filetype TEXT,
        datecreated TEXT,
        filehash TEXT
        
    )
''')

connection.commit()

@app.post("/api/telemetry")
def receive_telemetry(payload: Payload):

    # check if the file hash is already present in the database
    file_present = analyzeArtifact.analyze(payload.filehash)
    if file_present:
        # check ithe verdict and return the appropriate response
        pass
    

    try:
        cursor.execute('''
            INSERT INTO file_events (filename, username, filetype, datecreated, filehash)
            VALUES (?, ?, ?, ?, ?)
        ''', (payload.filename, payload.username, payload.filetype, payload.datecreated, payload.filehash))
        connection.commit()
        
        print(f"Logged new event for hash: {payload.filehash}")

        return {"status": "success", "action": "none"} 
    
    except Exception as e:
        return {"status": "error", "message": str(e)}

