import os
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi.security import HTTPAuthorizationCredentials

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Controllers.analyzeArtifact import analyze, initialize_database
import main
from Models.payload import AgentHeartbeat, AnalystLogin, EndpointHeartbeat, Payload
from security import authenticate_analyst, create_analyst, create_session, get_session_analyst, initialize_auth_database, revoke_session


class AnalyzeArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")
        self.db_path_patcher = patch("Controllers.analyzeArtifact.DB_PATH", self.db_path)
        self.db_path_patcher.start()
        initialize_database()
        initialize_auth_database(self.db_path)

    def tearDown(self):
        self.db_path_patcher.stop()
        self.temp_dir.cleanup()

    @patch("Controllers.analyzeArtifact._get_api_key", return_value="test-key")
    @patch(
        "Controllers.analyzeArtifact._request_json",
        return_value={
            "ok": True,
            "data": {
                "query_status": "ok",
                "data": [{"sha256_hash": "a1b2c3", "signature": "test-family"}],
            },
        },
    )
    def test_abuse_ch_matches_hash_without_case_sensitivity(self, mock_request, mock_api_key):
        from Controllers.analyzeArtifact import check_abuse_ch

        result = check_abuse_ch("A1B2C3")

        self.assertTrue(result["available"])
        self.assertTrue(result["malicious"])
        self.assertEqual(result["query_status"], "ok")
        self.assertEqual(result["results"][0]["signature"], "test-family")
        mock_request.assert_called_once()

    @patch("Controllers.analyzeArtifact._get_api_key", return_value="test-key")
    @patch(
        "Controllers.analyzeArtifact._request_json",
        return_value={"ok": True, "data": {"query_status": "rate_limit"}},
    )
    def test_abuse_ch_reports_unexpected_provider_status_as_unavailable(self, mock_request, mock_api_key):
        from Controllers.analyzeArtifact import check_abuse_ch

        result = check_abuse_ch("a1b2c3")

        self.assertFalse(result["available"])
        self.assertFalse(result["malicious"])
        self.assertEqual(result["query_status"], "rate_limit")
        self.assertIn("rate_limit", result["error"])
        mock_request.assert_called_once()

    @patch("Controllers.analyzeArtifact.check_virustotal", return_value={"malicious": 1, "suspicious": 0})
    @patch("Controllers.analyzeArtifact.check_abuse_ch", return_value={"malicious": False})
    def test_analyze_marks_hash_as_malicious_when_external_sources_flag_it(self, mock_abuse, mock_vt):
        self.assertEqual(analyze("hash-flagged"), "malicious")
        with sqlite3.connect(self.db_path) as connection:
            cached = connection.execute(
                "SELECT virustotal_result, abuse_ch_result, verdict "
                "FROM integrity_checks WHERE filehash = ?",
                ("hash-flagged",),
            ).fetchone()

        self.assertEqual(json.loads(cached[0])["malicious"], 1)
        self.assertEqual(json.loads(cached[1])["malicious"], False)
        self.assertEqual(cached[2], "malicious")

    @patch("Controllers.analyzeArtifact.check_virustotal", return_value={"malicious": 0, "suspicious": 2})
    @patch("Controllers.analyzeArtifact.check_abuse_ch", return_value={"malicious": False})
    def test_analyze_marks_hash_as_suspicious_when_external_sources_are_suspicious(self, mock_abuse, mock_vt):
        self.assertEqual(analyze("hash-suspicious"), "suspicious")

    @patch(
        "Controllers.analyzeArtifact.check_virustotal",
        return_value={"available": True, "malicious": 0, "suspicious": 0, "stats": {"harmless": 5}},
    )
    @patch(
        "Controllers.analyzeArtifact.check_abuse_ch",
        return_value={"available": True, "malicious": False, "results": []},
    )
    def test_analyze_caches_full_integrity_results(self, mock_abuse, mock_vt):
        self.assertEqual(analyze("hash-cached"), "new")
        self.assertEqual(analyze("hash-cached"), "new")

        mock_vt.assert_called_once_with("hash-cached")
        mock_abuse.assert_called_once_with("hash-cached")
        with sqlite3.connect(self.db_path) as connection:
            cached = connection.execute(
                "SELECT virustotal_result, abuse_ch_result, verdict, checked_at "
                "FROM integrity_checks WHERE filehash = ?",
                ("hash-cached",),
            ).fetchone()

        self.assertEqual(json.loads(cached[0])["stats"], {"harmless": 5})
        self.assertEqual(json.loads(cached[1])["results"], [])
        self.assertEqual(cached[2], "new")
        self.assertTrue(cached[3])

    @patch("Controllers.analyzeArtifact.check_virustotal", return_value={"malicious": 0, "suspicious": 0})
    @patch("Controllers.analyzeArtifact.check_abuse_ch", return_value={"malicious": False})
    def test_analyze_skips_external_checks_for_recorded_duplicates(self, mock_abuse, mock_vt):
        self.assertEqual(analyze("hash-duplicate"), "new")
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO file_events (filename, username, filetype, datecreated, filehash) "
                "VALUES (?, ?, ?, ?, ?)",
                ("sample.bin", "tester", "binary", "today", "hash-duplicate"),
            )

        self.assertEqual(analyze("hash-duplicate"), "duplicate")
        mock_vt.assert_called_once_with("hash-duplicate")
        mock_abuse.assert_called_once_with("hash-duplicate")

    @patch("Controllers.analyzeArtifact.check_virustotal")
    @patch("Controllers.analyzeArtifact.check_abuse_ch")
    def test_cached_malicious_hash_stays_malicious_after_event_is_logged(self, mock_abuse, mock_vt):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO file_events (filename, username, filetype, datecreated, filehash) "
                "VALUES (?, ?, ?, ?, ?)",
                ("sample.bin", "tester", ".bin", "today", "known-malicious"),
            )
            connection.execute(
                "INSERT INTO integrity_checks "
                "(filehash, virustotal_result, abuse_ch_result, verdict, checked_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("known-malicious", '{"malicious": 1}', '{"malicious": false}', "malicious", "today"),
            )

        self.assertEqual(analyze("known-malicious"), "malicious")
        mock_vt.assert_not_called()
        mock_abuse.assert_not_called()

    def test_initialize_database_preserves_existing_events(self):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO file_events (filename, username, filetype, datecreated, filehash) "
                "VALUES (?, ?, ?, ?, ?)",
                ("sample.bin", "tester", "binary", "today", "existing-hash"),
            )

        initialize_database()

        with sqlite3.connect(self.db_path) as connection:
            event = connection.execute(
                "SELECT filename FROM file_events WHERE filehash = ?",
                ("existing-hash",),
            ).fetchone()
            cache_table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'integrity_checks'"
            ).fetchone()

        self.assertEqual(event[0], "sample.bin")
        self.assertIsNotNone(cache_table)

    def test_initialize_database_adds_and_backfills_mitre_columns(self):
        legacy_db = os.path.join(self.temp_dir.name, "legacy.db")
        with sqlite3.connect(legacy_db) as connection:
            connection.execute(
                """
                CREATE TABLE file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    username TEXT,
                    filetype TEXT,
                    datecreated TEXT,
                    filehash TEXT UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE integrity_checks (
                    filehash TEXT PRIMARY KEY,
                    virustotal_result TEXT NOT NULL,
                    abuse_ch_result TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    checked_at TEXT NOT NULL
                )
                """
            )
            connection.executemany(
                "INSERT INTO file_events (filename, filehash) VALUES (?, ?)",
                [("threat.bin", "old-malicious"), ("unknown.bin", "old-new")],
            )
            connection.executemany(
                """
                INSERT INTO integrity_checks
                    (filehash, virustotal_result, abuse_ch_result, verdict, checked_at)
                VALUES (?, '{}', '{}', ?, 'today')
                """,
                [("old-malicious", "malicious"), ("old-new", "new")],
            )

        with patch("Controllers.analyzeArtifact.DB_PATH", legacy_db):
            initialize_database()

        with sqlite3.connect(legacy_db) as connection:
            rows = connection.execute(
                "SELECT filehash, mitre_id, mitre_tactics FROM file_events ORDER BY filehash"
            ).fetchall()
            columns = {
                column[1]: column
                for column in connection.execute("PRAGMA table_info(file_events)")
            }

        self.assertEqual(rows, [("old-malicious", "T1204.002", "Execution"), ("old-new", None, None)])
        self.assertEqual(columns["mitre_id"][4], "'T1204.002'")
        self.assertEqual(columns["mitre_tactics"][4], "'Execution'")

    @patch("main.analyzeArtifact.analyze", return_value="new")
    def test_telemetry_endpoint_persists_payload(self, mock_analyze):
        payload = Payload(
            filename="sample.bin",
            username="tester",
            filetype=".bin",
            datecreated="2026-10-05 19:43:59",
            filehash="endpoint-hash",
        )

        with patch.object(main, "DB_PATH", self.db_path):
            response = main.receive_telemetry(payload)

        self.assertEqual(response, {"status": "success", "verdict": "new", "action": "logged"})
        mock_analyze.assert_called_once_with("endpoint-hash")
        with sqlite3.connect(self.db_path) as connection:
            event = connection.execute(
                "SELECT filename, username, filetype, datecreated, filehash "
                "FROM file_events WHERE filehash = ?",
                ("endpoint-hash",),
            ).fetchone()

        self.assertEqual(
            event,
            ("sample.bin", "tester", ".bin", "2026-10-05 19:43:59", "endpoint-hash"),
        )

    @patch("main.analyzeArtifact.analyze", return_value="malicious")
    def test_telemetry_endpoint_adds_mitre_mapping_for_malicious_file(self, mock_analyze):
        payload = Payload(
            filename="payload.bin",
            username="tester",
            filetype=".bin",
            datecreated="2026-10-05 19:43:59",
            filehash="mitre-endpoint-hash",
        )

        with patch.object(main, "DB_PATH", self.db_path):
            response = main.receive_telemetry(payload)

        self.assertEqual(response["verdict"], "malicious")
        with sqlite3.connect(self.db_path) as connection:
            mapping = connection.execute(
                "SELECT mitre_id, mitre_tactics FROM file_events WHERE filehash = ?",
                ("mitre-endpoint-hash",),
            ).fetchone()

        self.assertEqual(mapping, ("T1204.002", "Execution"))
        mock_analyze.assert_called_once_with("mitre-endpoint-hash")

    @patch("main.analyzeArtifact.analyze", return_value="malicious")
    def test_telemetry_endpoint_does_not_automatically_delete_malicious_verdict(self, mock_analyze):
        payload = Payload(
            filename="malware.bin",
            username="tester",
            filetype=".bin",
            datecreated="2026-10-05 19:43:59",
            filehash="malicious-endpoint-hash",
            filepath="/tmp/malware.bin",
        )

        with patch.object(main, "DB_PATH", self.db_path):
            response = main.receive_telemetry(payload)

        self.assertEqual(response["verdict"], "malicious")
        self.assertEqual(response["action"], "logged")
        mock_analyze.assert_called_once_with("malicious-endpoint-hash")

    def test_command_lifecycle_and_event_filepath(self):
        with patch.object(main, "DB_PATH", self.db_path):
            command = main.issue_command(
                main.CommandRequest(filepath="/tmp/suspicious.bin", action="quarantine"),
                {"id": 1},
            )
            pending = main.list_pending_commands()

        self.assertEqual(command["status"], "pending")
        self.assertEqual(command["action"], "quarantine")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["filepath"], "/tmp/suspicious.bin")

        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO file_events "
                "(filename, username, filetype, datecreated, filehash, filepath, device_name) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("suspicious.bin", "tester", ".bin", "today", "listed-hash", "/tmp/suspicious.bin", "SOC-WS-01"),
            )
            connection.execute(
                "INSERT INTO integrity_checks "
                "(filehash, virustotal_result, abuse_ch_result, verdict, checked_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("listed-hash", '{"available": true, "malicious": 3, "suspicious": 1, "stats": {"harmless": 10}}', '{"available": true, "malicious": false, "results": []}', "malicious", "today"),
            )

        with patch.object(main, "DB_PATH", self.db_path):
            events = main.list_events()
            history = main.list_command_history()

        self.assertEqual(events[0]["filepath"], "/tmp/suspicious.bin")
        self.assertEqual(events[0]["device_name"], "SOC-WS-01")
        self.assertEqual(events[0]["response_status"], "pending")
        self.assertEqual(json.loads(events[0]["virustotal_result"])["malicious"], 3)
        self.assertEqual(json.loads(events[0]["abuse_ch_result"])["available"], True)
        self.assertEqual(history[0]["status"], "pending")
        self.assertEqual(history[0]["verdict"], "malicious")
        self.assertEqual(history[0]["filename"], "suspicious.bin")

        with patch.object(main, "DB_PATH", self.db_path):
            completion = main.complete_command(command["id"])
            pending_after = main.list_pending_commands()
            events_after = main.list_events()
            history_after = main.list_command_history()

        self.assertEqual(completion["status"], "completed")
        self.assertEqual(pending_after, [])
        self.assertEqual(events_after[0]["response_status"], "completed")
        self.assertEqual(history_after[0]["status"], "completed")

    @patch(
        "Controllers.analyzeArtifact.check_virustotal",
        return_value={"available": True, "malicious": 2, "suspicious": 0, "stats": {"harmless": 6}},
    )
    @patch(
        "Controllers.analyzeArtifact.check_abuse_ch",
        return_value={"available": True, "malicious": False, "results": []},
    )
    def test_list_events_backfills_missing_cti_snapshot_once(self, mock_abuse, mock_vt):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO file_events "
                "(filename, username, filetype, datecreated, filehash, filepath, device_name) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("threat.bin", "analyst", ".bin", "today", "uncached-hash", "/tmp/threat.bin", "SOC-LAB-01"),
            )

        with patch.object(main, "DB_PATH", self.db_path):
            events = main.list_events()
            main.list_events()

        self.assertEqual(events[0]["verdict"], "malicious")
        self.assertEqual(json.loads(events[0]["virustotal_result"])["malicious"], 2)
        self.assertTrue(events[0]["abuse_ch_result"])
        mock_vt.assert_called_once_with("uncached-hash")
        mock_abuse.assert_called_once_with("uncached-hash")

    def test_endpoint_inventory_groups_device_file_events(self):
        heartbeat = EndpointHeartbeat(
            device_id="SOC-LAB-01@CORP",
            device_name="SOC-LAB-01",
            username="analyst",
            os_version="Linux test-kernel",
            domain_name="CORP",
        )
        with patch.object(main, "DB_PATH", self.db_path):
            main.endpoint_heartbeat(heartbeat)

        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO file_events "
                "(filename, username, filetype, datecreated, filehash, filepath, device_name, device_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("malware.bin", "analyst", ".bin", "2026-10-06", "device-hash-1", "/tmp/malware.bin", "SOC-LAB-01", "SOC-LAB-01@CORP"),
            )
            connection.execute(
                "INSERT INTO file_events "
                "(filename, username, filetype, datecreated, filehash, filepath, device_name, device_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("note.txt", "analyst", ".txt", "2026-10-06", "device-hash-2", "/tmp/note.txt", "SOC-LAB-01", "SOC-LAB-01@CORP"),
            )
            connection.execute(
                "INSERT INTO integrity_checks "
                "(filehash, virustotal_result, abuse_ch_result, verdict, checked_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("device-hash-1", '{}', '{}', "malicious", "today"),
            )

        with patch.object(main, "DB_PATH", self.db_path):
            endpoints = main.list_endpoints()

        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["device_name"], "SOC-LAB-01")
        self.assertEqual(endpoints[0]["domain_name"], "CORP")
        self.assertEqual(endpoints[0]["os_version"], "Linux test-kernel")
        self.assertEqual(endpoints[0]["event_count"], 2)
        self.assertEqual(endpoints[0]["malicious_count"], 1)

    def test_agent_heartbeat_registers_and_updates_agent(self):
        heartbeat = AgentHeartbeat(
            agent_id="agent-123",
            hostname="LAB-VM-01",
            ip_address="192.0.2.10",
            os_version="Linux test-kernel",
        )

        with patch.object(main, "DB_PATH", self.db_path):
            result = main.agent_heartbeat(heartbeat)
            agents = main.list_agents()

        self.assertEqual(result["status"], "online")
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["agent_id"], "agent-123")
        self.assertEqual(agents[0]["hostname"], "LAB-VM-01")
        self.assertEqual(agents[0]["ip_address"], "192.0.2.10")
        self.assertEqual(agents[0]["os_version"], "Linux test-kernel")
        self.assertEqual(agents[0]["status"], "online")
        self.assertEqual(agents[0]["last_seen"], result["last_seen"])

        updated_heartbeat = heartbeat.model_copy(update={"ip_address": "192.0.2.11"})
        with patch.object(main, "DB_PATH", self.db_path):
            main.agent_heartbeat(updated_heartbeat)
            agents = main.list_agents()

        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["ip_address"], "192.0.2.11")
        self.assertEqual(agents[0]["status"], "online")

    def test_list_agents_marks_stale_heartbeat_offline(self):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO agents
                    (agent_id, hostname, ip_address, os_version, status, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "stale-agent",
                    "LAB-VM-02",
                    "192.0.2.20",
                    "Linux test-kernel",
                    "online",
                    (datetime.now(timezone.utc) - timedelta(minutes=4)).isoformat(),
                ),
            )

        with patch.object(main, "DB_PATH", self.db_path):
            agents = main.list_agents()

        self.assertEqual(agents[0]["status"], "offline")
        with sqlite3.connect(self.db_path) as connection:
            status = connection.execute(
                "SELECT status FROM agents WHERE agent_id = ?",
                ("stale-agent",),
            ).fetchone()[0]
        self.assertEqual(status, "offline")

    @patch("main.analyzeArtifact.analyze", return_value="duplicate")
    def test_duplicate_telemetry_backfills_missing_filepath(self, mock_analyze):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO file_events "
                "(filename, username, filetype, datecreated, filehash, filepath, device_name, device_id) "
                "VALUES (?, ?, ?, ?, ?, '', '', '')",
                ("sample.bin", "tester", ".bin", "today", "legacy-hash"),
            )
        payload = Payload(
            filename="sample.bin",
            username="tester",
            filetype=".bin",
            datecreated="today",
            filehash="legacy-hash",
            filepath="/home/tester/Downloads/sample.bin",
            device_name="SOC-WS-02",
            device_id="SOC-WS-02@CORP",
        )

        with patch.object(main, "DB_PATH", self.db_path):
            response = main.receive_telemetry(payload)

        with sqlite3.connect(self.db_path) as connection:
            filepath = connection.execute(
                "SELECT filepath, device_name, device_id FROM file_events WHERE filehash = ?",
                ("legacy-hash",),
            ).fetchone()

        self.assertEqual(response["action"], "duplicate")
        self.assertEqual(filepath, ("/home/tester/Downloads/sample.bin", "SOC-WS-02", "SOC-WS-02@CORP"))
        mock_analyze.assert_called_once_with("legacy-hash")

    def test_analyst_password_and_session_lifecycle(self):
        create_analyst(
            self.db_path,
            "analyst@example.test",
            "correct horse battery staple",
            "Alex Analyst",
            "Northstar Security",
        )

        self.assertIsNone(authenticate_analyst(self.db_path, "analyst@example.test", "wrong password"))
        analyst = authenticate_analyst(self.db_path, "ANALYST@example.test", "correct horse battery staple")
        self.assertEqual(analyst["full_name"], "Alex Analyst")
        self.assertEqual(analyst["company_name"], "Northstar Security")

        token, _ = create_session(self.db_path, analyst["id"])
        self.assertEqual(get_session_analyst(self.db_path, token)["email"], "analyst@example.test")
        revoke_session(self.db_path, token)
        self.assertIsNone(get_session_analyst(self.db_path, token))

    def test_agent_token_is_required(self):
        with patch.object(main, "AGENT_TOKEN", "test-agent-token"):
            with self.assertRaises(main.HTTPException) as error:
                main.require_agent_token("incorrect-token")
            self.assertEqual(error.exception.status_code, 401)
            self.assertIsNone(main.require_agent_token("test-agent-token"))

    def test_agent_token_does_not_fall_back_to_process_environment(self):
        with patch.object(main, "AGENT_TOKEN", ""), patch.dict(
            os.environ,
            {"VECTORONE_AGENT_TOKEN": "environment-only-token"},
        ):
            with self.assertRaises(main.HTTPException) as error:
                main.require_agent_token("environment-only-token")

        self.assertEqual(error.exception.status_code, 503)

    def test_login_endpoint_issues_and_revokes_bearer_session(self):
        create_analyst(
            self.db_path,
            "analyst@example.test",
            "correct horse battery staple",
            "Alex Analyst",
            "Northstar Security",
        )

        with patch.object(main, "DB_PATH", self.db_path):
            login_result = main.login(
                AnalystLogin(email="analyst@example.test", password="correct horse battery staple")
            )
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials=login_result["access_token"],
            )
            analyst = main.get_current_analyst(credentials)
            logout_result = main.logout(credentials, analyst)

        self.assertEqual(login_result["token_type"], "bearer")
        self.assertEqual(analyst["full_name"], "Alex Analyst")
        self.assertEqual(analyst["company_name"], "Northstar Security")
        self.assertEqual(logout_result["status"], "signed_out")
        with patch.object(main, "DB_PATH", self.db_path):
            with self.assertRaises(main.HTTPException) as error:
                main.get_current_analyst(credentials)
        self.assertEqual(error.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
