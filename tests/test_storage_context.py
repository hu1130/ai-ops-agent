import sqlite3
import tempfile
import unittest
from pathlib import Path

from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class StorageContextTest(unittest.TestCase):
    def test_save_results_persists_context_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            storage.save_results(
                [
                    CheckResult(
                        source="http",
                        name="Site",
                        status="ok",
                        summary="HTTP 200",
                        environment="staging",
                        run_type="synthetic_test",
                        trace_id="trace-1",
                    )
                ]
            )
            rows = storage.latest_results()
            storage.close()

        self.assertEqual("staging", rows[0]["environment"])
        self.assertEqual("synthetic_test", rows[0]["run_type"])
        self.assertEqual("trace-1", rows[0]["trace_id"])

    def test_existing_database_is_migrated_with_context_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "ops.db"
            connection = sqlite3.connect(db_path)
            connection.executescript(
                """
                create table check_results (
                    id integer primary key autoincrement,
                    created_at text not null,
                    source text not null,
                    name text not null,
                    status text not null,
                    summary text not null,
                    details_json text not null
                );
                create table incidents (
                    id integer primary key autoincrement,
                    created_at text not null,
                    severity text not null,
                    title text not null,
                    analysis text not null,
                    results_json text not null
                );
                insert into incidents (created_at, severity, title, analysis, results_json)
                values ('2026-01-01T00:00:00+00:00', 'ok', 'recovered', 'ok', '[]');
                create table action_logs (
                    id integer primary key autoincrement,
                    created_at text not null,
                    action_type text not null,
                    title text not null,
                    risk text not null,
                    status text not null,
                    reason text not null,
                    params_json text not null,
                    output text not null,
                    error text not null
                );
                """
            )
            connection.close()

            storage = Storage(db_path)
            storage.save_results([CheckResult(source="http", name="Site", status="ok", summary="HTTP 200")])
            rows = storage.latest_results()
            recovered_incident = storage.latest_incidents(1)[0]
            action_columns = [
                row["name"]
                for row in storage.connection.execute("pragma table_info(action_logs)").fetchall()
            ]
            incident_columns = [
                row["name"]
                for row in storage.connection.execute("pragma table_info(incidents)").fetchall()
            ]
            incident_events_exists = storage.connection.execute(
                "select name from sqlite_master where type = 'table' and name = 'incident_events'"
            ).fetchone()
            audit_logs_exists = storage.connection.execute(
                "select name from sqlite_master where type = 'table' and name = 'api_audit_logs'"
            ).fetchone()
            learning_recommendations_exists = storage.connection.execute(
                "select name from sqlite_master where type = 'table' and name = 'learning_recommendations'"
            ).fetchone()
            learning_config_patches_exists = storage.connection.execute(
                "select name from sqlite_master where type = 'table' and name = 'learning_config_patches'"
            ).fetchone()
            learning_columns = [
                row["name"]
                for row in storage.connection.execute("pragma table_info(learning_recommendations)").fetchall()
            ]
            storage.close()

        self.assertEqual("prod", rows[0]["environment"])
        self.assertEqual("normal", rows[0]["run_type"])
        self.assertIn("trace_id", rows[0])
        self.assertIn("incident_id", action_columns)
        self.assertIn("classification_category", incident_columns)
        self.assertEqual("", recovered_incident["classification_category"])
        self.assertEqual("resolved", recovered_incident["status"])
        self.assertIsNotNone(incident_events_exists)
        self.assertIsNotNone(audit_logs_exists)
        self.assertIsNotNone(learning_recommendations_exists)
        self.assertIsNotNone(learning_config_patches_exists)
        self.assertIn("decision_by", learning_columns)
        self.assertIn("draft_json", learning_columns)


if __name__ == "__main__":
    unittest.main()
