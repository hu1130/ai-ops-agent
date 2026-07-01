from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path

from ops_agent.retention import run_retention_cleanup
from ops_agent.storage import Storage


class RetentionTest(unittest.TestCase):
    def test_retention_dry_run_counts_without_deleting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            insert_check(storage, "ok", days_ago=40)
            result = run_retention_cleanup(storage, {"enabled": True, "check_results_days": 30}, dry_run=True)
            rows = storage.latest_results(10)
            storage.close()

        self.assertEqual(1, result.deleted_check_results)
        self.assertEqual(1, len(rows))

    def test_retention_deletes_old_ok_but_keeps_recent_and_problem_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            insert_check(storage, "ok", days_ago=40)
            insert_check(storage, "ok", days_ago=5)
            insert_check(storage, "warning", days_ago=40)
            result = run_retention_cleanup(
                storage,
                {"enabled": True, "check_results_days": 30, "problem_results_days": 90},
                dry_run=False,
            )
            rows = storage.latest_results(10)
            storage.close()

        self.assertEqual(1, result.deleted_check_results)
        self.assertEqual(2, len(rows))
        self.assertEqual({"ok", "warning"}, {row["status"] for row in rows})

    def test_problem_results_are_not_kept_shorter_than_ok_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            insert_check(storage, "warning", days_ago=40)
            result = run_retention_cleanup(
                storage,
                {"enabled": True, "check_results_days": 90, "problem_results_days": 30},
                dry_run=False,
            )
            rows = storage.latest_results(10)
            storage.close()

        self.assertEqual(0, result.deleted_check_results)
        self.assertEqual(1, len(rows))

    def test_test_results_use_shorter_retention_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            insert_check(storage, "warning", days_ago=8, environment="test", run_type="manual_test")
            insert_check(storage, "warning", days_ago=8, environment="prod", run_type="normal")
            result = run_retention_cleanup(
                storage,
                {
                    "enabled": True,
                    "check_results_days": 30,
                    "problem_results_days": 90,
                    "test_results_days": 7,
                    "test_environments": ["test"],
                    "test_run_types": ["manual_test"],
                },
                dry_run=False,
            )
            rows = storage.latest_results(10)
            storage.close()

        self.assertEqual(1, result.deleted_check_results)
        self.assertEqual(1, len(rows))
        self.assertEqual("prod", rows[0]["environment"])

    def test_retention_deletes_old_incidents_and_action_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            old = iso_days_ago(120)
            storage.connection.execute(
                """
                insert into incidents (created_at, severity, title, analysis, results_json)
                values (?, 'warning', 'old', 'old', '[]')
                """,
                (old,),
            )
            incident_id = storage.connection.execute("select id from incidents").fetchone()[0]
            storage.connection.execute(
                """
                insert into incident_events (incident_id, created_at, from_status, to_status, actor, note, metadata_json)
                values (?, ?, '', 'open', 'system', 'created', '{}')
                """,
                (incident_id, old),
            )
            storage.connection.execute(
                """
                insert into action_logs (created_at, action_type, title, risk, status, reason, params_json, output, error)
                values (?, 'check_port', 'old', 'low', 'executed', 'old', '{}', '', '')
                """,
                (old,),
            )
            storage.connection.commit()
            result = run_retention_cleanup(
                storage,
                {"enabled": True, "incidents_days": 90, "action_logs_days": 90},
                dry_run=False,
            )
            incidents = storage.latest_incidents()
            actions = storage.latest_action_logs()
            incident_events = storage.latest_incident_events(incident_id)
            storage.close()

        self.assertEqual(1, result.deleted_incidents)
        self.assertEqual(1, result.deleted_action_logs)
        self.assertEqual([], incidents)
        self.assertEqual([], actions)
        self.assertEqual([], incident_events)

    def test_test_incidents_and_actions_use_shorter_retention_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            old = iso_days_ago(8)
            storage.connection.execute(
                """
                insert into incidents (created_at, environment, run_type, trace_id, severity, title, analysis, results_json)
                values (?, 'test', 'manual_test', 'trace-a', 'warning', 'old', 'old', '[]')
                """,
                (old,),
            )
            storage.connection.execute(
                """
                insert into action_logs (
                    created_at, environment, run_type, trace_id, action_type, title, risk, status, reason, params_json, output, error
                )
                values (?, 'test', 'manual_test', 'trace-a', 'check_port', 'old', 'low', 'executed', 'old', '{}', '', '')
                """,
                (old,),
            )
            storage.connection.commit()
            result = run_retention_cleanup(
                storage,
                {
                    "enabled": True,
                    "incidents_days": 90,
                    "action_logs_days": 90,
                    "test_incidents_days": 7,
                    "test_action_logs_days": 7,
                    "test_environments": ["test"],
                    "test_run_types": ["manual_test"],
                },
                dry_run=False,
            )
            incidents = storage.latest_incidents()
            actions = storage.latest_action_logs()
            storage.close()

        self.assertEqual(1, result.deleted_incidents)
        self.assertEqual(1, result.deleted_action_logs)
        self.assertEqual([], incidents)
        self.assertEqual([], actions)

    def test_retention_deletes_old_api_audit_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            old = iso_days_ago(200)
            recent = iso_days_ago(10)
            storage.connection.execute(
                """
                insert into api_audit_logs (
                    created_at, environment, run_type, actor, source_ip, method, path,
                    operation, target_type, target_id, status_code, outcome, message, metadata_json
                )
                values (?, 'prod', 'api', 'owner', '127.0.0.1', 'POST', '/api/incidents/1/ack',
                        'incident.ack', 'incident', 1, 200, 'success', 'old', '{}')
                """,
                (old,),
            )
            storage.connection.execute(
                """
                insert into api_audit_logs (
                    created_at, environment, run_type, actor, source_ip, method, path,
                    operation, target_type, target_id, status_code, outcome, message, metadata_json
                )
                values (?, 'prod', 'api', 'owner', '127.0.0.1', 'POST', '/api/incidents/1/ack',
                        'incident.ack', 'incident', 1, 200, 'success', 'recent', '{}')
                """,
                (recent,),
            )
            storage.connection.commit()
            result = run_retention_cleanup(
                storage,
                {"enabled": True, "api_audit_logs_days": 180},
                dry_run=False,
            )
            rows = storage.latest_api_audit_logs()
            storage.close()

        self.assertEqual(1, result.deleted_api_audit_logs)
        self.assertEqual(1, len(rows))
        self.assertEqual("recent", rows[0]["message"])


def insert_check(
    storage: Storage,
    status: str,
    days_ago: int,
    environment: str = "prod",
    run_type: str = "normal",
) -> None:
    storage.connection.execute(
        """
        insert into check_results (created_at, environment, run_type, trace_id, source, name, status, summary, details_json)
        values (?, ?, ?, 'trace-a', 'http', 'site', ?, 'summary', '{}')
        """,
        (iso_days_ago(days_ago), environment, run_type, status),
    )
    storage.connection.commit()


def iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


if __name__ == "__main__":
    unittest.main()
