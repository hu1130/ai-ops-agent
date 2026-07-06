import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.diagnosis import persist_incident_diagnosis
from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class ChangeEventsTest(unittest.TestCase):
    def test_change_event_is_saved_and_correlated_with_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            change = storage.save_change_event(
                {
                    "environment": "prod",
                    "run_type": "normal",
                    "project_id": "site",
                    "source": "deploy",
                    "change_type": "deployment",
                    "title": "Deploy site release",
                    "summary": "Released new routing code.",
                    "actor": "tester",
                    "commit_sha": "abc123",
                }
            )
            incident_id = storage.save_incident(
                "critical",
                "Site HTTP 500",
                "analysis",
                [
                    CheckResult(
                        source="http",
                        name="Site",
                        status="critical",
                        summary="HTTP 500 from site",
                        environment="prod",
                        run_type="normal",
                    )
                ],
            )
            incident = storage.get_incident(incident_id) or {}
            correlation = storage.correlate_incident_changes(incident)
            storage.close()

        self.assertEqual("abc123", change["commit_sha"])
        self.assertEqual(1, correlation["related_count"])
        self.assertEqual(change["id"], correlation["related_changes"][0]["id"])
        self.assertIn("project_matches_incident_signal", correlation["related_changes"][0]["correlation_reasons"])

    def test_diagnosis_payload_includes_recent_change_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            storage.save_change_event(
                {
                    "environment": "prod",
                    "run_type": "normal",
                    "source": "config_center",
                    "change_type": "config",
                    "title": "Change API timeout",
                    "summary": "Timeout setting changed before the incident.",
                    "actor": "tester",
                }
            )
            incident_id = storage.save_incident(
                "warning",
                "API slow",
                "analysis",
                [
                    CheckResult(
                        source="json_api",
                        name="API",
                        status="warning",
                        summary="Slow response: 9000 ms",
                        environment="prod",
                        run_type="normal",
                    )
                ],
            )
            diagnosis = persist_incident_diagnosis(storage, None, incident_id)
            records = storage.latest_incident_diagnoses(incident_id)
            storage.close()

        self.assertEqual(1, diagnosis["change_correlation"]["related_count"])
        self.assertEqual(
            "Change API timeout",
            diagnosis["evidence"]["recent_changes"]["related_changes"][0]["title"],
        )
        self.assertEqual(1, records[0]["payload"]["change_correlation"]["related_count"])

    def test_change_events_dashboard_api_creates_and_lists_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(raw={"app": {"environment": "prod", "run_type": "normal"}}, base_dir=Path(tmp))
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                created = post_json(
                    f"http://{host}:{port}/api/change-events",
                    {
                        "title": "Manual config change",
                        "source": "operator",
                        "change_type": "config",
                        "project_id": "ops-agent",
                        "actor": "tester",
                    },
                )
                with urllib.request.urlopen(
                    f"http://{host}:{port}/api/change-events?project_id=ops-agent",
                    timeout=5,
                ) as response:
                    listed = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertGreater(created["id"], 0)
        self.assertEqual(1, len(listed))
        self.assertEqual(created["id"], listed[0]["id"])
        self.assertEqual("tester", listed[0]["actor"])


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
