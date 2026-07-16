import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class OperatorWorkflowApiTest(unittest.TestCase):
    def test_operator_inbox_and_primary_action_are_available_through_one_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Slow response",
                "analysis",
                [CheckResult(source="json_api", name="Chat", status="warning", summary="Slow response")],
            )
            config = AppConfig(
                raw={
                    "app": {
                        "api_auth_required_for_reads": True,
                        "api_tokens": [{"name": "owner", "token": "operator-token", "role": "operator"}],
                    }
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            headers = {"Authorization": "Bearer operator-token"}
            try:
                inbox_request = urllib.request.Request(f"http://{host}:{port}/api/operator/inbox", headers=headers)
                with urllib.request.urlopen(inbox_request, timeout=5) as response:
                    inbox = json.loads(response.read().decode("utf-8"))

                guide_request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/operator-guide",
                    headers=headers,
                )
                with urllib.request.urlopen(guide_request, timeout=5) as response:
                    guide = json.loads(response.read().decode("utf-8"))

                action_request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/operator-action",
                    data=b'{"note":"one click"}',
                    method="POST",
                    headers={**headers, "Content-Type": "application/json"},
                )
                with urllib.request.urlopen(action_request, timeout=5) as response:
                    action = json.loads(response.read().decode("utf-8"))
                audits = storage.latest_api_audit_logs()
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(1, inbox["summary"]["total"])
        self.assertEqual("run_diagnosis", guide["primary_action"]["kind"])
        self.assertEqual("completed", action["status"])
        self.assertEqual("incident.operator_action", audits[0]["operation"])
        self.assertEqual("owner", audits[0]["actor"])

    def test_viewer_cannot_execute_operator_primary_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Slow response",
                "analysis",
                [CheckResult(source="json_api", name="Chat", status="warning", summary="Slow response")],
            )
            config = AppConfig(
                raw={
                    "app": {
                        "api_tokens": [{"name": "viewer", "token": "viewer-token", "role": "viewer"}],
                    }
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/operator-action",
                    data=b"{}",
                    method="POST",
                    headers={
                        "Authorization": "Bearer viewer-token",
                        "Content-Type": "application/json",
                    },
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=5)
                audits = storage.latest_api_audit_logs()
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(403, raised.exception.code)
        self.assertEqual("forbidden", audits[0]["outcome"])


if __name__ == "__main__":
    unittest.main()
