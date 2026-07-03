import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.diagnosis import build_incident_diagnosis
from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class DiagnosisTest(unittest.TestCase):
    def test_incident_diagnosis_identifies_healthcheck_config_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(
                source="http",
                name="DuanShiping health",
                status="critical",
                summary="HTTP 404 from https://duanshiping.setdx.com/healthz",
                environment="prod",
                run_type="normal",
            )
            storage.save_incident("warning", "Previous health issue", "analysis", [result])
            incident_id = storage.save_incident("critical", "Health check 404", "analysis", [result])
            diagnosis = build_incident_diagnosis(storage, None, incident_id)
            storage.close()

        self.assertEqual("route_or_healthcheck_config_mismatch", diagnosis["probable_causes"][0]["category"])
        self.assertEqual("collect_targeted_evidence", diagnosis["next_decision"]["action"])
        self.assertEqual(1, len(diagnosis["related_incidents"]))

    def test_incident_diagnosis_api_returns_structured_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(
                source="server",
                name="Disk",
                status="critical",
                summary="Disk usage high",
                environment="prod",
                run_type="normal",
            )
            incident_id = storage.save_incident("critical", "Disk high", "analysis", [result])
            config = AppConfig(raw={"app": {"environment": "prod", "run_type": "normal"}}, base_dir=Path(tmp))
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                with urllib.request.urlopen(
                    f"http://{host}:{port}/api/incidents/{incident_id}/diagnosis",
                    timeout=5,
                ) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("Disk high", payload["incident"]["title"])
        self.assertEqual("resource_saturation", payload["probable_causes"][0]["category"])
        self.assertTrue(payload["collection_plan"])


if __name__ == "__main__":
    unittest.main()
