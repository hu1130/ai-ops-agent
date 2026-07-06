import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from ops_agent.ai.repair import build_ai_repair_proposal, dry_run_ai_repair_proposal, record_ai_repair_test_result
from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class AiRepairTest(unittest.TestCase):
    def test_rule_based_repair_proposal_tracks_dry_run_and_test_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={"ai": {"repair": {"provider": "rules", "model": "rule-based-repair-v1"}}},
                base_dir=Path(tmp),
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [
                    CheckResult(
                        source="http",
                        name="DuanShiping health",
                        status="critical",
                        summary="HTTP 404 from https://duanshiping.setdx.com/healthz",
                    )
                ],
                classification={"category": "route_or_healthcheck_config_mismatch", "confidence": 0.91},
            )
            storage.save_incident_diagnosis(
                incident_id,
                {
                    "context": {"environment": "prod", "run_type": "normal"},
                    "probable_causes": [
                        {"category": "route_or_healthcheck_config_mismatch", "confidence": 0.91}
                    ],
                    "next_decision": {"action": "review_monitor_target"},
                    "evidence": {"http_status": 404},
                },
            )

            proposal = build_ai_repair_proposal(storage, config, incident_id, request={"actor": "tester"})
            dry_run = dry_run_ai_repair_proposal(storage, proposal["id"], actor="tester")
            tested = record_ai_repair_test_result(
                storage,
                proposal["id"],
                result={"status": "passed", "output": "unit tests passed"},
                actor="tester",
            )
            rows = storage.latest_ai_repair_proposals(incident_id=incident_id)
            storage.close()

        self.assertEqual("proposed", proposal["status"])
        self.assertEqual("low", proposal["risk"])
        self.assertEqual("config_or_route_review", proposal["patch"]["patch_type"])
        self.assertEqual("dry_run_passed", dry_run["status"])
        self.assertTrue(dry_run["dry_run"]["valid"])
        self.assertFalse(dry_run["dry_run"]["mutates_files"])
        self.assertEqual("test_passed", tested["status"])
        self.assertEqual("passed", tested["test_result"]["status"])
        self.assertEqual([proposal["id"]], [row["id"] for row in rows])

    def test_ai_repair_dashboard_api_runs_proposal_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {"name": "ops"},
                    "ai": {"repair": {"provider": "rules", "model": "rule-based-repair-v1"}},
                },
                base_dir=Path(tmp),
            )
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue(s)",
                "analysis",
                [
                    CheckResult(
                        source="http",
                        name="DuanShiping health",
                        status="critical",
                        summary="HTTP 404 from https://duanshiping.setdx.com/healthz",
                    )
                ],
                classification={"category": "route_or_healthcheck_config_mismatch", "confidence": 0.91},
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                proposal = post_json(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ai-repair/propose",
                    {"actor": "tester"},
                )
                repair_id = proposal["id"]
                listed = get_json(f"http://{host}:{port}/api/ai-repairs?incident_id={incident_id}")
                dry_run = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{repair_id}/dry-run",
                    {"actor": "tester"},
                )
                tested = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{repair_id}/test",
                    {"actor": "tester", "status": "passed", "output": "ok"},
                )
                approved = post_json(
                    f"http://{host}:{port}/api/ai-repairs/{repair_id}/approve",
                    {"actor": "tester", "note": "reviewed"},
                )
                detail = get_json(f"http://{host}:{port}/api/ai-repairs/{repair_id}")
                audit = storage.latest_api_audit_logs(20)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(repair_id, listed[0]["id"])
        self.assertEqual("dry_run_passed", dry_run["status"])
        self.assertEqual("test_passed", tested["status"])
        self.assertEqual("approved", approved["status"])
        self.assertEqual("approved", detail["status"])
        self.assertIn("ai_repair.propose", {row["operation"] for row in audit})
        self.assertIn("ai_repair.dry_run", {row["operation"] for row in audit})
        self.assertIn("ai_repair.approve", {row["operation"] for row in audit})


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def get_json(url: str) -> dict | list:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
