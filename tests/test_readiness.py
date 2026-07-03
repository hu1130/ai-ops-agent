import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.dashboard import start_dashboard
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.remediation.readiness import evaluate_action_readiness, incident_self_heal_readiness
from ops_agent.storage import Storage


class ReadinessTest(unittest.TestCase):
    def test_mutating_action_with_evidence_is_ready_for_approval(self) -> None:
        config = restart_config()
        action = RemediationAction(
            action_type="restart_service",
            title="Restart ops-agent",
            reason="Service unavailable",
            risk="medium",
            params={"service": "ops-agent"},
        )
        readiness = evaluate_action_readiness(
            action,
            config,
            incident={"occurrence_count": 3},
            diagnosis=diagnosis_payload(confidence=0.91),
        )

        self.assertEqual("approval_required", readiness["status"])
        self.assertTrue(readiness["approval_ready"])
        self.assertFalse(readiness["auto_ready"])
        self.assertEqual([], readiness["blockers"])
        self.assertTrue(readiness["policy"]["verification_required"])

    def test_mutating_action_without_diagnosis_is_blocked(self) -> None:
        config = restart_config()
        action = RemediationAction(
            action_type="restart_service",
            title="Restart ops-agent",
            reason="Service unavailable",
            risk="medium",
            params={"service": "ops-agent"},
        )

        readiness = evaluate_action_readiness(action, config, incident={"occurrence_count": 3})

        self.assertEqual("blocked", readiness["status"])
        self.assertFalse(readiness["approval_ready"])
        self.assertTrue(any("diagnosis" in message for message in readiness["blockers"]))

    def test_incident_readiness_api_returns_recommendation_scores(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "critical",
                "Site down",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
                occurrence_count=3,
            )
            storage.save_incident_diagnosis(incident_id, diagnosis_payload(confidence=0.9))
            storage.save_incident_recommendations(
                incident_id,
                [
                    {
                        "position": 1,
                        "category": "diagnose",
                        "action_type": "check_port",
                        "title": "Check site port",
                        "reason": "Confirm connectivity",
                        "risk": "low",
                        "auto_execute": True,
                        "params": {"host": "example.com", "port": 443},
                    }
                ],
            )
            config = AppConfig(
                raw={
                    "remediation": {
                        "policies": [
                            {
                                "action_type": "check_port",
                                "targets": ["example.com:443"],
                                "enabled": True,
                                "auto_execute": True,
                                "requires_approval": False,
                            }
                        ]
                    }
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                direct = incident_self_heal_readiness(storage, config, incident_id)
                with urllib.request.urlopen(
                    f"http://{host}:{port}/api/incidents/{incident_id}/self-heal-readiness",
                    timeout=5,
                ) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(1, direct["auto_ready_count"])
        self.assertEqual(1, payload["recommendation_count"])
        self.assertEqual(1, payload["auto_ready_count"])
        self.assertEqual("auto_ready", payload["recommendations"][0]["readiness"]["status"])


def restart_config() -> AppConfig:
    return AppConfig(
        raw={
            "remediation": {
                "guardrails": {
                    "min_diagnosis_confidence_for_mutating": 0.8,
                    "min_occurrences_for_mutating": 2,
                    "diagnosis_required_for_mutating": True,
                    "verification_required_for_mutating": True,
                },
                "policies": [
                    {
                        "name": "ops-agent restart",
                        "action_type": "restart_service",
                        "targets": ["ops-agent"],
                        "enabled": True,
                        "auto_execute": False,
                        "requires_approval": True,
                        "verification_required": True,
                        "verify_after": {
                            "type": "http",
                            "url": "http://127.0.0.1:8765/api/summary",
                            "expected_status": 200,
                        },
                    }
                ],
            }
        },
        base_dir=Path("."),
    )


def diagnosis_payload(confidence: float = 0.9) -> dict:
    return {
        "context": {"environment": "prod", "run_type": "normal", "trace_id": "trace-readiness"},
        "probable_causes": [
            {
                "category": "service_unavailable",
                "confidence": confidence,
                "evidence": ["http/Site: HTTP 500"],
            }
        ],
        "next_decision": {
            "action": "collect_targeted_evidence",
            "safe_to_auto_remediate": True,
            "requires_human_confirmation": True,
        },
        "evidence": {},
    }


if __name__ == "__main__":
    unittest.main()
