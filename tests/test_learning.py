import tempfile
import unittest
from pathlib import Path

from ops_agent.ai.learning import build_learning_recommendations
from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.scheduler import OpsScheduler
from ops_agent.storage import Storage


class LearningOptimizationTest(unittest.TestCase):
    def test_generator_flags_unknown_low_confidence_and_frequent_unresolved(self) -> None:
        incidents = [
            {
                "id": 1,
                "status": "open",
                "severity": "critical",
                "title": "Unknown issue",
                "classification_category": "unknown",
                "classification_confidence": 0.4,
                "occurrence_count": 1,
                "last_summary": "unknown signal",
                "environment": "prod",
                "run_type": "normal",
            },
            {
                "id": 2,
                "status": "resolved",
                "severity": "warning",
                "title": "Slow API",
                "classification_category": "performance_degraded",
                "classification_confidence": 0.52,
                "occurrence_count": 2,
                "last_summary": "slow response",
                "environment": "prod",
                "run_type": "normal",
            },
            {
                "id": 3,
                "status": "open",
                "severity": "critical",
                "title": "Site down",
                "classification_category": "service_unavailable",
                "classification_confidence": 0.86,
                "occurrence_count": 12,
                "fingerprint": "prod:normal:http:Site",
                "last_summary": "HTTP 500",
                "environment": "prod",
                "run_type": "normal",
            },
        ]

        recommendations = build_learning_recommendations(incidents, {"frequent_occurrence_threshold": 10})
        trigger_types = {item["trigger_type"] for item in recommendations}

        self.assertIn("unknown_classification", trigger_types)
        self.assertIn("low_confidence", trigger_types)
        self.assertIn("frequent_unresolved", trigger_types)
        self.assertTrue(all(item["dedupe_key"] for item in recommendations))

    def test_storage_saves_learning_recommendations_with_dedupe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            payload = {
                "dedupe_key": "low_confidence:performance_degraded:prod:normal",
                "priority": "medium",
                "category": "performance_degraded",
                "trigger_type": "low_confidence",
                "title": "Improve classifier confidence",
                "reason": "low confidence",
                "recommended_action": "add rules",
                "evidence": ["incident #1"],
                "incident_ids": [1],
                "metrics": {"avg_confidence": 0.52},
            }
            first = storage.save_learning_recommendations([payload])[0]
            second = storage.save_learning_recommendations([payload])[0]
            rows = storage.latest_learning_recommendations()
            summary = storage.learning_summary()
            storage.close()

        self.assertEqual(first["id"], second["id"])
        self.assertEqual(1, len(rows))
        self.assertEqual(2, rows[0]["seen_count"])
        self.assertEqual(["incident #1"], rows[0]["evidence"])
        self.assertEqual([1], rows[0]["incident_ids"])
        self.assertEqual(1, summary["open_count"])

    def test_storage_tracks_learning_review_decision_and_draft(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            payload = {
                "dedupe_key": "unknown:prod:normal",
                "priority": "high",
                "category": "unknown",
                "trigger_type": "unknown_classification",
                "title": "Review unknown signals",
                "reason": "unknown incidents exist",
                "recommended_action": "add classifier rules",
                "evidence": ["incident #1: summary=mystery outage"],
                "incident_ids": [1],
                "metrics": {"incident_count": 1},
            }
            row = storage.save_learning_recommendations([payload])[0]
            updated = storage.update_learning_recommendation_status(
                row["id"],
                "accepted",
                actor="tester",
                note="valid signal",
                draft={"draft_type": "classifier_rule", "status": "draft"},
            )
            repeated = storage.save_learning_recommendations([payload])[0]
            storage.close()

        self.assertEqual("accepted", updated["status"])
        self.assertEqual("tester", updated["decision_by"])
        self.assertEqual("valid signal", updated["decision_note"])
        self.assertEqual("classifier_rule", updated["draft"]["draft_type"])
        self.assertEqual("accepted", repeated["status"])
        self.assertEqual(2, repeated["seen_count"])

    def test_scheduler_generates_learning_recommendations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "learning": {
                        "enabled": True,
                        "lookback_hours": 72,
                        "interval_seconds": 3600,
                        "min_unknown_count": 1,
                    }
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue",
                "analysis",
                [CheckResult(source="manual", name="Unknown", status="critical", summary="mystery")],
                classification={
                    "category": "unknown",
                    "confidence": 0.4,
                    "summary": "unknown signal",
                    "evidence": ["manual/Unknown"],
                    "next_steps": ["review"],
                },
            )
            scheduler = OpsScheduler(config, storage, Notifier())
            saved = scheduler.run_learning_optimization_if_due(force=True)
            rows = storage.latest_learning_recommendations()
            storage.close()

        self.assertTrue(saved)
        self.assertEqual("unknown_classification", rows[0]["trigger_type"])


if __name__ == "__main__":
    unittest.main()
