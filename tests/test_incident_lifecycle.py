import tempfile
import unittest
from pathlib import Path

from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class IncidentLifecycleTest(unittest.TestCase):
    def test_save_incident_creates_open_status_and_initial_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Ops Agent detected 1 issue",
                "analysis",
                [CheckResult(source="http", name="Site", status="warning", summary="Slow")],
            )
            incident = storage.get_incident(incident_id)
            events = storage.latest_incident_events(incident_id)
            storage.close()

        self.assertEqual("open", incident["status"])
        self.assertEqual(1, len(events))
        self.assertEqual("", events[0]["from_status"])
        self.assertEqual("open", events[0]["to_status"])

    def test_incident_transitions_are_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 1 issue",
                "analysis",
                [CheckResult(source="json_api", name="Chat", status="critical", summary="Failed")],
            )
            storage.transition_incident(incident_id, "acknowledged", actor="alice", note="checking")
            storage.transition_incident(incident_id, "resolved", actor="alice", note="fixed")
            incident = storage.get_incident(incident_id)
            events = storage.latest_incident_events(incident_id)
            storage.close()

        self.assertEqual("resolved", incident["status"])
        self.assertEqual("alice", incident["acknowledged_by"])
        self.assertIsNotNone(incident["resolved_at"])
        self.assertEqual(["open", "acknowledged", "resolved"], [event["to_status"] for event in events])

    def test_closed_incident_cannot_be_reopened(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Ops Agent detected 1 issue",
                "analysis",
                [CheckResult(source="http", name="Site", status="warning", summary="Slow")],
            )
            storage.transition_incident(incident_id, "closed", actor="alice", note="not actionable")
            with self.assertRaises(ValueError):
                storage.transition_incident(incident_id, "open", actor="alice")
            storage.close()

    def test_action_logs_can_be_linked_to_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Ops Agent detected 1 issue",
                "analysis",
                [CheckResult(source="http", name="Site", status="warning", summary="Slow")],
            )
            storage.save_action_log(
                "check_port",
                "Check port",
                "low",
                "dry_run",
                "diagnose",
                {"host": "example.com", "port": 443},
                incident_id=incident_id,
            )
            linked = storage.latest_action_logs(10, incident_id=incident_id)
            unlinked = storage.latest_action_logs(10, incident_id=999)
            storage.close()

        self.assertEqual(1, len(linked))
        self.assertEqual(incident_id, linked[0]["incident_id"])
        self.assertEqual([], unlinked)

    def test_incident_assignment_priority_comments_and_false_positive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Ops Agent detected 1 issue",
                "analysis",
                [CheckResult(source="http", name="Site", status="warning", summary="Slow")],
            )
            assigned = storage.assign_incident(incident_id, "alice", actor="lead")
            prioritized = storage.set_incident_priority(incident_id, "high", actor="lead")
            comment = storage.add_incident_comment(incident_id, "alice", "checking nginx logs")
            false_positive = storage.mark_incident_false_positive(incident_id, actor="alice", reason="probe config issue")
            detail = storage.incident_detail(incident_id)
            filtered = storage.latest_incidents(10, assignee="alice", priority="high", false_positive=True)
            storage.close()

        self.assertEqual("alice", assigned["assignee"])
        self.assertEqual("high", prioritized["priority"])
        self.assertEqual("checking nginx logs", comment["comment"])
        self.assertEqual("closed", false_positive["status"])
        self.assertEqual(1, false_positive["false_positive"])
        self.assertEqual("probe config issue", false_positive["false_positive_reason"])
        self.assertEqual(1, len(detail["comments"]))
        self.assertEqual(1, detail["summary"]["comment_count"])
        self.assertEqual([incident_id], [row["id"] for row in filtered])

    def test_incident_fingerprint_tracks_occurrences(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="http", name="Site", status="warning", summary="Slow")
            incident_id = storage.save_incident(
                "warning",
                "Ops Agent detected 1 issue",
                "analysis",
                [result],
                fingerprint="prod:normal:http:Site",
            )
            active = storage.find_active_incident_by_fingerprint("prod:normal:http:Site")
            updated = storage.update_incident_occurrence(
                incident_id,
                "critical",
                "Ops Agent detected 1 issue",
                [CheckResult(source="http", name="Site", status="critical", summary="Failed")],
            )
            storage.transition_incident(incident_id, "resolved", actor="test")
            resolved_lookup = storage.find_active_incident_by_fingerprint("prod:normal:http:Site")
            storage.close()

        self.assertEqual(incident_id, active["id"])
        self.assertEqual(2, updated["occurrence_count"])
        self.assertEqual("critical", updated["severity"])
        self.assertIn("http/Site", updated["last_summary"])
        self.assertIsNone(resolved_lookup)

    def test_incident_classification_is_saved_updated_and_summarized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Ops Agent detected 1 issue",
                "analysis",
                [CheckResult(source="json_api", name="Chat", status="warning", summary="Slow response")],
                classification={
                    "category": "performance_degraded",
                    "confidence": 0.78,
                    "summary": "slow synthetic response",
                    "evidence": ["json_api/Chat slow"],
                    "next_steps": ["check upstream latency"],
                },
            )
            incident = storage.get_incident(incident_id)
            updated = storage.update_incident_occurrence(
                incident_id,
                "critical",
                "Ops Agent detected 1 issue",
                [CheckResult(source="json_api", name="Chat", status="critical", summary="HTTP 500")],
                classification={
                    "category": "dependency_failure",
                    "confidence": 0.82,
                    "summary": "upstream failure",
                    "evidence": ["json_api/Chat HTTP 500"],
                    "next_steps": ["check dependency logs"],
                },
            )
            summary = storage.classification_summary()
            storage.close()

        self.assertEqual("performance_degraded", incident["classification_category"])
        self.assertEqual(0.78, incident["classification_confidence"])
        self.assertIn("json_api/Chat slow", incident["classification_evidence_json"])
        self.assertEqual("dependency_failure", updated["classification_category"])
        self.assertEqual(1, summary["total_incidents"])
        self.assertEqual(1, summary["classified_count"])
        self.assertEqual("dependency_failure", summary["by_category"][0]["category"])
        self.assertEqual(2, summary["by_category"][0]["occurrence_count"])

    def test_active_incidents_can_be_matched_by_fingerprint_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            site = CheckResult(source="http", name="Site", status="critical", summary="Down")
            chat = CheckResult(source="json_api", name="Chat", status="warning", summary="Slow")
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 2 issues",
                "analysis",
                [site, chat],
                fingerprint="prod:normal:http:Site|json_api:Chat",
            )
            site_matches = storage.find_active_incidents_for_check("prod", "normal", "http:Site")
            partial_recoveries = storage.find_recoverable_active_incidents("prod", "normal", ["http:Site"])
            full_recoveries = storage.find_recoverable_active_incidents(
                "prod",
                "normal",
                ["http:Site", "json_api:Chat"],
            )
            storage.transition_incident(incident_id, "resolved", actor="test")
            resolved_matches = storage.find_active_incidents_for_check("prod", "normal", "http:Site")
            storage.close()

        self.assertEqual([incident_id], [row["id"] for row in site_matches])
        self.assertEqual([], partial_recoveries)
        self.assertEqual([incident_id], [row["id"] for row in full_recoveries])
        self.assertEqual([], resolved_matches)


if __name__ == "__main__":
    unittest.main()
