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


if __name__ == "__main__":
    unittest.main()
