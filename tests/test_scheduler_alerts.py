import tempfile
import unittest
import json
from pathlib import Path

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.scheduler import OpsScheduler, build_daily_report, build_recovery_message
from ops_agent.storage import Storage


class RecordingNotifier(Notifier):
    def __init__(self) -> None:
        super().__init__(cooldown_seconds=0)
        self.sent: list[tuple[str, str, str]] = []

    def send(self, title: str, text: str, dedupe_key: str = "default") -> bool:
        self.sent.append((title, text, dedupe_key))
        return True


class SchedulerAlertsTest(unittest.TestCase):
    def test_recovery_message_lists_recovered_checks(self) -> None:
        message = build_recovery_message([CheckResult(source="http", name="Site", status="ok", summary="HTTP 200")])
        self.assertIn("恢复正常", message)
        self.assertIn("http/Site", message)

    def test_daily_report_counts_statuses(self) -> None:
        rows = [
            {"source": "http", "name": "Site", "status": "ok", "summary": "HTTP 200"},
            {"source": "json", "name": "Chat", "status": "warning", "summary": "Slow"},
        ]
        report = build_daily_report(rows)
        self.assertIn("过去 24 小时巡检记录: 2 条", report)
        self.assertIn("警告: 1 条", report)

    def test_alert_creates_remediation_action_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1},
                    "app": {"environment": "staging", "run_type": "synthetic_test"},
                    "ai": {"enabled": False},
                    "remediation": {
                        "enabled": True,
                        "mode": "suggest",
                        "actions": {"check_port": {"auto_execute": True}},
                    },
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            scheduler = OpsScheduler(config, storage, Notifier())
            scheduler.process_alert_states(
                [
                    CheckResult(
                        source="http",
                        name="Site",
                        status="critical",
                        summary="Request failed",
                        details={"url": "https://example.com"},
                        environment="staging",
                        run_type="synthetic_test",
                        trace_id="trace-1",
                    )
                ]
            )
            rows = storage.latest_action_logs()
            storage.close()
        self.assertTrue(any(row["action_type"] == "check_port" for row in rows))
        self.assertTrue(any(row["environment"] == "staging" for row in rows))
        self.assertTrue(any(row["run_type"] == "synthetic_test" for row in rows))
        self.assertTrue(any(row["trace_id"] == "trace-1" for row in rows))
        self.assertTrue(all(row["incident_id"] for row in rows))

    def test_recovery_resolves_open_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1, "recovery_enabled": True},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            scheduler = OpsScheduler(config, storage, Notifier())
            scheduler.process_alert_states(
                [CheckResult(source="http", name="Site", status="critical", summary="Request failed")]
            )
            open_incident = storage.latest_incidents(1)[0]
            scheduler.process_alert_states(
                [CheckResult(source="http", name="Site", status="ok", summary="HTTP 200")]
            )
            resolved = storage.get_incident(open_incident["id"])
            events = storage.latest_incident_events(open_incident["id"])
            storage.close()

        self.assertEqual("resolved", resolved["status"])
        self.assertIn("resolved", [event["to_status"] for event in events])

    def test_repeated_problem_updates_existing_incident_without_new_alert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1, "recovery_enabled": True},
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            problem = CheckResult(source="http", name="Site", status="critical", summary="Request failed")
            scheduler.process_alert_states([problem])
            scheduler.process_alert_states([problem])
            incidents = storage.latest_incidents(10)
            storage.close()

        self.assertEqual(1, len(incidents))
        self.assertEqual(2, incidents[0]["occurrence_count"])
        self.assertEqual(1, len(notifier.sent))

    def test_existing_open_incident_is_merged_after_scheduler_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1, "recovery_enabled": True},
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            first_notifier = RecordingNotifier()
            first_scheduler = OpsScheduler(config, storage, first_notifier)
            problem = CheckResult(source="http", name="Site", status="critical", summary="Request failed")
            first_scheduler.process_alert_states([problem])

            restarted_notifier = RecordingNotifier()
            restarted_scheduler = OpsScheduler(config, storage, restarted_notifier)
            restarted_scheduler.process_alert_states([problem])
            incidents = storage.latest_incidents(10)
            storage.close()

        self.assertEqual(1, len(incidents))
        self.assertEqual(2, incidents[0]["occurrence_count"])
        self.assertEqual(1, len(first_notifier.sent))
        self.assertEqual(0, len(restarted_notifier.sent))

    def test_healthy_check_resolves_existing_open_incident_after_scheduler_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1, "recovery_enabled": True},
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            first_scheduler = OpsScheduler(config, storage, RecordingNotifier())
            first_scheduler.process_alert_states(
                [CheckResult(source="http", name="Site", status="critical", summary="Request failed")]
            )
            open_incident = storage.latest_incidents(1)[0]

            restarted_notifier = RecordingNotifier()
            restarted_scheduler = OpsScheduler(config, storage, restarted_notifier)
            restarted_scheduler.process_alert_states(
                [CheckResult(source="http", name="Site", status="ok", summary="HTTP 200")]
            )
            resolved = storage.get_incident(open_incident["id"])
            events = storage.latest_incident_events(open_incident["id"])
            storage.close()

        self.assertEqual("resolved", resolved["status"])
        self.assertIn("resolved", [event["to_status"] for event in events])
        self.assertEqual(1, len(restarted_notifier.sent))
        self.assertEqual("Ops Agent recovered 1 issue(s)", restarted_notifier.sent[0][0])

    def test_multi_target_incident_requires_all_targets_healthy_before_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1, "recovery_enabled": True},
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            incident_id = storage.save_incident(
                "critical",
                "Ops Agent detected 2 issue(s)",
                "analysis",
                [
                    CheckResult(source="http", name="Site", status="critical", summary="Request failed"),
                    CheckResult(source="json_api", name="Chat", status="warning", summary="Slow response"),
                ],
                fingerprint="prod:normal:http:Site|json_api:Chat",
            )

            scheduler.process_alert_states(
                [CheckResult(source="http", name="Site", status="ok", summary="HTTP 200")]
            )
            still_open = storage.get_incident(incident_id)

            scheduler.process_alert_states(
                [
                    CheckResult(source="http", name="Site", status="ok", summary="HTTP 200"),
                    CheckResult(source="json_api", name="Chat", status="ok", summary="Fast response"),
                ]
            )
            resolved = storage.get_incident(incident_id)
            events = storage.latest_incident_events(incident_id)
            storage.close()

        self.assertEqual("open", still_open["status"])
        self.assertEqual("resolved", resolved["status"])
        self.assertIn("resolved", [event["to_status"] for event in events])
        self.assertEqual(1, len(notifier.sent))
        self.assertEqual("Ops Agent recovered 2 issue(s)", notifier.sent[0][0])

    def test_playbook_halt_skips_remaining_steps_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "remediation": {
                        "enabled": True,
                        "mode": "auto",
                        "allowed_actions": ["check_port", "run_diagnostic_command"],
                    }
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            scheduler = OpsScheduler(config, storage, RecordingNotifier())
            actions = [
                RemediationAction(
                    action_type="check_port",
                    title="Failing port",
                    reason="test",
                    params={
                        "host": "127.0.0.1",
                        "port": 1,
                        "timeout_seconds": 0.05,
                        "_playbook": {
                            "name": "halt-playbook",
                            "step_id": "check",
                            "stage": "diagnose",
                            "on_failure": "halt",
                        },
                    },
                    auto_execute=True,
                ),
                RemediationAction(
                    action_type="run_diagnostic_command",
                    title="Should be skipped",
                    reason="test",
                    params={
                        "command": "df -h",
                        "_playbook": {
                            "name": "halt-playbook",
                            "step_id": "diagnostic",
                            "stage": "diagnose",
                            "on_failure": "continue",
                        },
                    },
                    auto_execute=True,
                ),
            ]
            results = scheduler.process_remediation_actions(actions)
            rows = sorted(storage.latest_action_logs(), key=lambda row: row["id"])
            storage.close()

        self.assertEqual(["failed", "skipped"], [result.status for result in results])
        self.assertEqual("skipped", rows[1]["status"])
        self.assertIn("playbook halted", rows[1]["error"])

    def test_playbook_rollback_runs_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "remediation": {
                        "enabled": True,
                        "mode": "auto",
                        "allowed_actions": ["check_port"],
                    }
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            scheduler = OpsScheduler(config, storage, RecordingNotifier())
            rollback = RemediationAction(
                action_type="check_port",
                title="Rollback probe",
                reason="rollback diagnostic",
                params={
                    "host": "127.0.0.1",
                    "port": 1,
                    "timeout_seconds": 0.05,
                    "_playbook": {
                        "name": "rollback-playbook",
                        "step_id": "rollback",
                        "stage": "rollback",
                        "on_failure": "continue",
                    },
                },
                auto_execute=False,
            )
            actions = [
                RemediationAction(
                    action_type="check_port",
                    title="Failing port",
                    reason="test",
                    params={
                        "host": "127.0.0.1",
                        "port": 1,
                        "timeout_seconds": 0.05,
                        "_playbook": {
                            "name": "rollback-playbook",
                            "step_id": "check",
                            "stage": "diagnose",
                            "on_failure": "rollback",
                            "rollback_actions": [rollback.to_dict()],
                        },
                    },
                    auto_execute=True,
                ),
                RemediationAction(
                    action_type="check_port",
                    title="Skipped after rollback",
                    reason="test",
                    params={
                        "host": "127.0.0.1",
                        "port": 1,
                        "_playbook": {
                            "name": "rollback-playbook",
                            "step_id": "after",
                            "stage": "diagnose",
                            "on_failure": "continue",
                        },
                    },
                    auto_execute=True,
                ),
            ]
            results = scheduler.process_remediation_actions(actions)
            rows = sorted(storage.latest_action_logs(), key=lambda row: row["id"])
            storage.close()

        self.assertEqual(["failed", "dry_run", "skipped"], [result.status for result in results])
        self.assertEqual("Rollback probe", rows[1]["title"])
        self.assertEqual("dry_run", rows[1]["status"])
        rollback_params = json.loads(rows[1]["params_json"])
        self.assertEqual("rollback", rollback_params["_playbook"]["stage"])

    def test_playbook_escalation_notifies_and_transitions_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "remediation": {
                        "enabled": True,
                        "mode": "auto",
                        "allowed_actions": ["check_port"],
                    }
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            incident_id = storage.save_incident(
                "critical",
                "Test incident",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="Request failed")],
            )
            action = RemediationAction(
                action_type="check_port",
                title="Failing port",
                reason="test",
                params={
                    "host": "127.0.0.1",
                    "port": 1,
                    "timeout_seconds": 0.05,
                    "_playbook": {
                        "name": "escalate-playbook",
                        "step_id": "check",
                        "stage": "diagnose",
                        "on_failure": "escalate",
                    },
                },
                auto_execute=True,
            )
            scheduler.process_remediation_actions([action], incident_id=incident_id)
            incident = storage.get_incident(incident_id)
            storage.close()

        self.assertTrue(any(title == "Ops Agent playbook escalation" for title, _, _ in notifier.sent))
        self.assertEqual("remediating", incident["status"])


if __name__ == "__main__":
    unittest.main()
