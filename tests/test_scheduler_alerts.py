import tempfile
import unittest
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.scheduler import (
    OpsScheduler,
    build_daily_report,
    build_recovery_message,
    enabled_report_target_keys,
    filter_report_rows,
)
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

    def test_daily_report_filters_disabled_targets(self) -> None:
        config = AppConfig(
            raw={
                "http_checks": [
                    {"name": "Active site", "url": "https://active.example.com"},
                    {"name": "Disabled site", "url": "https://disabled.example.com", "enabled": False},
                ],
                "docker_checks": [
                    {"name": "Active container", "container": "active-app"},
                    {"name": "Disabled container", "container": "disabled-app", "enabled": False},
                ],
                "server_checks": {"enabled": False},
            },
            base_dir=Path("."),
        )
        rows = [
            {"source": "http", "name": "Active site", "status": "ok", "summary": "HTTP 200"},
            {"source": "http", "name": "Disabled site", "status": "warning", "summary": "Still historical"},
            {"source": "docker", "name": "Active container", "status": "ok", "summary": "Running"},
            {"source": "docker", "name": "Disabled container", "status": "warning", "summary": "Historical"},
            {"source": "server", "name": "Disk usage", "status": "ok", "summary": "Disk OK"},
        ]

        filtered = filter_report_rows(rows, enabled_report_target_keys(config))
        report = build_daily_report(filtered)

        self.assertEqual(["Active site", "Active container"], [row["name"] for row in filtered])
        self.assertIn("Active site", report)
        self.assertIn("Active container", report)
        self.assertNotIn("Disabled site", report)
        self.assertNotIn("Disabled container", report)
        self.assertNotIn("Disk usage", report)

    def test_due_checks_skips_disabled_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            scheduler = OpsScheduler(
                AppConfig(raw={"app": {"interval_seconds": 60}}, base_dir=Path(tmp)),
                storage,
                RecordingNotifier(),
            )
            checks = [
                {"name": "Enabled", "url": "https://example.com", "enabled": True},
                {"name": "Disabled", "url": "https://disabled.example.com", "enabled": False},
            ]
            due = scheduler.due_checks("http", checks, respect_intervals=False, now=0)
            storage.close()

        self.assertEqual(["Enabled"], [check["name"] for check in due])

    def test_per_check_alert_after_failures_overrides_global_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 3},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            scheduler.process_alert_states(
                [
                    CheckResult(
                        source="http",
                        name="Business entry",
                        status="critical",
                        summary="Missing required response text: Project Dashboard",
                        details={"url": "https://example.com/project", "alert_after_failures": 1},
                    )
                ]
            )
            incidents = storage.latest_incidents(1)
            storage.close()

        self.assertEqual(1, len(incidents))
        self.assertEqual("critical", incidents[0]["severity"])
        self.assertEqual(1, len(notifier.sent))

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
            recommendations = storage.latest_incident_recommendations(rows[0]["incident_id"])
            storage.close()
        self.assertTrue(any(row["action_type"] == "check_port" for row in rows))
        self.assertTrue(any(row["environment"] == "staging" for row in rows))
        self.assertTrue(any(row["run_type"] == "synthetic_test" for row in rows))
        self.assertTrue(any(row["trace_id"] == "trace-1" for row in rows))
        self.assertTrue(all(row["incident_id"] for row in rows))
        check_port = next(row for row in recommendations if row["action_type"] == "check_port")
        self.assertEqual("diagnose", check_port["category"])
        self.assertEqual("suggested", check_port["status"])
        self.assertEqual("dry_run", check_port["metadata"]["dry_run_status"])
        self.assertEqual("example.com", check_port["params"]["host"])
        self.assertEqual(443, check_port["params"]["port"])
        self.assertTrue(check_port["auto_execute"])
        self.assertFalse(check_port["approval_required"])
        self.assertFalse(check_port["verification_required"])
        self.assertEqual("staging", check_port["environment"])
        self.assertEqual("synthetic_test", check_port["run_type"])
        self.assertEqual("trace-1", check_port["trace_id"])

    def test_alert_persists_incident_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
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
                        summary="HTTP 500",
                        details={"url": "https://example.com", "status_code": 500},
                    )
                ]
            )
            incident = storage.latest_incidents(1)[0]
            stats = storage.classification_summary()
            storage.close()

        self.assertEqual("service_unavailable", incident["classification_category"])
        self.assertGreater(incident["classification_confidence"], 0.8)
        self.assertEqual("service_unavailable", stats["by_category"][0]["category"])

    def test_alert_auto_triggers_ai_repair_proposal_and_queue_notification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "email": {"enabled": True, "to_emails": ["owner@example.local"]},
                    },
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {
                        "enabled": True,
                        "repair": {
                            "provider": "rules",
                            "auto_trigger": {
                                "enabled": True,
                                "severities": ["critical"],
                                "categories": ["service_unavailable"],
                                "min_classification_confidence": 0.65,
                                "run_dry_run": True,
                                "notify": True,
                                "notify_states": ["review_only", "needs_sandbox", "blocked"],
                            },
                        },
                    },
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            scheduler.process_alert_states(
                [
                    CheckResult(
                        source="http",
                        name="Site",
                        status="critical",
                        summary="HTTP 500",
                        details={"url": "https://example.com", "status_code": 500},
                    )
                ]
            )
            incident = storage.latest_incidents(1)[0]
            repairs = storage.latest_ai_repair_proposals(incident_id=incident["id"])
            events = storage.latest_incident_events(incident["id"])
            notifications = storage.latest_notification_logs()
            storage.close()

        self.assertEqual(1, len(repairs))
        self.assertEqual("dry_run_passed", repairs[0]["status"])
        self.assertEqual("rules", repairs[0]["model_provider"])
        self.assertIn("AI repair auto trigger", incident["analysis"])
        self.assertTrue(any(event["note"] == "AI repair auto-triggered" for event in events))
        self.assertEqual(2, len(notifier.sent))
        self.assertIn("Ops Agent AI repair approval queue: 1 item(s)", {title for title, _, _ in notifier.sent})
        self.assertIn("Ops Agent detected 1 issue(s)", {title for title, _, _ in notifier.sent})
        self.assertTrue(any(json.loads(row["route_names_json"]) == ["ai-repair-approval-queue"] for row in notifications))

    def test_ai_repair_auto_trigger_skips_warning_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1},
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {
                        "enabled": True,
                        "repair": {
                            "provider": "rules",
                            "auto_trigger": {"enabled": True},
                        },
                    },
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            scheduler.process_alert_states(
                [CheckResult(source="json_api", name="Chat", status="warning", summary="Slow response: 8000 ms")]
            )
            incident = storage.latest_incidents(1)[0]
            repairs = storage.latest_ai_repair_proposals(incident_id=incident["id"])
            storage.close()

        self.assertEqual([], repairs)
        self.assertEqual(1, len(notifier.sent))

    def test_ai_repair_auto_trigger_rate_limits_recent_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {"consecutive_failures": 1},
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {
                        "enabled": True,
                        "repair": {
                            "provider": "rules",
                            "auto_trigger": {
                                "enabled": True,
                                "severities": ["critical"],
                                "categories": ["service_unavailable"],
                                "min_classification_confidence": 0.65,
                                "run_dry_run": True,
                                "notify": False,
                                "max_triggers_per_window": 1,
                                "trigger_window_minutes": 60,
                            },
                        },
                    },
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            scheduler = OpsScheduler(config, storage, RecordingNotifier())
            scheduler.process_alert_states(
                [
                    CheckResult(
                        source="http",
                        name="Site A",
                        status="critical",
                        summary="HTTP 500",
                        details={"url": "https://a.example.com", "status_code": 500},
                    )
                ]
            )
            scheduler.process_alert_states(
                [
                    CheckResult(
                        source="http",
                        name="Site B",
                        status="critical",
                        summary="HTTP 500",
                        details={"url": "https://b.example.com", "status_code": 500},
                    )
                ]
            )
            incidents = storage.latest_incidents(10)
            repairs = storage.latest_ai_repair_proposals()
            second = next(row for row in incidents if "Site B" in row["last_summary"])
            events = storage.latest_incident_events(second["id"])
            storage.close()

        self.assertEqual(1, len(repairs))
        self.assertEqual("auto_trigger", repairs[0]["prompt"]["source"])
        self.assertIn("rate_limited", second["analysis"])
        self.assertTrue(any(event["note"] == "AI repair auto-trigger rate-limited" for event in events))

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

    def test_alert_route_adds_header_and_dedupe_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "routes": [
                            {
                                "name": "site-owner",
                                "match": {"sources": ["http"], "severities": ["critical"]},
                                "channels": ["email"],
                            }
                        ],
                    },
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            scheduler.process_alert_states(
                [CheckResult(source="http", name="Site", status="critical", summary="Request failed")]
            )
            logs = storage.latest_notification_logs()
            storage.close()

        self.assertEqual(1, len(notifier.sent))
        self.assertIn("Alert routing:", notifier.sent[0][1])
        self.assertIn("- routes: site-owner", notifier.sent[0][1])
        self.assertEqual("http:Site:critical|route:site-owner:email", notifier.sent[0][2])
        self.assertEqual(1, len(logs))
        self.assertEqual("sent", logs[0]["status"])
        self.assertEqual(["site-owner"], json.loads(logs[0]["route_names_json"]))
        self.assertEqual(["email"], json.loads(logs[0]["channels_json"]))

    def test_silence_window_suppresses_notification_but_saves_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "silence_windows": [
                            {
                                "name": "all-day-warning",
                                "start": "00:00",
                                "end": "00:00",
                                "timezone": "+00:00",
                                "match": {"severities": ["warning"]},
                            }
                        ],
                    },
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            scheduler.process_alert_states(
                [CheckResult(source="http", name="Site", status="warning", summary="Slow response")]
            )
            incidents = storage.latest_incidents(1)
            logs = storage.latest_notification_logs()
            storage.close()

        self.assertEqual(0, len(notifier.sent))
        self.assertEqual(1, len(incidents))
        self.assertEqual("open", incidents[0]["status"])
        self.assertEqual(1, len(logs))
        self.assertEqual("suppressed", logs[0]["status"])
        self.assertIn("all-day-warning", logs[0]["suppressed_reason"])

    def test_repeated_problem_sends_reminder_after_repeat_interval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "recovery_enabled": True,
                        "repeat_notification_enabled": True,
                        "repeat_notification_interval_seconds": 60,
                    },
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
            incident = storage.latest_incidents(1)[0]
            old_notification = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            storage.connection.execute(
                "update incidents set last_notification_at = ? where id = ?",
                (old_notification, incident["id"]),
            )
            storage.connection.commit()

            scheduler.process_alert_states([problem])
            updated = storage.get_incident(incident["id"])
            storage.close()

        self.assertEqual(2, len(notifier.sent))
        self.assertEqual("Ops Agent repeated issue reminder #1", notifier.sent[1][0])
        self.assertIn("累计出现次数: 2", notifier.sent[1][1])
        self.assertEqual("repeat", updated["last_notification_kind"])

    def test_repeated_problem_does_not_send_reminder_before_interval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "recovery_enabled": True,
                        "repeat_notification_enabled": True,
                        "repeat_notification_interval_seconds": 3600,
                    },
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
            updated = storage.latest_incidents(1)[0]
            storage.close()

        self.assertEqual(1, len(notifier.sent))
        self.assertEqual(2, updated["occurrence_count"])
        self.assertEqual("initial", updated["last_notification_kind"])

    def test_repeated_problem_reminder_can_be_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "recovery_enabled": True,
                        "repeat_notification_enabled": False,
                        "repeat_notification_interval_seconds": 60,
                    },
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
            incident = storage.latest_incidents(1)[0]
            old_notification = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            storage.connection.execute(
                "update incidents set last_notification_at = ? where id = ?",
                (old_notification, incident["id"]),
            )
            storage.connection.commit()
            scheduler.process_alert_states([problem])
            updated = storage.get_incident(incident["id"])
            storage.close()

        self.assertEqual(1, len(notifier.sent))
        self.assertEqual(2, updated["occurrence_count"])
        self.assertEqual("initial", updated["last_notification_kind"])

    def test_repeated_problem_escalates_after_active_duration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "recovery_enabled": True,
                        "repeat_notification_enabled": True,
                        "repeat_notification_interval_seconds": 60,
                        "escalation_enabled": True,
                        "escalation_after_seconds": 300,
                        "escalation_critical_occurrences": 10,
                    },
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {"enabled": False, "mode": "off"},
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            problem = CheckResult(source="http", name="Site", status="warning", summary="Slow")
            scheduler.process_alert_states([problem])
            incident = storage.latest_incidents(1)[0]
            old_first_seen = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            storage.connection.execute(
                """
                update incidents
                set first_seen_at = ?, last_notification_at = ?
                where id = ?
                """,
                (old_first_seen, old_first_seen, incident["id"]),
            )
            storage.connection.commit()

            scheduler.process_alert_states([problem])
            escalated = storage.get_incident(incident["id"])
            events = storage.latest_incident_events(incident["id"])
            storage.close()

        self.assertEqual(2, len(notifier.sent))
        self.assertEqual("[升级] Ops Agent incident #1 requires attention", notifier.sent[1][0])
        self.assertIn("事件升级提醒", notifier.sent[1][1])
        self.assertEqual(1, escalated["escalation_level"])
        self.assertEqual("escalation", escalated["last_notification_kind"])
        self.assertTrue(any(event["note"] == "incident escalated" for event in events))

    def test_critical_repeated_problem_escalates_by_occurrence_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "recovery_enabled": True,
                        "repeat_notification_enabled": True,
                        "repeat_notification_interval_seconds": 60,
                        "escalation_enabled": True,
                        "escalation_after_seconds": 86400,
                        "escalation_critical_occurrences": 3,
                    },
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
            incident = storage.latest_incidents(1)[0]
            old_notification = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            storage.connection.execute(
                """
                update incidents
                set occurrence_count = 2, last_notification_at = ?
                where id = ?
                """,
                (old_notification, incident["id"]),
            )
            storage.connection.commit()

            scheduler.process_alert_states([problem])
            escalated = storage.get_incident(incident["id"])
            storage.close()

        self.assertEqual(2, len(notifier.sent))
        self.assertIn("critical incident occurred 3 times", notifier.sent[1][1])
        self.assertEqual(1, escalated["escalation_level"])
        self.assertIn("critical incident occurred 3 times", escalated["escalation_reason"])

    def test_escalation_can_be_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "recovery_enabled": True,
                        "repeat_notification_enabled": False,
                        "escalation_enabled": False,
                        "escalation_after_seconds": 300,
                        "escalation_critical_occurrences": 3,
                    },
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
            incident = storage.latest_incidents(1)[0]
            old_first_seen = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            storage.connection.execute(
                "update incidents set first_seen_at = ?, occurrence_count = 9 where id = ?",
                (old_first_seen, incident["id"]),
            )
            storage.connection.commit()
            scheduler.process_alert_states([problem])
            not_escalated = storage.get_incident(incident["id"])
            storage.close()

        self.assertEqual(1, len(notifier.sent))
        self.assertEqual(0, not_escalated["escalation_level"])

    def test_failed_auto_remediation_escalates_on_same_notifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                raw={
                    "alerts": {
                        "consecutive_failures": 1,
                        "recovery_enabled": True,
                        "escalation_enabled": True,
                    },
                    "app": {"environment": "prod", "run_type": "normal"},
                    "ai": {"enabled": False},
                    "remediation": {
                        "enabled": True,
                        "mode": "auto",
                        "allowed_actions": ["check_port"],
                        "actions": {"check_port": {"auto_execute": True}},
                    },
                },
                base_dir=Path(tmp),
            )
            storage = Storage(Path(tmp) / "ops.db")
            notifier = RecordingNotifier()
            scheduler = OpsScheduler(config, storage, notifier)
            scheduler.process_alert_states(
                [
                    CheckResult(
                        source="http",
                        name="Site",
                        status="critical",
                        summary="Request failed",
                        details={"url": "http://127.0.0.1:1"},
                    )
                ]
            )
            incident = storage.latest_incidents(1)[0]
            events = storage.latest_incident_events(incident["id"])
            storage.close()

        self.assertEqual(2, len(notifier.sent))
        self.assertEqual("Ops Agent detected 1 issue(s)", notifier.sent[0][0])
        self.assertEqual("[升级] Ops Agent incident #1 requires attention", notifier.sent[1][0])
        self.assertIn("remediation action(s) failed", notifier.sent[1][1])
        self.assertEqual(1, incident["escalation_level"])
        self.assertTrue(any(event["note"] == "incident escalated" for event in events))

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
