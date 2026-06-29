import tempfile
import unittest
from pathlib import Path

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.scheduler import OpsScheduler, build_daily_report, build_recovery_message
from ops_agent.storage import Storage


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
                    )
                ]
            )
            rows = storage.latest_action_logs()
            storage.close()
        self.assertTrue(any(row["action_type"] == "check_port" for row in rows))


if __name__ == "__main__":
    unittest.main()
