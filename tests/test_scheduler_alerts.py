import unittest

from ops_agent.events import CheckResult
from ops_agent.scheduler import build_daily_report, build_recovery_message


class SchedulerAlertsTest(unittest.TestCase):
    def test_recovery_message_lists_recovered_checks(self) -> None:
        message = build_recovery_message([CheckResult(source="http", name="Site", status="ok", summary="HTTP 200")])
        self.assertIn("已经恢复正常", message)
        self.assertIn("http/Site", message)

    def test_daily_report_counts_statuses(self) -> None:
        rows = [
            {"source": "http", "name": "Site", "status": "ok", "summary": "HTTP 200"},
            {"source": "json", "name": "Chat", "status": "warning", "summary": "Slow"},
        ]
        report = build_daily_report(rows)
        self.assertIn("过去 24 小时巡检记录：2 条", report)
        self.assertIn("警告：1 条", report)


if __name__ == "__main__":
    unittest.main()
