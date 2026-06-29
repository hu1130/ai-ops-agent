import tempfile
import unittest
from pathlib import Path

from ops_agent.dashboard import render_page
from ops_agent.events import CheckResult
from ops_agent.storage import Storage


class DashboardTest(unittest.TestCase):
    def test_dashboard_summary_counts_recent_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            storage.save_results(
                [
                    CheckResult(source="http", name="官网", status="ok", summary="HTTP 200"),
                    CheckResult(source="json", name="AI 客服", status="warning", summary="Slow response"),
                    CheckResult(source="server", name="Disk", status="critical", summary="Disk high"),
                ]
            )
            summary = storage.dashboard_summary()
            storage.close()

        self.assertEqual(3, summary["total_checks"])
        self.assertEqual(2, summary["active_problem_count"])
        self.assertEqual("critical", summary["current_status"])
        self.assertEqual(1, summary["source_counts"]["json"])

    def test_render_page_contains_event_center_and_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="json", name="AI 客服", status="warning", summary="Slow response")
            storage.save_results([result])
            storage.save_incident("warning", "Ops Agent detected 1 issue(s)", "下一步建议", [result])
            html = render_page(storage)
            storage.close()

        self.assertIn("事件中心", html)
        self.assertIn("当前监控目标", html)
        self.assertIn("AI 客服", html)
        self.assertIn("下一步建议", html)


if __name__ == "__main__":
    unittest.main()
