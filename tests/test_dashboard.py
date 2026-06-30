import tempfile
import unittest
import urllib.request
from pathlib import Path

from ops_agent.dashboard import render_page, start_dashboard
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

    def test_incident_lifecycle_api_transitions_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="json", name="AI", status="warning", summary="Slow")
            incident_id = storage.save_incident("warning", "Ops Agent detected 1 issue(s)", "analysis", [result])
            server = start_dashboard(storage, "127.0.0.1", 0)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ack",
                    data=b'{"actor":"tester","note":"checking"}',
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = response.read().decode("utf-8")
                with urllib.request.urlopen(
                    f"http://{host}:{port}/api/incidents/{incident_id}/events",
                    timeout=5,
                ) as response:
                    events_body = response.read().decode("utf-8")
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertIn('"status": "acknowledged"', body)
        self.assertIn('"to_status": "acknowledged"', events_body)


if __name__ == "__main__":
    unittest.main()
