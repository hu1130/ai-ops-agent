import tempfile
import unittest
import json
import urllib.error
import urllib.request
from pathlib import Path

from ops_agent.config import AppConfig
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
            storage.save_action_log(
                "check_port",
                "Check port",
                "low",
                "dry_run",
                "diagnose",
                {"host": "example.com", "port": 443},
                incident_id=incident_id,
            )
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
                with urllib.request.urlopen(
                    f"http://{host}:{port}/api/incidents/{incident_id}/actions",
                    timeout=5,
                ) as response:
                    actions_body = response.read().decode("utf-8")
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertIn('"status": "acknowledged"', body)
        self.assertIn('"to_status": "acknowledged"', events_body)
        self.assertIn('"incident_id":', actions_body)

    def test_action_approval_api_lists_and_rejects_pending_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            action_id = storage.save_action_log(
                "restart_service",
                "Restart app",
                "medium",
                "pending_approval",
                "manual approval",
                {"service": "app"},
            )
            storage.save_action_log(
                "check_port",
                "Check port",
                "low",
                "dry_run",
                "diagnose",
                {"host": "example.com", "port": 443},
            )
            server = start_dashboard(storage, "127.0.0.1", 0)
            host, port = server.server_address
            try:
                with urllib.request.urlopen(
                    f"http://{host}:{port}/api/actions/pending",
                    timeout=5,
                ) as response:
                    pending = json.loads(response.read().decode("utf-8"))
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/actions/{action_id}/reject",
                    data=b'{"actor":"tester","note":"not needed"}',
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    rejected = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(1, len(pending))
        self.assertEqual(action_id, pending[0]["id"])
        self.assertEqual("rejected", rejected["status"])
        self.assertEqual("rejected", rejected["decision"])
        self.assertEqual("tester", rejected["decision_by"])

    def test_action_approval_api_executes_approved_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "remediation": {
                        "allowed_actions": ["check_port"],
                        "verification": {"enabled": False},
                    }
                },
                base_dir=Path(tmp),
            )
            action_id = storage.save_action_log(
                "check_port",
                "Check closed port",
                "low",
                "pending_approval",
                "manual approval",
                {"host": "127.0.0.1", "port": 1, "timeout_seconds": 0.05},
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/actions/{action_id}/approve",
                    data=b'{"actor":"tester"}',
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    approved = json.loads(response.read().decode("utf-8"))
                row = storage.get_action_log(action_id)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(action_id, approved["action_id"])
        self.assertEqual("failed", approved["result"]["status"])
        self.assertEqual("failed", row["status"])
        self.assertEqual("approved", row["decision"])
        self.assertEqual("tester", row["approved_by"])

    def test_post_api_requires_token_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="json", name="AI", status="warning", summary="Slow")
            incident_id = storage.save_incident("warning", "Ops Agent detected 1 issue(s)", "analysis", [result])
            config = AppConfig(
                raw={"app": {"api_token": "secret-token"}},
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ack",
                    data=b'{"actor":"tester"}',
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=5)
                row = storage.get_incident(incident_id)
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(401, raised.exception.code)
        self.assertEqual("open", row["status"])

    def test_post_api_accepts_bearer_token_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="json", name="AI", status="warning", summary="Slow")
            incident_id = storage.save_incident("warning", "Ops Agent detected 1 issue(s)", "analysis", [result])
            config = AppConfig(
                raw={"app": {"api_token": "secret-token"}},
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ack",
                    data=b'{"actor":"tester"}',
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer secret-token",
                    },
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("acknowledged", body["status"])

    def test_get_api_can_require_token_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={"app": {"api_token": "secret-token", "api_auth_required_for_reads": True}},
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(f"http://{host}:{port}/api/summary", timeout=5)
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/summary",
                    headers={"X-Ops-Agent-Token": "secret-token"},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(401, raised.exception.code)
        self.assertIn("current_status", body)

    def test_viewer_token_can_read_when_read_auth_is_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(
                raw={
                    "app": {
                        "api_auth_required_for_reads": True,
                        "api_tokens": [
                            {"name": "readonly", "token": "viewer-token", "role": "viewer"},
                        ],
                    }
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/summary",
                    headers={"Authorization": "Bearer viewer-token"},
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertIn("current_status", body)

    def test_viewer_token_cannot_write_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="json", name="AI", status="warning", summary="Slow")
            incident_id = storage.save_incident("warning", "Ops Agent detected 1 issue(s)", "analysis", [result])
            config = AppConfig(
                raw={
                    "app": {
                        "api_tokens": [
                            {"name": "readonly", "token": "viewer-token", "role": "viewer"},
                        ],
                    }
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ack",
                    data=b"{}",
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer viewer-token",
                    },
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=5)
                incident = storage.get_incident(incident_id)
                audit = storage.latest_api_audit_logs()[0]
                metadata = json.loads(audit["metadata_json"])
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(403, raised.exception.code)
        self.assertEqual("open", incident["status"])
        self.assertEqual("forbidden", audit["outcome"])
        self.assertEqual(403, audit["status_code"])
        self.assertEqual("viewer", metadata["auth_role"])
        self.assertEqual("readonly", metadata["token_name"])

    def test_operator_token_can_write_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="json", name="AI", status="warning", summary="Slow")
            incident_id = storage.save_incident("warning", "Ops Agent detected 1 issue(s)", "analysis", [result])
            config = AppConfig(
                raw={
                    "app": {
                        "api_tokens": [
                            {"name": "ops-console", "token": "operator-token", "role": "operator"},
                        ],
                    }
                },
                base_dir=Path(tmp),
            )
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ack",
                    data=b"{}",
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "X-Ops-Agent-Token": "operator-token",
                    },
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = json.loads(response.read().decode("utf-8"))
                audit = storage.latest_api_audit_logs()[0]
                metadata = json.loads(audit["metadata_json"])
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual("acknowledged", body["status"])
        self.assertEqual("ops-console", body["acknowledged_by"])
        self.assertEqual("success", audit["outcome"])
        self.assertEqual("ops-console", audit["actor"])
        self.assertEqual("operator", metadata["auth_role"])
        self.assertEqual("ops-console", metadata["token_name"])

    def test_post_api_records_success_audit_log(self) -> None:
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
                    headers={
                        "Content-Type": "application/json",
                        "X-Forwarded-For": "203.0.113.10",
                    },
                )
                with urllib.request.urlopen(request, timeout=5):
                    pass
                with urllib.request.urlopen(f"http://{host}:{port}/api/audit-logs", timeout=5) as response:
                    api_rows = json.loads(response.read().decode("utf-8"))
                rows = storage.latest_api_audit_logs()
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(1, len(rows))
        self.assertEqual(rows[0]["id"], api_rows[0]["id"])
        self.assertEqual("incident.ack", rows[0]["operation"])
        self.assertEqual("incident", rows[0]["target_type"])
        self.assertEqual(incident_id, rows[0]["target_id"])
        self.assertEqual("tester", rows[0]["actor"])
        self.assertEqual("203.0.113.10", rows[0]["source_ip"])
        self.assertEqual(200, rows[0]["status_code"])
        self.assertEqual("success", rows[0]["outcome"])

    def test_unauthorized_post_records_audit_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            result = CheckResult(source="json", name="AI", status="warning", summary="Slow")
            incident_id = storage.save_incident("warning", "Ops Agent detected 1 issue(s)", "analysis", [result])
            config = AppConfig(raw={"app": {"api_token": "secret-token"}}, base_dir=Path(tmp))
            server = start_dashboard(storage, "127.0.0.1", 0, config=config)
            host, port = server.server_address
            try:
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/incidents/{incident_id}/ack",
                    data=b'{"actor":"tester"}',
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(request, timeout=5)
                rows = storage.latest_api_audit_logs()
            finally:
                server.shutdown()
                server.server_close()
                storage.close()

        self.assertEqual(401, raised.exception.code)
        self.assertEqual(1, len(rows))
        self.assertEqual("incident.ack", rows[0]["operation"])
        self.assertEqual(incident_id, rows[0]["target_id"])
        self.assertEqual(401, rows[0]["status_code"])
        self.assertEqual("unauthorized", rows[0]["outcome"])


if __name__ == "__main__":
    unittest.main()
