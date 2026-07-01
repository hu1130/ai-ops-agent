import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.remediation.executor import execute_action
from ops_agent.remediation.planner import build_remediation_plan
from ops_agent.remediation.verifier import verify_after_action
from ops_agent.storage import Storage


class RemediationTest(unittest.TestCase):
    def test_plan_for_json_api_includes_port_check(self) -> None:
        config = AppConfig(
            raw={"remediation": {"enabled": True, "actions": {"check_port": {"auto_execute": True}}}},
            base_dir=Path("."),
        )
        issue = CheckResult(
            source="json_api",
            name="AI customer service",
            status="warning",
            summary="Slow response",
            details={"url": "https://agent.example.com/v1/chat"},
        )
        actions = build_remediation_plan([issue], config)
        self.assertTrue(any(action.action_type == "check_port" for action in actions))
        self.assertTrue(any(action.params.get("port") == 443 for action in actions))

    def test_policy_auto_execute_overrides_plan_defaults(self) -> None:
        config = AppConfig(
            raw={
                "remediation": {
                    "enabled": True,
                    "actions": {"check_port": {"auto_execute": False}},
                    "policies": [
                        {
                            "action_type": "check_port",
                            "targets": ["agent.example.com:443"],
                            "enabled": True,
                            "auto_execute": True,
                            "requires_approval": False,
                        }
                    ],
                }
            },
            base_dir=Path("."),
        )
        issue = CheckResult(
            source="json_api",
            name="AI customer service",
            status="warning",
            summary="Slow response",
            details={"url": "https://agent.example.com/v1/chat"},
        )
        actions = build_remediation_plan([issue], config)
        self.assertEqual(1, len(actions))
        check_port_actions = [action for action in actions if action.action_type == "check_port"]
        self.assertEqual(1, len(check_port_actions))
        self.assertTrue(check_port_actions[0].auto_execute)

    def test_playbook_generates_template_actions(self) -> None:
        config = AppConfig(
            raw={
                "remediation": {
                    "enabled": True,
                    "playbooks": [
                        {
                            "name": "web triage",
                            "on_failure": "halt",
                            "match": {"sources": ["json_api"]},
                            "steps": [
                                {
                                    "id": "check_target",
                                    "stage": "diagnose",
                                    "on_failure": "halt",
                                    "action_type": "check_port",
                                    "title": "PB {{host}}:{{port}}",
                                    "reason": "{{source}}/{{name}} playbook matched",
                                    "params": {"host": "{{host}}", "port": "{{port}}", "timeout_seconds": 3},
                                    "auto_execute": True,
                                },
                                {
                                    "id": "inspect_containers",
                                    "stage": "diagnose",
                                    "action_type": "run_diagnostic_command",
                                    "title": "PB docker ps",
                                    "reason": "Keep docker template syntax",
                                    "params": {"command": "docker ps --format table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"},
                                },
                            ],
                        }
                    ],
                    "policies": [
                        {
                            "action_type": "check_port",
                            "targets": ["agent.example.com:443"],
                            "enabled": True,
                            "auto_execute": True,
                        },
                        {
                            "action_type": "run_diagnostic_command",
                            "targets": ["docker"],
                            "enabled": True,
                        },
                    ],
                }
            },
            base_dir=Path("."),
        )
        issue = CheckResult(
            source="json_api",
            name="AI customer service",
            status="warning",
            summary="Slow response",
            details={"url": "https://agent.example.com/v1/chat"},
        )
        actions = build_remediation_plan([issue], config)
        self.assertEqual(2, len(actions))
        port_actions = [action for action in actions if action.title == "PB agent.example.com:443"]
        self.assertEqual(1, len(port_actions))
        self.assertEqual("web triage", port_actions[0].params["_playbook"]["name"])
        self.assertEqual("check_target", port_actions[0].params["_playbook"]["step_id"])
        self.assertEqual("halt", port_actions[0].params["_playbook"]["on_failure"])
        docker_actions = [action for action in actions if action.action_type == "run_diagnostic_command"]
        self.assertEqual(
            "docker ps --format table {{.Names}}\\t{{.Status}}\\t{{.Ports}}",
            docker_actions[0].params["command"],
        )

    def test_playbook_does_not_match_unrelated_issue(self) -> None:
        config = AppConfig(
            raw={
                "remediation": {
                    "enabled": True,
                    "playbooks": [
                        {
                            "name": "web triage",
                            "match": {"sources": ["json_api"]},
                            "steps": [
                                {
                                    "action_type": "check_port",
                                    "title": "Should not appear",
                                    "reason": "source mismatch",
                                    "params": {"host": "example.com", "port": 443},
                                }
                            ],
                        }
                    ],
                }
            },
            base_dir=Path("."),
        )
        issue = CheckResult(source="manual", name="Manual issue", status="warning", summary="test")
        self.assertEqual([], build_remediation_plan([issue], config))

    def test_policy_denies_unlisted_target(self) -> None:
        config = AppConfig(
            raw={
                "remediation": {
                    "policies": [
                        {
                            "action_type": "check_port",
                            "targets": ["allowed.example.com:443"],
                            "enabled": True,
                            "auto_execute": True,
                        }
                    ]
                }
            },
            base_dir=Path("."),
        )
        action = RemediationAction(
            action_type="check_port",
            title="Check blocked port",
            reason="Manual test",
            params={"host": "blocked.example.com", "port": 443},
            auto_execute=True,
        )
        result = execute_action(action, config, dry_run=False)
        self.assertEqual("skipped", result.status)
        self.assertIn("policy denied", result.error)

    def test_policy_requires_verify_after_for_mutating_action(self) -> None:
        config = AppConfig(
            raw={
                "remediation": {
                    "policies": [
                        {
                            "action_type": "restart_service",
                            "targets": ["ops-agent"],
                            "enabled": True,
                            "requires_approval": True,
                            "verification_required": True,
                        }
                    ]
                }
            },
            base_dir=Path("."),
        )
        action = RemediationAction(
            action_type="restart_service",
            title="Restart ops-agent",
            reason="Manual test",
            risk="medium",
            params={"service": "ops-agent"},
        )
        result = execute_action(action, config, dry_run=False, approved=True)
        self.assertEqual("skipped", result.status)
        self.assertIn("verify_after", result.error)

    def test_disabled_policy_is_skipped(self) -> None:
        config = AppConfig(
            raw={
                "remediation": {
                    "policies": [
                        {
                            "action_type": "cleanup_temp_files",
                            "targets": ["/tmp"],
                            "enabled": False,
                        }
                    ]
                }
            },
            base_dir=Path("."),
        )
        action = RemediationAction(
            action_type="cleanup_temp_files",
            title="Cleanup temp",
            reason="Manual test",
            risk="medium",
            params={"paths": ["/tmp"]},
        )
        result = execute_action(action, config, dry_run=False, approved=True)
        self.assertEqual("skipped", result.status)
        self.assertIn("policy denied", result.error)

    def test_dry_run_does_not_execute_mutating_action(self) -> None:
        config = AppConfig(raw={"remediation": {"allowed_actions": ["restart_service"]}}, base_dir=Path("."))
        action = RemediationAction(
            action_type="restart_service",
            title="Restart app",
            reason="Manual test",
            risk="medium",
            params={"service": "app"},
        )
        result = execute_action(action, config, dry_run=True)
        self.assertEqual("dry_run", result.status)
        self.assertIn("restart_service", result.output)

    def test_non_read_only_command_is_skipped(self) -> None:
        config = AppConfig(
            raw={"remediation": {"allowed_actions": ["run_diagnostic_command"]}},
            base_dir=Path("."),
        )
        action = RemediationAction(
            action_type="run_diagnostic_command",
            title="Bad command",
            reason="Manual test",
            params={"command": "rm -rf /tmp/example"},
            auto_execute=True,
        )
        result = execute_action(action, config, dry_run=False)
        self.assertEqual("skipped", result.status)
        self.assertIn("非只读命令", result.error)

    def test_restart_service_requires_allowlist_even_when_approved(self) -> None:
        config = AppConfig(
            raw={"remediation": {"allowed_actions": ["restart_service"], "allowed_services": []}},
            base_dir=Path("."),
        )
        action = RemediationAction(
            action_type="restart_service",
            title="Restart app",
            reason="Manual test",
            risk="medium",
            params={"service": "app"},
        )
        result = execute_action(action, config, dry_run=False, approved=True)
        self.assertEqual("skipped", result.status)
        self.assertIn("allowed_services", result.error)

    def test_storage_records_action_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            storage.save_action_log(
                "check_port",
                "检查端口",
                "low",
                "dry_run",
                "test",
                {"host": "127.0.0.1", "port": 80},
            )
            rows = storage.latest_action_logs()
            storage.close()
        self.assertEqual(1, len(rows))
        self.assertEqual("check_port", rows[0]["action_type"])

    def test_storage_updates_action_log_after_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            action_id = storage.save_action_log(
                "restart_service",
                "重启服务",
                "medium",
                "pending_approval",
                "test",
                {"service": "app"},
            )
            storage.update_action_log(action_id, "skipped", error="not allowed", approved_by="tester")
            row = storage.get_action_log(action_id)
            storage.close()
        self.assertIsNotNone(row)
        self.assertEqual("skipped", row["status"])
        self.assertEqual("tester", row["approved_by"])

    def test_verify_after_action_http_success(self) -> None:
        server = start_test_server(200)
        try:
            port = server.server_address[1]
            action = RemediationAction(
                action_type="check_port",
                title="Check",
                reason="test",
                params={
                    "verify_after": {
                        "type": "http",
                        "url": f"http://127.0.0.1:{port}/health",
                        "wait_seconds": 0,
                        "retries": 1,
                        "timeout_seconds": 2,
                    }
                },
            )
            config = AppConfig(raw={"remediation": {"verification": {"enabled": True}}}, base_dir=Path("."))
            result = verify_after_action(action, config)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual("verified_ok", result.status)

    def test_verify_after_action_http_failure(self) -> None:
        server = start_test_server(503)
        try:
            port = server.server_address[1]
            action = RemediationAction(
                action_type="check_port",
                title="Check",
                reason="test",
                params={
                    "verify_after": {
                        "type": "http",
                        "url": f"http://127.0.0.1:{port}/health",
                        "expected_status": 200,
                        "wait_seconds": 0,
                        "retries": 1,
                        "timeout_seconds": 2,
                    }
                },
            )
            config = AppConfig(raw={"remediation": {"verification": {"enabled": True}}}, base_dir=Path("."))
            result = verify_after_action(action, config)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual("verified_failed", result.status)

    def test_storage_records_verification_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            action_id = storage.save_action_log(
                "check_port",
                "检查端口",
                "low",
                "executed",
                "test",
                {"host": "127.0.0.1", "port": 80},
            )
            storage.update_action_verification(action_id, "verified_ok", "HTTP 200")
            row = storage.get_action_log(action_id)
            storage.close()
        self.assertIsNotNone(row)
        self.assertEqual("verified_ok", row["status"])
        self.assertEqual("verified_ok", row["verify_status"])


def start_test_server(status_code: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(status_code)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == "__main__":
    unittest.main()
