import tempfile
import unittest
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.remediation.executor import execute_action
from ops_agent.remediation.planner import build_remediation_plan
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


if __name__ == "__main__":
    unittest.main()
