import tempfile
import unittest
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.diagnostics.collector import DiagnosticSnapshot, collect_relevant_logs, format_snapshot
from ops_agent.diagnostics.suggestions import build_action_suggestions
from ops_agent.events import CheckResult


class DiagnosticsTest(unittest.TestCase):
    def test_suggestions_include_json_api_guidance(self) -> None:
        text = build_action_suggestions(
            [CheckResult(source="json", name="AI customer service", status="warning", summary="Slow response")]
        )
        self.assertIn("AI 客服", text)
        self.assertIn("模型供应商", text)

    def test_format_snapshot_includes_sections(self) -> None:
        text = format_snapshot(
            DiagnosticSnapshot(
                resource_lines=["磁盘: 10%"],
                docker_lines=["docker ps:"],
                log_lines=["ERROR x"],
                command_lines=["docker logs --tail 120 app"],
            )
        )
        self.assertIn("诊断快照", text)
        self.assertIn("服务器资源", text)
        self.assertIn("建议排查命令", text)

    def test_collect_relevant_logs_reads_configured_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "app.log").write_text("ok\nERROR boom\n", encoding="utf-8")
            config = AppConfig(
                raw={
                    "alerts": {"diagnostics": {"max_log_lines": 10}},
                    "log_checks": [{"name": "App log", "path": "app.log"}],
                },
                base_dir=base,
            )
            lines = collect_relevant_logs(
                [CheckResult(source="log", name="App log", status="warning", summary="ERROR boom")],
                config,
                {"max_log_lines": 10, "max_log_chars": 1000},
            )
        self.assertTrue(any("ERROR boom" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
