import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ops_agent.monitors.log_monitor import run_log_check


class LogMonitorTest(unittest.TestCase):
    def test_run_log_check_finds_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            log_path = tmp_path / "app.log"
            log_path.write_text("ok\nERROR database timeout\n", encoding="utf-8")
            result = run_log_check({"name": "app", "path": str(log_path), "keywords": ["ERROR"]}, tmp_path)
            self.assertEqual(result.status, "warning")
            self.assertEqual(result.details["match_count"], 1)

    def test_run_log_check_reads_docker_logs_by_container_name(self) -> None:
        completed = Mock(returncode=0, stdout="ok\nERROR api timeout\n", stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("ops_agent.monitors.log_monitor.subprocess.run", return_value=completed) as run:
                result = run_log_check(
                    {
                        "name": "api",
                        "container": "ai-customer-service-api-1",
                        "tail_lines": 20,
                        "keywords": ["ERROR"],
                    },
                    Path(tmp),
                )

        self.assertEqual(result.status, "warning")
        self.assertEqual(result.details["container"], "ai-customer-service-api-1")
        self.assertEqual(result.details["match_count"], 1)
        run.assert_called_once()
        self.assertIn("ai-customer-service-api-1", run.call_args.args[0])

    def test_docker_log_only_new_skips_first_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch("ops_agent.monitors.log_monitor.subprocess.run") as run:
                result = run_log_check(
                    {"name": "api", "container": "api-1", "only_new": True},
                    Path(tmp),
                )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.summary, "No new docker log lines")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
