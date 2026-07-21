import tempfile
import unittest
from pathlib import Path
import subprocess
from unittest.mock import Mock, patch

from ops_agent.monitors.log_monitor import run_log_check


class LogMonitorTest(unittest.TestCase):
    @patch("ops_agent.monitors.log_monitor.subprocess.run")
    def test_resolves_recreated_compose_container_before_reading_logs(self, run) -> None:
        missing = subprocess.CompletedProcess([], 1, stdout="", stderr="No such container")
        listing = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                '{"Names":"40d66a351638_ai-customer-service-semp-api-1",'
                '"Image":"api:latest","State":"running","Status":"Up",'
                '"Labels":"com.docker.compose.project=ai-customer-service,'
                'com.docker.compose.service=semp-api"}'
            ),
            stderr="",
        )
        healthy_log = subprocess.CompletedProcess([], 0, stdout="request completed\n", stderr="")
        run.side_effect = [missing, listing, healthy_log]

        with tempfile.TemporaryDirectory() as tmp:
            result = run_log_check(
                {
                    "name": "secondary API log",
                    "container": "ai-customer-service-semp-api-1",
                    "project_id": "ai-customer-service",
                    "compose_service": "semp-api",
                },
                Path(tmp),
            )

        self.assertEqual("ok", result.status)
        self.assertEqual("40d66a351638_ai-customer-service-semp-api-1", result.details["container"])

    def test_run_log_check_finds_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            log_path = tmp_path / "app.log"
            log_path.write_text("ok\nERROR database timeout\n", encoding="utf-8")
            result = run_log_check({"name": "app", "path": str(log_path), "keywords": ["ERROR"]}, tmp_path)
            self.assertEqual(result.status, "warning")
            self.assertEqual(result.details["match_count"], 1)

    def test_run_log_check_can_mark_business_log_match_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            log_path = tmp_path / "app.log"
            log_path.write_text("GET /project 500\n", encoding="utf-8")
            result = run_log_check(
                {
                    "name": "project entry log",
                    "path": str(log_path),
                    "keywords": ["GET /project 500"],
                    "status_on_match": "critical",
                    "alert_after_failures": 1,
                },
                tmp_path,
            )

        self.assertEqual(result.status, "critical")
        self.assertEqual(1, result.details["alert_after_failures"])

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
