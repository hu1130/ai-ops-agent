import json
import subprocess
import unittest
from unittest.mock import patch

from ops_agent.monitors.docker_monitor import run_docker_check


class DockerMonitorTest(unittest.TestCase):
    @patch("ops_agent.monitors.docker_monitor.subprocess.run")
    def test_resolves_recreated_compose_container_by_project_and_service(self, run) -> None:
        missing = subprocess.CompletedProcess([], 1, stdout="", stderr="No such container")
        listing = subprocess.CompletedProcess(
            [],
            0,
            stdout=json.dumps(
                {
                    "Names": "40d66a351638_ai-customer-service-semp-api-1",
                    "Image": "ai-customer-service-semp-api:latest",
                    "State": "running",
                    "Status": "Up 1 minute",
                    "Labels": (
                        "com.docker.compose.project=ai-customer-service,"
                        "com.docker.compose.service=semp-api"
                    ),
                }
            ),
            stderr="",
        )
        healthy = subprocess.CompletedProcess(
            [],
            0,
            stdout=json.dumps({"Status": "running", "Running": True}),
            stderr="",
        )
        run.side_effect = [missing, listing, healthy]

        result = run_docker_check(
            {
                "name": "secondary API",
                "container": "ai-customer-service-semp-api-1",
                "project_id": "ai-customer-service",
                "compose_service": "semp-api",
            }
        )

        self.assertEqual("ok", result.status)
        self.assertEqual("40d66a351638_ai-customer-service-semp-api-1", result.details["container"])
        self.assertEqual("generated_name_suffix", result.details["container_resolution"]["resolution_source"])

    @patch("ops_agent.monitors.docker_monitor.subprocess.run")
    def test_running_healthy_container_is_ok(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(
            {"Status": "running", "Running": True, "Health": {"Status": "healthy"}}
        )
        run.return_value.stderr = ""

        result = run_docker_check({"name": "api", "container": "api-1"})

        self.assertEqual("ok", result.status)
        self.assertIn("health healthy", result.summary)
        self.assertEqual("api-1", result.details["container"])

    @patch("ops_agent.monitors.docker_monitor.subprocess.run")
    def test_unhealthy_container_is_critical_with_alert_threshold(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(
            {"Status": "running", "Running": True, "Health": {"Status": "unhealthy"}}
        )
        run.return_value.stderr = ""

        result = run_docker_check({"name": "api", "container": "api-1", "alert_after_failures": 1})

        self.assertEqual("critical", result.status)
        self.assertIn("health unhealthy", result.summary)
        self.assertEqual(1, result.details["alert_after_failures"])

    @patch("ops_agent.monitors.docker_monitor.probe_url")
    @patch("ops_agent.monitors.docker_monitor.subprocess.run")
    def test_unhealthy_container_with_reachable_fallback_is_warning(self, run, probe_url) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps(
            {"Status": "running", "Running": True, "Health": {"Status": "unhealthy"}}
        )
        run.return_value.stderr = ""
        probe_url.return_value = {"url": "https://example.com/login", "status_code": 200, "reachable": True}

        result = run_docker_check(
            {
                "name": "app",
                "container": "app-1",
                "fallback_urls": ["https://example.com/login"],
                "fallback_success_status": "warning",
            }
        )

        self.assertEqual("warning", result.status)
        self.assertIn("fallback reachable", result.summary)
        self.assertEqual("container_healthcheck_fallback_reachable", result.details["classification"])

    @patch("ops_agent.monitors.docker_monitor.subprocess.run")
    def test_exited_container_is_critical(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({"Status": "exited", "Running": False, "ExitCode": 1})
        run.return_value.stderr = ""

        result = run_docker_check({"name": "worker", "container": "worker-1"})

        self.assertEqual("critical", result.status)
        self.assertIn("status exited", result.summary)
        self.assertEqual(1, result.details["exit_code"])

    @patch("ops_agent.monitors.docker_monitor.subprocess.run")
    def test_missing_healthcheck_can_be_warning_when_required(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({"Status": "running", "Running": True})
        run.return_value.stderr = ""

        result = run_docker_check({"name": "api", "container": "api-1", "require_healthcheck": True})

        self.assertEqual("warning", result.status)
        self.assertIn("no Docker healthcheck", result.summary)


if __name__ == "__main__":
    unittest.main()
