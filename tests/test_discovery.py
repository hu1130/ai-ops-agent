import json
import subprocess
import unittest

from pathlib import Path

from ops_agent.ai.classifier import classify_incident
from ops_agent.cli import validate_config
from ops_agent.config import AppConfig
from ops_agent.discovery import discover_runtime_assets, run_asset_discovery_check


def docker_result(rows: list[dict], returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    output = "\n".join(json.dumps(row) for row in rows)
    return subprocess.CompletedProcess([], returncode, stdout=output, stderr=stderr)


class RuntimeDiscoveryTest(unittest.TestCase):
    def test_compose_identity_covers_recreated_container_with_generated_prefix(self) -> None:
        rows = [
            {
                "Names": "40d66a351638_ai-customer-service-semp-api-1",
                "Image": "ai-customer-service-semp-api:latest",
                "State": "running",
                "Ports": "8000/tcp",
                "Labels": (
                    "com.docker.compose.project=ai-customer-service,"
                    "com.docker.compose.service=semp-api"
                ),
            }
        ]
        config = {
            "docker_checks": [
                {
                    "container": "ai-customer-service-semp-api-1",
                    "project_id": "ai-customer-service",
                    "compose_service": "semp-api",
                }
            ],
            "asset_discovery": {"enabled": True},
        }

        result = discover_runtime_assets(config, runner=lambda *_args, **_kwargs: docker_result(rows))

        self.assertEqual("ok", result["status"])
        self.assertEqual(0, result["summary"]["unmonitored_applications"])
        self.assertEqual(1, result["summary"]["covered"])

    def test_discovers_unmonitored_application_and_ignores_infrastructure_and_disabled_project(self) -> None:
        rows = [
            {"Names": "known-api", "Image": "known-api", "State": "running", "Ports": "8000/tcp"},
            {"Names": "new-api", "Image": "new-api", "State": "running", "Ports": "9000/tcp"},
            {"Names": "app-mysql", "Image": "mysql:8.4", "State": "running", "Ports": "3306/tcp"},
            {"Names": "old-project-app", "Image": "old-project", "State": "running", "Ports": "5000/tcp"},
        ]
        config = {
            "docker_checks": [{"container": "known-api"}],
            "projects": [{"id": "old-project", "enabled": False}],
            "asset_discovery": {"enabled": True},
        }

        result = discover_runtime_assets(config, runner=lambda *_args, **_kwargs: docker_result(rows))

        self.assertEqual(1, result["summary"]["unmonitored_applications"])
        self.assertEqual("new-api", result["unmonitored_applications"][0]["name"])
        reasons = {item["name"]: item["reason"] for item in result["ignored_assets"]}
        self.assertEqual("infrastructure_container", reasons["app-mysql"])
        self.assertEqual("disabled_project:old-project", reasons["old-project-app"])

    def test_public_port_without_application_name_is_candidate(self) -> None:
        rows = [
            {
                "Names": "custom",
                "Image": "company/custom",
                "State": "running",
                "Ports": "0.0.0.0:8088->8080/tcp",
            }
        ]
        result = discover_runtime_assets(
            {"asset_discovery": {"enabled": True}},
            runner=lambda *_args, **_kwargs: docker_result(rows),
        )

        self.assertEqual("custom", result["unmonitored_applications"][0]["name"])

    def test_discovery_check_returns_warning_and_alert_thresholds(self) -> None:
        rows = [{"Names": "new-backend", "Image": "new-backend", "State": "running", "Ports": "8000/tcp"}]
        config = {
            "asset_discovery": {
                "enabled": True,
                "alert_after_failures": 2,
                "recovery_after_successes": 3,
            }
        }
        result = run_asset_discovery_check(config, runner=lambda *_args, **_kwargs: docker_result(rows))

        self.assertEqual("warning", result.status)
        self.assertEqual("discovery", result.source)
        self.assertEqual(2, result.details["alert_after_failures"])
        self.assertEqual(3, result.details["recovery_after_successes"])

    def test_docker_failure_is_reported_without_exception(self) -> None:
        result = discover_runtime_assets(
            {"asset_discovery": {"enabled": True}},
            runner=lambda *_args, **_kwargs: docker_result([], returncode=1, stderr="permission denied"),
        )

        self.assertEqual("warning", result["status"])
        self.assertIn("permission denied", result["error"])

    def test_coverage_gap_has_dedicated_classification(self) -> None:
        rows = [{"Names": "new-api", "Image": "new-api", "State": "running", "Ports": "8000/tcp"}]
        result = run_asset_discovery_check(
            {"asset_discovery": {"enabled": True}},
            runner=lambda *_args, **_kwargs: docker_result(rows),
        )
        classification = classify_incident([result])

        self.assertEqual("monitor_coverage_gap", classification.category)
        self.assertGreaterEqual(classification.confidence, 0.9)

    def test_discovery_config_rejects_zero_interval(self) -> None:
        config = AppConfig(raw={"asset_discovery": {"enabled": True, "interval_seconds": 0}}, base_dir=Path("."))
        errors = validate_config(config)

        self.assertTrue(any("asset_discovery.interval_seconds" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
