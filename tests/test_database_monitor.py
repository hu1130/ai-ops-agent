import json
import subprocess
import unittest

from ops_agent.ai.classifier import classify_incident
from ops_agent.cli import validate_config
from ops_agent.config import AppConfig
from ops_agent.monitors.database_monitor import parse_metrics, run_database_check
from pathlib import Path


def completed(payload: dict, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=json.dumps(payload), stderr=stderr)


class DatabaseMonitorTest(unittest.TestCase):
    def test_mysql_docker_check_returns_real_metrics(self) -> None:
        payload = {
            "database": "app",
            "version": "8.4.0",
            "max_connections": 100,
            "threads_connected": 12,
            "threads_running": 2,
            "slow_queries": 4,
            "uptime_seconds": 3600,
            "database_bytes": 1024,
            "read_only": 0,
        }
        commands = []

        def runner(command, **_kwargs):
            commands.append(command)
            return completed(payload)

        result = run_database_check(
            {"name": "App DB", "engine": "mysql_docker", "container": "mysql-app"},
            runner=runner,
        )

        self.assertEqual("ok", result.status)
        self.assertEqual("database", result.source)
        self.assertEqual(12.0, result.details["connection_usage_percent"])
        self.assertEqual("mysql-app", commands[0][4])
        self.assertNotIn("password", result.details)

    def test_connection_pressure_returns_warning(self) -> None:
        payload = {
            "database": "app",
            "version": "8.4.0",
            "max_connections": 100,
            "threads_connected": 90,
            "threads_running": 25,
            "slow_queries": 0,
            "uptime_seconds": 3600,
            "database_bytes": 2048,
            "read_only": 0,
        }
        result = run_database_check(
            {
                "name": "App DB",
                "engine": "mysql_docker",
                "container": "mysql-app",
                "max_connection_usage_percent": 80,
                "max_running_threads": 20,
            },
            runner=lambda *_args, **_kwargs: completed(payload),
        )

        self.assertEqual("warning", result.status)
        self.assertIn("connection usage", result.summary)
        self.assertEqual("database_pressure", result.details["classification"])

    def test_query_failure_is_critical_and_keeps_alert_policy(self) -> None:
        result = run_database_check(
            {
                "name": "App DB",
                "engine": "mysql_docker",
                "container": "mysql-app",
                "alert_after_failures": 2,
                "recovery_after_successes": 3,
            },
            runner=lambda *_args, **_kwargs: completed({}, returncode=1, stderr="connection refused"),
        )

        self.assertEqual("critical", result.status)
        self.assertIn("connection refused", result.summary)
        self.assertEqual(2, result.details["alert_after_failures"])
        self.assertEqual(3, result.details["recovery_after_successes"])

    def test_invalid_metrics_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_metrics("not-json")

    def test_database_failure_has_dedicated_classification(self) -> None:
        result = run_database_check(
            {"name": "App DB", "engine": "mysql_docker", "container": "mysql-app"},
            runner=lambda *_args, **_kwargs: completed({}, returncode=1, stderr="connection refused"),
        )
        classification = classify_incident([result])

        self.assertEqual("database_failure", classification.category)
        self.assertGreater(classification.confidence, 0.9)

    def test_database_config_requires_supported_engine_and_container(self) -> None:
        config = AppConfig(
            raw={"database_checks": [{"engine": "oracle"}]},
            base_dir=Path("."),
        )
        errors = validate_config(config)

        self.assertTrue(any("database_checks[0].engine" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
