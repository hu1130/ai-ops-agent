import unittest
from pathlib import Path

from ops_agent.cli import validate_config
from ops_agent.config import AppConfig


class CliTest(unittest.TestCase):
    def test_validate_config_reports_bad_url(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "http_checks": [{"name": "Bad", "url": "not-a-url"}],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("http_checks[0].url" in error for error in errors))

    def test_validate_config_accepts_minimal_config(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "http_checks": [{"name": "Site", "url": "https://example.com", "timeout_seconds": 5}],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_reports_bad_context_config(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60, "environment": "prod cn"},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "retention": {"test_environments": "test"},
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("app.environment" in error for error in errors))
        self.assertTrue(any("retention.test_environments" in error for error in errors))

    def test_validate_config_accepts_container_log_check(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "log_checks": [{"name": "api", "container": "api-1"}],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_accepts_remediation_policies(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "remediation": {
                    "policies": [
                        {
                            "name": "ops-agent restart",
                            "action_type": "restart_service",
                            "enabled": True,
                            "targets": ["ops-agent"],
                            "auto_execute": False,
                            "requires_approval": True,
                            "verification_required": True,
                            "verify_after": {
                                "type": "http",
                                "url": "http://127.0.0.1:8765/api/summary",
                            },
                        }
                    ]
                },
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_reports_bad_remediation_policy(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "remediation": {
                    "policies": [
                        {
                            "enabled": "yes",
                            "targets": "ops-agent",
                            "verify_after": "http://127.0.0.1:8765/api/summary",
                        }
                    ]
                },
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("remediation.policies[0].action_type" in error for error in errors))
        self.assertTrue(any("remediation.policies[0].enabled" in error for error in errors))
        self.assertTrue(any("remediation.policies[0].targets" in error for error in errors))
        self.assertTrue(any("remediation.policies[0].verify_after" in error for error in errors))

    def test_validate_config_rejects_mutating_policy_wildcard_target(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "remediation": {
                    "policies": [
                        {
                            "action_type": "restart_service",
                            "enabled": True,
                            "targets": ["*"],
                            "requires_approval": True,
                        }
                    ]
                },
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("修改类动作不能使用 *" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
