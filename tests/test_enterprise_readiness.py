import unittest
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.enterprise import enterprise_readiness_snapshot, format_enterprise_readiness


class EnterpriseReadinessTest(unittest.TestCase):
    def test_detects_disabled_project_with_enabled_monitor_target(self) -> None:
        config = AppConfig(
            raw={
                "app": {"database_path": "data/ops_agent.db", "api_token": "token"},
                "projects": [
                    {
                        "id": "duanshiping",
                        "name": "DuanShiping",
                        "enabled": False,
                        "health_urls": ["https://duanshiping.example.com/login"],
                    }
                ],
                "http_checks": [
                    {
                        "name": "DuanShiping health",
                        "url": "https://duanshiping.example.com/login",
                        "enabled": True,
                    }
                ],
                "alerts": {"email": {"enabled": True}},
                "remediation": {"enabled": True, "policies": []},
            },
            base_dir=Path("."),
        )

        snapshot = enterprise_readiness_snapshot(config)
        drift = check_by_name(snapshot, "disabled_project_monitor_drift")

        self.assertEqual("blocker", drift["status"])
        self.assertEqual("duanshiping", drift["detail"]["matches"][0]["project_id"])

    def test_detects_unsafe_auto_execute_mutating_policy(self) -> None:
        config = AppConfig(
            raw={
                "app": {"database_path": "data/ops_agent.db", "api_token": "token"},
                "projects": [{"id": "app", "name": "App", "health_urls": ["https://app.example.com/health"]}],
                "http_checks": [{"name": "App health", "url": "https://app.example.com/health"}],
                "alerts": {"email": {"enabled": True}},
                "remediation": {
                    "enabled": True,
                    "verification": {"enabled": False},
                    "policies": [
                        {
                            "name": "unsafe restart",
                            "action_type": "restart_service",
                            "targets": ["app"],
                            "enabled": True,
                            "auto_execute": True,
                            "requires_approval": False,
                            "verification_required": False,
                        }
                    ],
                },
            },
            base_dir=Path("."),
        )

        snapshot = enterprise_readiness_snapshot(config)
        guardrail = check_by_name(snapshot, "mutating_action_guardrails")

        self.assertEqual("blocker", guardrail["status"])
        self.assertEqual("unsafe restart", guardrail["detail"]["unsafe_policies"][0]["name"])

    def test_ready_foundation_formats_summary(self) -> None:
        config = AppConfig(
            raw={
                "app": {
                    "database_path": "data/ops_agent.db",
                    "api_tokens": [{"name": "ops", "token": "secret", "role": "admin"}],
                },
                "projects": [
                    {
                        "id": "app",
                        "name": "App",
                        "health_urls": ["https://app.example.com/health"],
                        "test_commands": ["python -m unittest discover -s tests"],
                    }
                ],
                "http_checks": [{"name": "App health", "url": "https://app.example.com/health"}],
                "alerts": {
                    "email": {"enabled": True},
                    "repeat_notification_enabled": True,
                    "repeat_notification_interval_seconds": 3600,
                    "escalation_enabled": True,
                },
                "retention": {"enabled": True, "api_audit_logs_days": 180, "notification_logs_days": 180},
                "ai": {
                    "repair": {
                        "provider": "rules",
                        "policy": {"auto_approve": False},
                        "auto_trigger": {"enabled": False, "run_dry_run": True},
                    }
                },
                "remediation": {
                    "enabled": True,
                    "verification": {"enabled": True},
                    "guardrails": {"verification_required_for_mutating": True},
                    "playbooks": [{"name": "web triage", "enabled": True}],
                    "policies": [
                        {"name": "port", "action_type": "check_port", "targets": ["*"], "enabled": True},
                        {
                            "name": "restart app",
                            "action_type": "restart_service",
                            "targets": ["app"],
                            "enabled": True,
                            "auto_execute": False,
                            "requires_approval": True,
                            "verification_required": True,
                        },
                    ],
                },
            },
            base_dir=Path("."),
        )

        snapshot = enterprise_readiness_snapshot(config)
        text = format_enterprise_readiness(snapshot)

        self.assertNotEqual("not_enterprise_ready", snapshot["status"])
        self.assertIn("Enterprise readiness:", text)
        self.assertEqual("pass", check_by_name(snapshot, "api_authentication")["status"])

    def test_resilience_features_are_in_enterprise_readiness(self) -> None:
        config = AppConfig(
            raw={
                "database_checks": [{"name": "DB", "engine": "mysql_docker", "container": "mysql"}],
                "asset_discovery": {"enabled": True},
                "backups": {
                    "enabled": True,
                    "targets": [
                        {
                            "id": "db",
                            "engine": "mysql_docker",
                            "container": "mysql",
                            "restore_drill": {"enabled": True},
                        }
                    ],
                },
            },
            base_dir=Path("."),
        )

        snapshot = enterprise_readiness_snapshot(config)

        self.assertEqual("pass", check_by_name(snapshot, "database_monitoring")["status"])
        self.assertEqual("pass", check_by_name(snapshot, "runtime_asset_discovery")["status"])
        self.assertEqual("pass", check_by_name(snapshot, "backup_policy")["status"])
        self.assertEqual("pass", check_by_name(snapshot, "restore_drill_policy")["status"])


def check_by_name(snapshot: dict, name: str) -> dict:
    return next(check for check in snapshot["checks"] if check["name"] == name)


if __name__ == "__main__":
    unittest.main()
