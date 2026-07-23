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

    def test_validate_config_reports_bad_api_token_roles(self) -> None:
        config = AppConfig(
            raw={
                "app": {
                    "interval_seconds": 60,
                    "api_auth_required_for_reads": "yes",
                    "api_tokens": [
                        {"name": "bad", "token": "secret", "role": "owner"},
                    ],
                },
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("app.api_auth_required_for_reads" in error for error in errors))
        self.assertTrue(any("app.api_tokens[0].role" in error for error in errors))

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

    def test_validate_config_accepts_disabled_missing_log_path(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "log_checks": [{"name": "future log", "enabled": False, "path": "missing.log"}],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_rejects_non_boolean_log_enabled(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "log_checks": [{"name": "bad", "enabled": "no", "path": "missing.log"}],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("log_checks[0].enabled" in error for error in errors))

    def test_validate_config_accepts_docker_check(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "docker_checks": [
                    {
                        "name": "api",
                        "container": "api-1",
                        "unhealthy_status": "critical",
                        "fallback_urls": ["https://example.com/login"],
                        "fallback_success_status": "warning",
                        "alert_after_failures": 1,
                    }
                ],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_accepts_business_flow_check(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "business_flow_checks": [
                    {
                        "name": "project flow",
                        "variables": {"base_url": "https://example.com", "username": "ops", "password": "secret"},
                        "steps": [
                            {
                                "name": "login",
                                "url": "{{base_url}}/api/login",
                                "json": {"username": "{{username}}", "password": "{{password}}"},
                                "expected_status": 200,
                                "required_json_paths": ["data.token"],
                                "extract": {"token": "json:data.token"},
                            },
                            {
                                "name": "project list",
                                "method": "GET",
                                "url": "https://example.com/api/projects",
                                "headers": {"Authorization": "Bearer {{token}}"},
                                "expected_statuses": [200],
                                "required_json_paths": ["data.projects.0.id"],
                            },
                        ],
                    }
                ],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_rejects_bad_business_flow_check(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "business_flow_checks": [
                    {
                        "timeout_seconds": 0,
                        "variables": "bad",
                        "steps": [
                            {
                                "url": "not-a-url",
                                "method": "BAD",
                                "expected_statuses": ["bad"],
                                "headers": "bad",
                                "extract": "bad",
                            }
                        ],
                    }
                ],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("business_flow_checks[0].timeout_seconds" in error for error in errors))
        self.assertTrue(any("business_flow_checks[0].variables" in error for error in errors))
        self.assertTrue(any("business_flow_checks[0].steps[0].url" in error for error in errors))
        self.assertTrue(any("business_flow_checks[0].steps[0].method" in error for error in errors))
        self.assertTrue(any("business_flow_checks[0].steps[0].expected_statuses" in error for error in errors))
        self.assertTrue(any("business_flow_checks[0].steps[0].headers" in error for error in errors))
        self.assertTrue(any("business_flow_checks[0].steps[0].extract" in error for error in errors))

    def test_validate_config_rejects_bad_docker_check(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "docker_checks": [
                    {
                        "container": "",
                        "unhealthy_status": "bad",
                        "require_healthcheck": "yes",
                    }
                ],
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("docker_checks[0].container" in error for error in errors))
        self.assertTrue(any("docker_checks[0].unhealthy_status" in error for error in errors))
        self.assertTrue(any("docker_checks[0].require_healthcheck" in error for error in errors))

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

    def test_validate_config_accepts_remediation_playbook(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "remediation": {
                    "playbooks": [
                        {
                            "name": "web triage",
                            "enabled": True,
                            "on_failure": "halt",
                            "match": {"sources": ["http", "json_api"], "statuses": ["warning", "critical"]},
                            "steps": [
                                {
                                    "id": "check_target",
                                    "stage": "diagnose",
                                    "on_failure": "halt",
                                    "action_type": "check_port",
                                    "title": "检查 {{host}}:{{port}}",
                                    "reason": "web target failed",
                                    "params": {"host": "{{host}}", "port": "{{port}}"},
                                    "auto_execute": True,
                                }
                            ],
                            "rollback_steps": [
                                {
                                    "id": "inspect_after_failure",
                                    "stage": "rollback",
                                    "on_failure": "escalate",
                                    "action_type": "run_diagnostic_command",
                                    "title": "查看状态",
                                    "reason": "rollback diagnostic",
                                    "params": {"command": "systemctl status ops-agent --no-pager"},
                                }
                            ],
                        }
                    ]
                },
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_accepts_classification_rules(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "classification_rules": [
                    {
                        "name": "learned slow response",
                        "enabled": True,
                        "category": "performance_degraded",
                        "confidence": 0.8,
                        "match": {
                            "sources": ["json_api"],
                            "statuses": ["warning"],
                            "status_codes": [200],
                            "summary_contains": ["slow response"],
                        },
                        "next_steps": ["check latency"],
                    }
                ],
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_accepts_alert_routing(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {
                    "consecutive_failures": 2,
                    "cooldown_seconds": 300,
                    "default_channels": ["email"],
                    "routes": [
                        {
                            "name": "critical-email",
                            "enabled": True,
                            "match": {"severities": ["critical"], "sources": ["http"]},
                            "channels": ["email"],
                        }
                    ],
                    "silence_windows": [
                        {
                            "name": "night-warning",
                            "enabled": True,
                            "start": "00:00",
                            "end": "08:00",
                            "timezone": "+08:00",
                            "match": {"severities": ["warning"]},
                        }
                    ],
                },
            },
            base_dir=Path("."),
        )
        self.assertEqual([], validate_config(config))

    def test_validate_config_reports_bad_alert_routing(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {
                    "consecutive_failures": 2,
                    "cooldown_seconds": 300,
                    "default_channels": "email",
                    "routes": [
                        {
                            "enabled": "yes",
                            "match": {"sources": "http"},
                            "channels": "email",
                        }
                    ],
                    "silence_windows": [
                        {
                            "enabled": "yes",
                            "start": "25:00",
                            "end": "bad",
                            "timezone": "Asia/Shanghai",
                            "match": "bad",
                        }
                    ],
                },
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("alerts.default_channels" in error for error in errors))
        self.assertTrue(any("alerts.routes[0].enabled" in error for error in errors))
        self.assertTrue(any("alerts.routes[0].match.sources" in error for error in errors))
        self.assertTrue(any("alerts.routes[0].channels" in error for error in errors))
        self.assertTrue(any("alerts.silence_windows[0].enabled" in error for error in errors))
        self.assertTrue(any("alerts.silence_windows[0].start" in error for error in errors))
        self.assertTrue(any("alerts.silence_windows[0].end" in error for error in errors))
        self.assertTrue(any("alerts.silence_windows[0].timezone" in error for error in errors))
        self.assertTrue(any("alerts.silence_windows[0].match" in error for error in errors))

    def test_validate_config_reports_bad_classification_rules(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "classification_rules": [
                    {
                        "enabled": "yes",
                        "confidence": 2,
                        "match": {"sources": "json_api", "status_codes": ["bad"]},
                        "next_steps": "check",
                    }
                ],
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("classification_rules[0].enabled" in error for error in errors))
        self.assertTrue(any("classification_rules[0].category" in error for error in errors))
        self.assertTrue(any("classification_rules[0].confidence" in error for error in errors))
        self.assertTrue(any("classification_rules[0].match.sources" in error for error in errors))
        self.assertTrue(any("classification_rules[0].match.status_codes" in error for error in errors))
        self.assertTrue(any("classification_rules[0].next_steps" in error for error in errors))

    def test_validate_config_reports_bad_remediation_playbook(self) -> None:
        config = AppConfig(
            raw={
                "app": {"interval_seconds": 60},
                "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                "remediation": {
                    "playbooks": [
                        {
                            "enabled": "yes",
                            "on_failure": "bad",
                            "match": {"sources": "json_api"},
                            "steps": [
                                {
                                    "risk": "danger",
                                    "auto_execute": "yes",
                                    "params": "bad",
                                    "stage": "bad",
                                    "on_failure": "bad",
                                }
                            ],
                            "rollback_steps": "bad",
                        }
                    ]
                },
            },
            base_dir=Path("."),
        )
        errors = validate_config(config)
        self.assertTrue(any("remediation.playbooks[0].name" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].enabled" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].on_failure" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].match.sources" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].steps[0].action_type" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].steps[0].risk" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].steps[0].auto_execute" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].steps[0].params" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].steps[0].stage" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].steps[0].on_failure" in error for error in errors))
        self.assertTrue(any("remediation.playbooks[0].rollback_steps" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
