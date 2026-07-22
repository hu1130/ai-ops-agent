import tempfile
import unittest
from pathlib import Path

from ops_agent.ai.repair import ai_repair_policy_from_config
from ops_agent.config import AppConfig
from ops_agent.project_capabilities import ensure_project_action_allowed, project_capability_snapshot


class ProjectCapabilitiesTest(unittest.TestCase):
    def test_ignored_project_is_a_valid_non_monitoring_state(self) -> None:
        project = {
            "id": "retired",
            "enabled": False,
            "management_mode": "ignored",
            "automation_level": "monitor_only",
            "automation_level_configured": True,
        }

        result = project_capability_snapshot(AppConfig(raw={}, base_dir=Path(".")), project)

        self.assertTrue(result["ready"])
        self.assertEqual([], result["blockers"])

    def test_disabled_legacy_project_with_monitor_is_observe_only(self) -> None:
        project = {
            "id": "readonly",
            "enabled": False,
            "management_mode": "managed",
            "management_mode_configured": False,
            "automation_level": "",
        }
        config = AppConfig(
            raw={"docker_checks": [{"project_id": "readonly", "container": "readonly-api-1", "enabled": True}]},
            base_dir=Path("."),
        )

        result = project_capability_snapshot(config, project)

        self.assertEqual("observe_only", result["management_mode"])
        self.assertEqual("monitor_only", result["effective_level"])
        self.assertTrue(result["ready"])

    def test_repository_unlocks_code_suggestion_but_not_pull_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            config = AppConfig(raw={}, base_dir=Path(tmp))
            project = {
                "id": "sales",
                "enabled": True,
                "management_mode": "managed",
                "automation_level": "code_suggest",
                "automation_level_configured": True,
                "repo_root": str(repo),
                "discovery_bindings": {"containers": ["sales-api-1"]},
            }

            result = project_capability_snapshot(config, project)

            self.assertTrue(result["available"]["code_suggest"])
            self.assertFalse(result["available"]["pull_request"])
            self.assertTrue(result["ready"])

    def test_level_gate_blocks_actions_above_selected_level(self) -> None:
        project = {"automation_level": "code_suggest", "automation_level_configured": True}

        ensure_project_action_allowed(project, "sandbox-test")
        with self.assertRaisesRegex(ValueError, "required level is pull_request"):
            ensure_project_action_allowed(project, "create-pr")

    def test_legacy_project_keeps_existing_repair_policy(self) -> None:
        config = AppConfig(
            raw={"ai": {"repair": {"policy": {"enabled": True, "prepare_branch": True, "create_pr": True}}}},
            base_dir=Path("."),
        )
        policy = ai_repair_policy_from_config(config, {"id": "legacy", "repair_policy": {}})

        self.assertTrue(policy["enabled"])
        self.assertTrue(policy["prepare_branch"])
        self.assertTrue(policy["create_pr"])

    def test_monitor_only_disables_ai_repair_policy(self) -> None:
        config = AppConfig(
            raw={"ai": {"repair": {"policy": {"enabled": True, "prepare_branch": True, "create_pr": True}}}},
            base_dir=Path("."),
        )
        project = {"id": "readonly", "automation_level": "monitor_only", "automation_level_configured": True}

        policy = ai_repair_policy_from_config(config, project)

        self.assertFalse(policy["enabled"])
        self.assertFalse(policy["prepare_branch"])
        self.assertFalse(policy["create_pr"])


if __name__ == "__main__":
    unittest.main()
