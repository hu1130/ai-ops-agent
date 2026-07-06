import json
import os
import tempfile
import unittest
from pathlib import Path

from ops_agent.config import load_config
from ops_agent.config_center import (
    ai_repair_policy_snapshot,
    apply_config_update,
    backup_config,
    configure_deepseek_repair_model,
    config_snapshot,
    delete_project_config,
    list_config_backups,
    project_config_snapshot,
    project_repair_readiness_snapshot,
    restore_config_backup,
    update_ai_repair_policy,
    upsert_project_config,
    validate_config_candidate,
)


class ConfigCenterTest(unittest.TestCase):
    def test_apply_and_restore_config_with_secret_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "app": {"interval_seconds": 60},
                        "alerts": {"smtp_password": "mail-secret"},
                        "http_checks": [{"name": "Site", "url": "https://example.com"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            config = load_config(config_path)

            snapshot = config_snapshot(config)
            manual_backup = backup_config(config, reason="unit-test")
            candidate = json.loads(config_path.read_text(encoding="utf-8"))
            candidate["app"]["interval_seconds"] = 120
            validation = validate_config_candidate(config, candidate)
            applied = apply_config_update(config, candidate, reason="unit-test")
            restored = restore_config_backup(config, manual_backup["name"])
            backups = list_config_backups(config)
            saved = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertEqual("***", snapshot["config"]["alerts"]["smtp_password"])
        self.assertTrue(validation["valid"])
        self.assertEqual(["app"], validation["changed_sections"])
        self.assertEqual("applied", applied["status"])
        self.assertEqual("restored", restored["status"])
        self.assertEqual(60, saved["app"]["interval_seconds"])
        self.assertGreaterEqual(len(backups["backups"]), 2)

    def test_restore_rejects_non_backup_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(
                json.dumps({"app": {"interval_seconds": 60}, "http_checks": []}, ensure_ascii=False),
                encoding="utf-8",
            )
            config = load_config(config_path)

            with self.assertRaises(ValueError):
                restore_config_backup(config, "../config.json")

    def test_project_config_and_ai_repair_policy_updates_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(
                json.dumps({"app": {"interval_seconds": 60}, "http_checks": []}, ensure_ascii=False),
                encoding="utf-8",
            )
            config = load_config(config_path)

            created = upsert_project_config(
                config,
                {
                    "id": "duanshiping",
                    "name": "DuanShiping",
                    "repo_root": "/opt/duanshiping",
                    "health_urls": ["https://duanshiping.example.com/"],
                    "test_commands": ["python -m unittest discover -s tests"],
                    "repair_policy": {"auto_approve": False},
                },
                reason="unit-test-project",
            )
            projects = project_config_snapshot(config)
            policy = update_ai_repair_policy(
                config,
                {"auto_approve": True, "auto_approve_risks": ["low"], "prepare_branch": True},
                reason="unit-test-policy",
            )
            policy_snapshot = ai_repair_policy_snapshot(config)
            deepseek = configure_deepseek_repair_model(
                config,
                {"api_key_env": "DEEPSEEK_API_KEY", "model": "deepseek-v4-flash"},
                reason="unit-test-deepseek",
            )
            deleted = delete_project_config(config, "duanshiping", reason="unit-test-delete")
            saved = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertEqual("created", created["action"])
        self.assertEqual(["duanshiping"], [row["id"] for row in projects["projects"]])
        self.assertEqual("/opt/duanshiping", projects["projects"][0]["repo_root"])
        self.assertTrue(policy["policy"]["auto_approve"])
        self.assertTrue(policy_snapshot["policy"]["prepare_branch"])
        self.assertEqual("deepseek", deepseek["repair"]["provider"])
        self.assertEqual("deepseek-v4-flash", saved["ai"]["repair"]["model"])
        self.assertEqual("deleted", deleted["action"])
        self.assertEqual([], saved["projects"])

    def test_project_repair_readiness_reports_context_and_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "app"
            repo.mkdir()
            (repo / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
            (repo / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
            config = load_config(write_config(
                Path(tmp) / "config.json",
                {
                    "app": {"interval_seconds": 60},
                    "projects": [
                        {
                            "id": "app",
                            "repo_root": str(repo),
                            "repair_context_files": ["app.py", ".env"],
                            "test_commands": ["python -m py_compile app.py"],
                        },
                        {
                            "id": "unsafe",
                            "repo_root": str(repo),
                            "test_commands": ["rm -rf /tmp/nope"],
                        },
                    ],
                    "ai": {
                        "repair": {
                            "provider": "deepseek",
                            "api_key_env": "UNIT_TEST_DEEPSEEK_KEY",
                            "repository_context": {"enabled": True},
                        }
                    },
                    "http_checks": [],
                },
            ))
            old_key = os.environ.get("UNIT_TEST_DEEPSEEK_KEY")
            os.environ["UNIT_TEST_DEEPSEEK_KEY"] = "unit-test-key"
            try:
                readiness = project_repair_readiness_snapshot(config)
            finally:
                if old_key is None:
                    os.environ.pop("UNIT_TEST_DEEPSEEK_KEY", None)
                else:
                    os.environ["UNIT_TEST_DEEPSEEK_KEY"] = old_key

        by_id = {row["id"]: row for row in readiness["projects"]}
        self.assertTrue(readiness["model"]["api_key_configured"])
        self.assertEqual("ready", by_id["app"]["status"])
        self.assertEqual(["app.py"], by_id["app"]["repair_context"]["files"])
        self.assertTrue(any(item["path"] == ".env" for item in by_id["app"]["repair_context"]["skipped_files"]))
        self.assertEqual("blocked", by_id["unsafe"]["status"])
        self.assertIn("unsafe test commands are configured", by_id["unsafe"]["blockers"])

def write_config(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


if __name__ == "__main__":
    unittest.main()
