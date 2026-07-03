import json
import tempfile
import unittest
from pathlib import Path

from ops_agent.config import load_config
from ops_agent.config_center import (
    apply_config_update,
    backup_config,
    config_snapshot,
    list_config_backups,
    restore_config_backup,
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


if __name__ == "__main__":
    unittest.main()
