import json
import tempfile
import unittest
from pathlib import Path

from ops_agent.config import load_config
from ops_agent.monitor_targets import apply_monitor_target_change, get_monitor_target, list_monitor_targets


class MonitorTargetsTest(unittest.TestCase):
    def test_list_monitor_targets_redacts_secret_values(self) -> None:
        raw = {
            "http_checks": [{"name": "Site", "url": "https://example.com"}],
            "json_checks": [
                {
                    "name": "Chat",
                    "url": "https://example.com/chat",
                    "json": {"api_key": "secret-value", "message": "hello"},
                }
            ],
            "server_checks": {"enabled": True},
            "database_checks": [
                {
                    "name": "MySQL",
                    "engine": "mysql",
                    "host": "db.example.com",
                    "username": "ops",
                    "password": "db-secret",
                }
            ],
        }

        result = list_monitor_targets(raw)

        self.assertEqual(3, len(result["targets"]))
        self.assertEqual("Site", result["targets"][0]["name"])
        self.assertEqual("***", result["targets"][1]["target"]["json"]["api_key"])
        self.assertTrue(result["server"]["enabled"])
        self.assertEqual("***", result["targets"][2]["target"]["password"])

    def test_apply_monitor_target_change_persists_and_updates_in_memory_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "app": {"interval_seconds": 60},
                        "alerts": {"consecutive_failures": 2, "cooldown_seconds": 300},
                        "http_checks": [{"name": "Site", "url": "https://example.com"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            config = load_config(config_path)

            disabled = apply_monitor_target_change(config, "http", 0, "disable", {"actor": "tester"})
            created = apply_monitor_target_change(
                config,
                "http",
                None,
                "create",
                {
                    "target": {
                        "name": "API",
                        "url": "https://api.example.com/health",
                        "timeout_seconds": 3,
                    }
                },
            )
            saved = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertEqual("disable", disabled["action"])
        self.assertFalse(disabled["target"]["enabled"])
        self.assertEqual("create", created["action"])
        self.assertEqual("API", created["target"]["name"])
        self.assertFalse(config.raw["http_checks"][0]["enabled"])
        self.assertEqual("API", config.raw["http_checks"][1]["name"])
        self.assertFalse(saved["http_checks"][0]["enabled"])
        self.assertEqual("API", saved["http_checks"][1]["name"])

    def test_get_server_target(self) -> None:
        result = get_monitor_target({"server_checks": {"enabled": False}}, "server")

        self.assertEqual("server", result["id"])
        self.assertFalse(result["enabled"])


if __name__ == "__main__":
    unittest.main()
