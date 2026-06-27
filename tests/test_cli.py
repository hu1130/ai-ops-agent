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


if __name__ == "__main__":
    unittest.main()
