import tempfile
import unittest
from pathlib import Path

from ops_agent.monitors.log_monitor import run_log_check


class LogMonitorTest(unittest.TestCase):
    def test_run_log_check_finds_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            log_path = tmp_path / "app.log"
            log_path.write_text("ok\nERROR database timeout\n", encoding="utf-8")
            result = run_log_check({"name": "app", "path": str(log_path), "keywords": ["ERROR"]}, tmp_path)
            self.assertEqual(result.status, "warning")
            self.assertEqual(result.details["match_count"], 1)


if __name__ == "__main__":
    unittest.main()
