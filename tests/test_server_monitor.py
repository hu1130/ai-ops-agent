import unittest

from ops_agent.monitors.server_monitor import memory_summary, parse_percent, parse_ps_top_processes


class ServerMonitorTest(unittest.TestCase):
    def test_memory_summary_includes_top_processes_for_warning(self) -> None:
        text = memory_summary(
            88.5,
            512 * 1024 * 1024,
            {"top_processes": [{"name": "mysqld", "rss_mib": 700.1}]},
            "warning",
        )

        self.assertIn("Memory usage 88.5%", text)
        self.assertIn("available 512.0MiB", text)
        self.assertIn("mysqld 700.1MiB", text)

    def test_parse_percent_handles_bad_values(self) -> None:
        self.assertEqual(4.5, parse_percent("4.5%"))
        self.assertEqual(0.0, parse_percent("bad"))

    def test_parse_ps_top_processes(self) -> None:
        rows = parse_ps_top_processes(
            """
            11 mysqld 716800 9.4
            12 python 102400 1.3
            """,
            1,
        )

        self.assertEqual(1, len(rows))
        self.assertEqual("mysqld", rows[0]["name"])
        self.assertEqual(700.0, rows[0]["rss_mib"])


if __name__ == "__main__":
    unittest.main()
