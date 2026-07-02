import unittest
from datetime import datetime, timezone

from ops_agent.alerts.routing import (
    alert_context_from_results,
    in_silence_window,
    route_alert,
    routed_dedupe_key,
)
from ops_agent.events import CheckResult


class AlertRoutingTest(unittest.TestCase):
    def test_routes_alert_by_source_and_category(self) -> None:
        result = CheckResult(
            source="json_api",
            name="AI chat",
            status="warning",
            summary="Slow response: 14402 ms",
            details={"latency_ms": 14402, "max_latency_ms": 10000},
        )
        context = alert_context_from_results([result], title="Ops Agent detected 1 issue(s)")
        decision = route_alert(
            {
                "routes": [
                    {
                        "name": "ai-owner",
                        "match": {
                            "sources": ["json_api"],
                            "categories": ["performance_degraded"],
                        },
                        "channels": ["email"],
                    }
                ]
            },
            context,
        )

        self.assertFalse(decision.suppressed)
        self.assertEqual(["ai-owner"], decision.route_names)
        self.assertEqual(["email"], decision.channels)
        self.assertEqual("base|route:ai-owner:email", routed_dedupe_key("base", decision))

    def test_silence_window_matches_overnight_range(self) -> None:
        window = {
            "start": "22:00",
            "end": "08:00",
            "timezone": "+08:00",
        }
        now = datetime(2026, 7, 2, 17, 30, tzinfo=timezone.utc)

        self.assertTrue(in_silence_window(window, now))

    def test_silence_window_suppresses_matching_warning(self) -> None:
        result = CheckResult(source="http", name="Site", status="warning", summary="Slow")
        context = alert_context_from_results([result], title="Ops Agent detected 1 issue(s)")
        decision = route_alert(
            {
                "silence_windows": [
                    {
                        "name": "all-day-warning",
                        "start": "00:00",
                        "end": "00:00",
                        "timezone": "+00:00",
                        "match": {"severities": ["warning"]},
                    }
                ]
            },
            context,
            now=datetime(2026, 7, 2, 12, 0, tzinfo=timezone.utc),
        )

        self.assertTrue(decision.suppressed)
        self.assertIn("all-day-warning", decision.reason)


if __name__ == "__main__":
    unittest.main()
