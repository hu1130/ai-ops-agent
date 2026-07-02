import unittest

from ops_agent.ai.analyzer import analyze_incident, rule_based_analysis
from ops_agent.events import CheckResult


class AnalyzerTest(unittest.TestCase):
    def test_rule_based_analysis_mentions_http_suggestion(self) -> None:
        result = CheckResult(source="http", name="Home", status="critical", summary="Request failed")
        analysis = rule_based_analysis([result])
        self.assertIn("严重异常：1 个", analysis)
        self.assertIn("应用服务", analysis)

    def test_analyze_incident_adds_generic_classification(self) -> None:
        result = CheckResult(
            source="http",
            name="Home",
            status="warning",
            summary="primary_route_missing_fallback_reachable: primary HTTP 404; fallback reachable",
            details={
                "url": "https://example.com/healthz",
                "status_code": 404,
                "classification": "primary_route_missing_fallback_reachable",
                "fallback": {"url": "https://example.com/", "status_code": 200},
            },
        )

        analysis = analyze_incident([result], {"enabled": False})

        self.assertIn("通用异常分类", analysis)
        self.assertIn("probe_config_issue", analysis)
        self.assertIn("证据链", analysis)
        self.assertIn("AI 运维分析", analysis)


if __name__ == "__main__":
    unittest.main()
