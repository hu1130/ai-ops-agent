import unittest

from ops_agent.ai.analyzer import rule_based_analysis
from ops_agent.events import CheckResult


class AnalyzerTest(unittest.TestCase):
    def test_rule_based_analysis_mentions_http_suggestion(self) -> None:
        result = CheckResult(source="http", name="Home", status="critical", summary="Request failed")
        analysis = rule_based_analysis([result])
        self.assertIn("严重异常：1", analysis)
        self.assertIn("应用服务", analysis)


if __name__ == "__main__":
    unittest.main()
