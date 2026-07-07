import unittest

from ops_agent.ai.classifier import classify_incident, format_incident_classification
from ops_agent.events import CheckResult


class IncidentClassifierTest(unittest.TestCase):
    def test_http_fallback_reachable_is_probe_config_issue(self) -> None:
        result = CheckResult(
            source="http",
            name="Website health",
            status="warning",
            summary="primary_route_missing_fallback_reachable: primary HTTP 404",
            details={
                "url": "https://example.com/healthz",
                "status_code": 404,
                "classification": "primary_route_missing_fallback_reachable",
                "fallback": {"url": "https://example.com/", "status_code": 200},
            },
        )

        classification = classify_incident([result])

        self.assertEqual(classification.category, "probe_config_issue")
        self.assertGreaterEqual(classification.confidence, 0.9)
        self.assertTrue(any("备用入口" in item for item in classification.evidence))

    def test_http_5xx_stays_service_unavailable(self) -> None:
        result = CheckResult(
            source="http",
            name="API",
            status="critical",
            summary="HTTP 500 from https://example.com/health",
            details={"url": "https://example.com/health", "status_code": 500},
        )

        classification = classify_incident([result])

        self.assertEqual(classification.category, "service_unavailable")
        self.assertGreaterEqual(classification.confidence, 0.8)

    def test_server_resource_and_http_problem_correlates_to_dependency_failure(self) -> None:
        disk = CheckResult(
            source="server",
            name="Disk usage",
            status="warning",
            summary="Disk usage 95%",
            details={"used_percent": 95, "threshold": 90},
        )
        http = CheckResult(
            source="http",
            name="Home",
            status="critical",
            summary="Request failed",
            details={"url": "https://example.com/"},
        )

        classification = classify_incident([disk, http])

        self.assertEqual(classification.category, "dependency_failure")
        self.assertIn("资源压力", classification.summary)

    def test_json_suspicious_phrase_is_synthetic_quality_failure(self) -> None:
        result = CheckResult(
            source="json_api",
            name="Synthetic chat",
            status="warning",
            summary="Response contains suspicious phrase: 暂时无法回答",
            details={"url": "https://example.com/v1/chat", "status_code": 200},
        )

        classification = classify_incident([result])

        self.assertEqual(classification.category, "synthetic_quality_fail")

    def test_docker_unhealthy_is_container_unhealthy(self) -> None:
        result = CheckResult(
            source="docker",
            name="App container",
            status="critical",
            summary="Container app-1 health unhealthy",
            details={"container": "app-1", "container_status": "running", "running": True, "health_status": "unhealthy"},
        )

        classification = classify_incident([result])

        self.assertEqual("container_unhealthy", classification.category)
        self.assertGreaterEqual(classification.confidence, 0.85)

    def test_docker_unhealthy_with_fallback_reachable_is_probe_config_issue(self) -> None:
        result = CheckResult(
            source="docker",
            name="App container",
            status="warning",
            summary="Container app-1 health unhealthy; fallback reachable",
            details={
                "container": "app-1",
                "container_status": "running",
                "running": True,
                "health_status": "unhealthy",
                "classification": "container_healthcheck_fallback_reachable",
                "fallback": {"url": "https://example.com/login", "status_code": 200},
            },
        )

        classification = classify_incident([result])

        self.assertEqual("probe_config_issue", classification.category)
        self.assertGreaterEqual(classification.confidence, 0.85)

    def test_docker_inspect_failure_is_probe_config_issue(self) -> None:
        result = CheckResult(
            source="docker",
            name="Missing container",
            status="critical",
            summary="Docker inspect failed: old-container",
            details={"container": "old-container", "error": "No such object"},
        )

        classification = classify_incident([result])

        self.assertEqual("probe_config_issue", classification.category)

    def test_configured_classification_rule_overrides_builtin_rules(self) -> None:
        result = CheckResult(
            source="json_api",
            name="Synthetic chat",
            status="warning",
            summary="Repeated learned timeout token",
            details={"url": "https://example.com/v1/chat", "status_code": 200},
        )
        rules = [
            {
                "name": "learned-timeout-token",
                "enabled": True,
                "category": "dependency_failure",
                "confidence": 0.91,
                "summary": "Configured learned rule matched.",
                "match": {
                    "sources": ["json_api"],
                    "statuses": ["warning"],
                    "summary_contains": ["learned timeout"],
                },
            }
        ]

        classification = classify_incident([result], rules)

        self.assertEqual("dependency_failure", classification.category)
        self.assertEqual(0.91, classification.confidence)
        self.assertTrue(any("configured_rule=learned-timeout-token" in item for item in classification.evidence))

    def test_format_includes_evidence_chain(self) -> None:
        result = CheckResult(source="log", name="App log", status="warning", summary="Found 2 suspicious log lines")
        text = format_incident_classification(classify_incident([result]))

        self.assertIn("通用异常分类", text)
        self.assertIn("证据链", text)
        self.assertIn("下一步动作", text)


if __name__ == "__main__":
    unittest.main()
