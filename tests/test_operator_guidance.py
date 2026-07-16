import unittest

from ops_agent.ai.classifier import IncidentClassification
from ops_agent.events import CheckResult
from ops_agent.operator_guidance import build_operator_brief
from ops_agent.remediation.actions import ActionResult, RemediationAction


class OperatorGuidanceTest(unittest.TestCase):
    def test_warning_tells_owner_to_wait_for_retest(self) -> None:
        text = build_operator_brief(
            [CheckResult(source="json_api", name="Chat", status="warning", summary="Slow response")],
            IncidentClassification("performance_degraded", 0.82, "响应变慢"),
            [],
            {},
            incident_id=12,
            recovery_after_successes=2,
        )

        self.assertIn("事件编号: #12", text)
        self.assertIn("暂时不用操作", text)
        self.assertIn("没有执行重启、配置修改或代码修改", text)
        self.assertIn("连续 2 次正常后才会通知恢复", text)

    def test_critical_issue_requires_owner_attention(self) -> None:
        text = build_operator_brief(
            [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            IncidentClassification("service_unavailable", 0.9, "服务不可用"),
            [],
            {},
            incident_id=7,
            recovery_after_successes=2,
        )

        self.assertIn("可能已经影响用户访问或核心业务流程", text)
        self.assertIn("需要处理", text)

    def test_ai_repair_waiting_for_review_says_code_was_not_changed(self) -> None:
        text = build_operator_brief(
            [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            IncidentClassification("service_unavailable", 0.9, "服务不可用"),
            [],
            {"status": "dry_run_passed"},
            incident_id=8,
            recovery_after_successes=2,
        )

        self.assertIn("需要处理", text)
        self.assertIn("审核修复建议", text)
        self.assertIn("尚未修改代码", text)

    def test_failed_automatic_action_requests_human_help(self) -> None:
        action = RemediationAction(
            action_type="restart_service",
            title="重启网站服务",
            reason="服务不可用",
        )
        text = build_operator_brief(
            [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            IncidentClassification("service_unavailable", 0.9, "服务不可用"),
            [ActionResult(action=action, status="verified_failed", error="still unavailable")],
            {},
            incident_id=9,
            recovery_after_successes=2,
        )

        self.assertIn("自动处置没有成功", text)
        self.assertIn("需要人工处理", text)


if __name__ == "__main__":
    unittest.main()
