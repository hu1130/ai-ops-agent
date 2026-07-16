import socket
import tempfile
import unittest
from pathlib import Path

from ops_agent.config import AppConfig
from ops_agent.diagnosis import persist_incident_diagnosis
from ops_agent.events import CheckResult
from ops_agent.operator_workflow import (
    build_operator_guide,
    build_operator_inbox,
    execute_primary_operator_action,
)
from ops_agent.storage import Storage


class OperatorWorkflowTest(unittest.TestCase):
    def test_new_incident_has_one_plain_language_primary_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "critical",
                "Site unavailable",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
                classification={
                    "category": "service_unavailable",
                    "confidence": 0.9,
                    "summary": "网站返回 500",
                    "evidence": [],
                    "next_steps": [],
                },
            )
            guide = build_operator_guide(storage, AppConfig(raw={}, base_dir=Path(tmp)), incident_id)
            storage.close()

        self.assertEqual("让系统继续诊断", guide["primary_action"]["label"])
        self.assertEqual("run_diagnosis", guide["primary_action"]["kind"])
        self.assertFalse(guide["primary_action"]["changes_system"])
        self.assertIn("可能已经影响用户", guide["business_impact"])

    def test_safe_recommendation_becomes_primary_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Check target",
                "analysis",
                [CheckResult(source="http", name="Site", status="warning", summary="Slow")],
            )
            storage.save_incident_recommendations(
                incident_id,
                [
                    {
                        "position": 1,
                        "category": "diagnose",
                        "action_type": "check_port",
                        "title": "检查网站端口",
                        "reason": "确认端口是否可连接",
                        "risk": "low",
                        "status": "suggested",
                        "params": {"host": "example.com", "port": 443},
                    }
                ],
            )
            guide = build_operator_guide(storage, AppConfig(raw={}, base_dir=Path(tmp)), incident_id)
            storage.close()

        self.assertEqual("execute_recommendation", guide["primary_action"]["kind"])
        self.assertIn("检查网站端口", guide["primary_action"]["label"])
        self.assertFalse(guide["primary_action"]["changes_system"])

    def test_lower_risk_recommendation_is_selected_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "warning",
                "Check target",
                "analysis",
                [CheckResult(source="http", name="Site", status="warning", summary="Slow")],
            )
            storage.save_incident_recommendations(
                incident_id,
                [
                    {
                        "position": 1,
                        "action_type": "check_port",
                        "title": "高风险排查",
                        "reason": "test",
                        "risk": "high",
                        "status": "suggested",
                        "params": {"host": "example.com", "port": 443},
                    },
                    {
                        "position": 2,
                        "action_type": "check_port",
                        "title": "低风险排查",
                        "reason": "test",
                        "risk": "low",
                        "status": "suggested",
                        "params": {"host": "example.com", "port": 443},
                    },
                ],
            )
            guide = build_operator_guide(storage, AppConfig(raw={}, base_dir=Path(tmp)), incident_id)
            storage.close()

        self.assertIn("低风险排查", guide["primary_action"]["label"])

    def test_blocked_mutating_recommendation_is_not_exposed_for_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "critical",
                "Service down",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="HTTP 500")],
            )
            storage.save_incident_recommendations(
                incident_id,
                [
                    {
                        "position": 1,
                        "category": "remediate",
                        "action_type": "restart_service",
                        "title": "重启网站服务",
                        "reason": "服务不可用",
                        "risk": "medium",
                        "status": "suggested",
                        "approval_required": True,
                        "verification_required": True,
                        "params": {"service": "website", "verify_after": {"type": "service", "service": "website"}},
                    }
                ],
            )
            config = AppConfig(
                raw={
                    "remediation": {
                        "policies": [
                            {
                                "name": "website restart",
                                "action_type": "restart_service",
                                "targets": ["website"],
                                "enabled": True,
                                "requires_approval": True,
                                "verification_required": True,
                            }
                        ]
                    }
                },
                base_dir=Path(tmp),
            )
            guide = build_operator_guide(storage, config, incident_id)
            storage.close()

        self.assertEqual("run_diagnosis", guide["primary_action"]["kind"])
        self.assertTrue(guide["blockers"])

    def test_acknowledge_watch_closes_the_human_todo_without_closing_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            config = AppConfig(raw={}, base_dir=Path(tmp))
            incident_id = storage.save_incident(
                "warning",
                "Slow response",
                "analysis",
                [CheckResult(source="json_api", name="Chat", status="warning", summary="Slow response")],
            )
            persist_incident_diagnosis(storage, config, incident_id)
            before = build_operator_guide(storage, config, incident_id)
            result = execute_primary_operator_action(storage, config, incident_id, actor="owner")
            comments = storage.latest_incident_comments(incident_id)
            incident = storage.get_incident(incident_id)
            storage.close()

        self.assertEqual("acknowledge_watch", before["primary_action"]["kind"])
        self.assertEqual("waiting", result["status"])
        self.assertEqual("acknowledged", incident["status"])
        self.assertEqual(1, len(comments))

    def test_inbox_prioritizes_critical_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            warning_id = storage.save_incident(
                "warning",
                "Slow",
                "analysis",
                [CheckResult(source="http", name="Slow", status="warning", summary="Slow")],
            )
            critical_id = storage.save_incident(
                "critical",
                "Down",
                "analysis",
                [CheckResult(source="http", name="Down", status="critical", summary="HTTP 500")],
            )
            inbox = build_operator_inbox(storage, AppConfig(raw={}, base_dir=Path(tmp)))
            storage.close()

        self.assertEqual(2, inbox["summary"]["total"])
        self.assertEqual(critical_id, inbox["items"][0]["incident_id"])
        self.assertEqual({warning_id, critical_id}, {item["incident_id"] for item in inbox["items"]})

    def test_primary_recommendation_executes_successfully(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                storage = Storage(Path(tmp) / "ops.db")
                incident_id = storage.save_incident(
                    "warning",
                    "Port check",
                    "analysis",
                    [CheckResult(source="http", name="Site", status="warning", summary="Slow")],
                )
                storage.save_incident_recommendations(
                    incident_id,
                    [
                        {
                            "position": 1,
                            "category": "diagnose",
                            "action_type": "check_port",
                            "title": "检查本地端口",
                            "reason": "确认服务端口",
                            "risk": "low",
                            "status": "suggested",
                            "params": {"host": "127.0.0.1", "port": port},
                        }
                    ],
                )
                result = execute_primary_operator_action(
                    storage,
                    AppConfig(raw={}, base_dir=Path(tmp)),
                    incident_id,
                    actor="owner",
                )
                storage.close()
        finally:
            listener.close()

        self.assertEqual("completed", result["status"])
        self.assertEqual("executed", result["execution"]["action"]["result"]["status"])

    def test_failed_primary_recommendation_stops_and_hands_off(self) -> None:
        unused = socket.socket()
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
        unused.close()
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "ops.db")
            incident_id = storage.save_incident(
                "critical",
                "Port down",
                "analysis",
                [CheckResult(source="http", name="Site", status="critical", summary="Request failed")],
            )
            storage.save_incident_recommendations(
                incident_id,
                [
                    {
                        "position": 1,
                        "category": "diagnose",
                        "action_type": "check_port",
                        "title": "检查关闭端口",
                        "reason": "确认服务端口",
                        "risk": "low",
                        "status": "suggested",
                        "params": {"host": "127.0.0.1", "port": port, "timeout_seconds": 1},
                    }
                ],
            )
            result = execute_primary_operator_action(
                storage,
                AppConfig(raw={}, base_dir=Path(tmp)),
                incident_id,
                actor="owner",
            )
            guide = build_operator_guide(storage, AppConfig(raw={}, base_dir=Path(tmp)), incident_id)
            storage.close()

        self.assertEqual("needs_manual", result["status"])
        self.assertEqual("failed", result["execution"]["action"]["result"]["status"])
        self.assertEqual("manual_handoff", guide["primary_action"]["kind"])
        self.assertIn("停止重试", guide["primary_action"]["reason"])


if __name__ == "__main__":
    unittest.main()
