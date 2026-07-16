from __future__ import annotations

from typing import Any

from ops_agent.ai.classifier import CATEGORY_LABELS
from ops_agent.ai.repair import ai_repair_approval_queue_item, run_ai_repair_queue_next_action
from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig
from ops_agent.diagnosis import persist_incident_diagnosis
from ops_agent.operator_guidance import business_impact
from ops_agent.remediation.playbook_center import (
    create_incident_playbook_recommendations,
    preview_incident_playbooks,
)
from ops_agent.remediation.readiness import incident_self_heal_readiness
from ops_agent.remediation.recommendations import approve_recommendation
from ops_agent.storage import Storage


ACTIVE_RECOMMENDATION_STATUSES = {"suggested", "dry_run", "pending_approval"}
FAILED_ACTION_STATUSES = {"failed", "verified_failed", "skipped"}
DONE_INCIDENT_STATUSES = {"resolved", "closed"}
AI_ACTION_LABELS = {
    "dry-run": "检查 AI 修复方案",
    "sandbox-test": "在沙箱测试 AI 修复方案",
    "approve": "批准 AI 修复方案",
    "prepare-branch": "准备安全修复分支",
    "create-pr": "创建修复审核单",
    "deploy-merged": "部署并验证已合并修复",
}
AI_ACTION_PRIORITY = {
    "dry-run": 20,
    "sandbox-test": 25,
    "approve": 35,
    "prepare-branch": 40,
    "create-pr": 45,
    "deploy-merged": 50,
}
RISK_PRIORITY = {"low": 0, "medium": 1, "high": 2}


def build_operator_inbox(storage: Storage, config: AppConfig | None, limit: int = 50) -> dict[str, Any]:
    incidents = [
        incident
        for incident in storage.latest_incidents(max(limit * 4, 100))
        if str(incident.get("status") or "") not in DONE_INCIDENT_STATUSES
        and str(incident.get("severity") or "") != "ok"
        and not bool(incident.get("false_positive"))
    ]
    items = [build_operator_guide(storage, config, int(incident["id"])) for incident in incidents]
    items.sort(key=inbox_sort_key)
    items = items[: max(1, min(int(limit or 50), 200))]
    return {
        "mode": "operator_inbox",
        "summary": {
            "total": len(items),
            "need_action": sum(1 for item in items if item["needs_human_action"]),
            "critical": sum(1 for item in items if item["severity"] == "critical"),
            "ready_to_execute": sum(1 for item in items if item["primary_action"]["executable"]),
            "waiting": sum(1 for item in items if item["state"] == "waiting"),
        },
        "items": items,
    }


def build_operator_guide(storage: Storage, config: AppConfig | None, incident_id: int) -> dict[str, Any]:
    incident = storage.get_incident(incident_id)
    if not incident:
        raise ValueError(f"incident not found: {incident_id}")

    diagnoses = storage.latest_incident_diagnoses(incident_id, limit=1)
    diagnosis = diagnoses[0] if diagnoses else None
    recommendations = enriched_recommendations(storage, config, incident_id)
    repairs = active_ai_repairs(storage, incident_id)
    actions = storage.latest_action_logs(100, incident_id=incident_id)
    primary = choose_primary_action(storage, config, incident, diagnosis, recommendations, repairs, actions)
    severity = str(incident.get("severity") or "warning")
    category = str(incident.get("classification_category") or "unknown")
    status = str(incident.get("status") or "open")
    state = operator_state(incident, primary, actions)
    blockers = unique_strings(
        blocker
        for recommendation in recommendations
        for blocker in safe_dict(recommendation.get("readiness")).get("blockers") or []
    )
    blockers.extend(
        blocker
        for repair in repairs
        for blocker in repair.get("blockers") or []
        if str(blocker) not in blockers
    )
    return {
        "mode": "operator_guide",
        "incident_id": incident_id,
        "state": state,
        "state_label": state_label(state),
        "severity": severity,
        "status": status,
        "needs_human_action": bool(primary["executable"] or state == "needs_manual"),
        "headline": operator_headline(incident, state),
        "what_happened": str(incident.get("classification_summary") or incident.get("last_summary") or "等待更多证据"),
        "business_impact": business_impact(category, severity),
        "what_system_did": system_activity_summary(diagnosis, recommendations, repairs, actions),
        "primary_action": primary,
        "progress": operator_progress(incident, diagnosis, recommendations, repairs, actions),
        "blockers": blockers[:8],
        "technical": {
            "category": category,
            "category_label": CATEGORY_LABELS.get(category, category),
            "confidence": float(incident.get("classification_confidence") or 0),
            "occurrence_count": int(incident.get("occurrence_count") or 0),
            "last_summary": str(incident.get("last_summary") or ""),
            "trace_id": str(incident.get("trace_id") or ""),
            "recommendation_count": len(recommendations),
            "ai_repair_count": len(repairs),
            "action_count": len(actions),
        },
    }


def execute_primary_operator_action(
    storage: Storage,
    config: AppConfig,
    incident_id: int,
    actor: str = "operator",
    note: str = "",
    notifier: Notifier | None = None,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    before = build_operator_guide(storage, config, incident_id)
    primary = safe_dict(before.get("primary_action"))
    kind = str(primary.get("kind") or "")
    if not primary.get("executable") or not kind or kind == "none":
        raise ValueError("当前没有需要执行的推荐动作")

    payload = safe_dict(request)
    execution: dict[str, Any]
    if kind == "execute_recommendation":
        execution = approve_recommendation(
            storage,
            config,
            int(primary["target_id"]),
            actor=actor,
            note=note or "operator inbox primary action",
            notifier=notifier,
        )
    elif kind == "advance_ai_repair":
        execution = run_ai_repair_queue_next_action(
            storage,
            config,
            int(primary["target_id"]),
            actor=actor,
            request={**payload, "note": note or "operator inbox primary action"},
        )
    elif kind == "run_diagnosis":
        execution = persist_incident_diagnosis(storage, config, incident_id)
    elif kind == "generate_recommendations":
        execution = create_incident_playbook_recommendations(storage, config, incident_id)
    elif kind in {"acknowledge_watch", "manual_handoff"}:
        incident = storage.get_incident(incident_id) or {}
        if str(incident.get("status") or "") == "open":
            execution = storage.transition_incident(
                incident_id,
                "acknowledged",
                actor=actor,
                note=note or ("continue automatic monitoring" if kind == "acknowledge_watch" else "manual owner follow-up required"),
                metadata={"operator_action": kind},
            )
        else:
            execution = incident
    else:
        raise ValueError(f"unsupported operator action: {kind}")

    outcome = execution_outcome(kind, execution)
    comment = operator_action_comment(kind, outcome, primary)
    storage.add_incident_comment(
        incident_id,
        actor=actor,
        comment=comment,
        metadata={"operator_action": kind, "outcome": outcome},
    )
    after = build_operator_guide(storage, config, incident_id)
    return {
        "mode": "operator_primary_action",
        "status": outcome,
        "message": outcome_message(outcome),
        "executed_action": primary,
        "execution": execution,
        "before": before,
        "after": after,
    }


def enriched_recommendations(storage: Storage, config: AppConfig | None, incident_id: int) -> list[dict[str, Any]]:
    if config is None:
        return storage.latest_incident_recommendations(incident_id)
    return list(incident_self_heal_readiness(storage, config, incident_id).get("recommendations") or [])


def active_ai_repairs(storage: Storage, incident_id: int) -> list[dict[str, Any]]:
    repairs = storage.latest_ai_repair_proposals(limit=20, incident_id=incident_id)
    items = [ai_repair_approval_queue_item(storage, repair) for repair in repairs]
    return [item for item in items if item.get("queue_state") != "done"]


def choose_primary_action(
    storage: Storage,
    config: AppConfig | None,
    incident: dict[str, Any],
    diagnosis: dict[str, Any] | None,
    recommendations: list[dict[str, Any]],
    repairs: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    incident_id = int(incident["id"])
    status = str(incident.get("status") or "open")
    if status in DONE_INCIDENT_STATUSES:
        return no_action(incident_id, "问题已恢复，无需操作")
    if latest_action_failed(actions):
        if status == "open":
            return action_payload(
                incident_id,
                "manual_handoff",
                incident_id,
                "转人工并继续监控",
                "最近一次安全处理没有成功，系统已停止重试，需要项目负责人介入。",
                risk="low",
                changes_system=False,
            )
        return no_action(incident_id, "自动处理已停止，等待项目负责人处理")

    candidates: list[tuple[int, dict[str, Any]]] = []
    for recommendation in recommendations:
        recommendation_status = str(recommendation.get("status") or "")
        readiness = safe_dict(recommendation.get("readiness"))
        if recommendation_status not in ACTIVE_RECOMMENDATION_STATUSES or readiness.get("status") == "blocked":
            continue
        changes_system = bool(readiness.get("is_mutating"))
        priority = 30 if changes_system else 10
        candidates.append(
            (
                priority,
                action_payload(
                    incident_id,
                    "execute_recommendation",
                    int(recommendation["id"]),
                    f"执行并验证：{recommendation.get('title') or '安全处理动作'}",
                    str(recommendation.get("reason") or "系统已完成安全检查"),
                    risk=str(recommendation.get("risk") or "low"),
                    changes_system=changes_system,
                ),
            )
        )

    for repair in repairs:
        next_action = safe_dict(repair.get("next_action"))
        action_type = str(next_action.get("type") or "")
        if not action_type:
            continue
        changes_system = action_type in {"prepare-branch", "create-pr", "deploy-merged"}
        candidates.append(
            (
                AI_ACTION_PRIORITY.get(action_type, 60),
                action_payload(
                    incident_id,
                    "advance_ai_repair",
                    int(repair["id"]),
                    AI_ACTION_LABELS.get(action_type, str(next_action.get("label") or "继续 AI 修复")),
                    str(repair.get("summary") or "按安全流程推进 AI 修复"),
                    risk=str(repair.get("risk") or "medium"),
                    changes_system=changes_system,
                    engine_action=action_type,
                ),
            )
        )

    if candidates:
        return min(
            candidates,
            key=lambda item: (
                item[0],
                RISK_PRIORITY.get(str(item[1].get("risk") or ""), 3),
                int(item[1]["target_id"]),
            ),
        )[1]

    if not diagnosis:
        return action_payload(
            incident_id,
            "run_diagnosis",
            incident_id,
            "让系统继续诊断",
            "先补齐证据和根因判断，再决定是否允许自动修复。",
            risk="low",
            changes_system=False,
        )

    if config is not None and not recommendations:
        preview = preview_incident_playbooks(storage, config, incident_id)
        if int(preview.get("action_count") or 0) > 0:
            return action_payload(
                incident_id,
                "generate_recommendations",
                incident_id,
                "生成安全处理方案",
                "系统已找到匹配的处理流程，先生成经过白名单检查的动作。",
                risk="low",
                changes_system=False,
            )

    if status in {"acknowledged", "remediating", "verifying"}:
        return no_action(incident_id, "系统正在跟踪处理，无需重复操作")
    if str(incident.get("severity") or "") == "critical":
        return action_payload(
            incident_id,
            "manual_handoff",
            incident_id,
            "转人工并继续监控",
            "当前没有满足安全条件的自动动作，需要项目负责人介入。",
            risk="low",
            changes_system=False,
        )
    return action_payload(
        incident_id,
        "acknowledge_watch",
        incident_id,
        "我知道了，继续自动监控",
        "当前是警告级问题，确认收到后系统继续复测。",
        risk="low",
        changes_system=False,
    )


def action_payload(
    incident_id: int,
    kind: str,
    target_id: int,
    label: str,
    reason: str,
    risk: str,
    changes_system: bool,
    engine_action: str = "",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "target_id": target_id,
        "label": label,
        "reason": reason,
        "risk": risk,
        "changes_system": changes_system,
        "requires_confirmation": True,
        "executable": True,
        "method": "POST",
        "path": f"/api/incidents/{incident_id}/operator-action",
        "engine_action": engine_action,
    }


def no_action(incident_id: int, label: str) -> dict[str, Any]:
    return {
        "kind": "none",
        "target_id": incident_id,
        "label": label,
        "reason": label,
        "risk": "low",
        "changes_system": False,
        "requires_confirmation": False,
        "executable": False,
        "method": "",
        "path": "",
        "engine_action": "",
    }


def operator_state(incident: dict[str, Any], primary: dict[str, Any], actions: list[dict[str, Any]]) -> str:
    status = str(incident.get("status") or "")
    if status in DONE_INCIDENT_STATUSES:
        return "resolved"
    if primary.get("kind") == "manual_handoff" or latest_action_failed(actions):
        return "needs_manual"
    if primary.get("executable"):
        return "ready"
    return "waiting"


def state_label(state: str) -> str:
    return {
        "resolved": "已恢复",
        "needs_manual": "需要人工",
        "ready": "可以处理",
        "waiting": "系统处理中",
    }.get(state, "待确认")


def operator_headline(incident: dict[str, Any], state: str) -> str:
    name = str(incident.get("last_summary") or incident.get("title") or f"事件 #{incident.get('id')}")
    prefix = {
        "resolved": "已恢复",
        "needs_manual": "需要项目负责人处理",
        "ready": "已有推荐动作",
        "waiting": "系统正在继续跟踪",
    }.get(state, "需要确认")
    return f"{prefix}：{name}"


def system_activity_summary(
    diagnosis: dict[str, Any] | None,
    recommendations: list[dict[str, Any]],
    repairs: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> str:
    if any(str(action.get("verification_status") or action.get("status") or "") == "verified_ok" for action in actions):
        return "系统已经执行安全动作并验证成功，正在等待监控确认稳定恢复。"
    if any(str(action.get("verification_status") or action.get("status") or "") in FAILED_ACTION_STATUSES for action in actions):
        return "系统尝试过安全处理但没有成功，已经保留现场和错误信息。"
    if repairs:
        return "系统已生成 AI 修复流程，当前只推进到允许的安全阶段。"
    if recommendations:
        return "系统已完成诊断并生成处理方案，尚未越过审批权限。"
    if diagnosis:
        return "系统已完成诊断和证据留存，没有修改服务器或代码。"
    return "系统已发现问题，正在补充诊断证据，没有修改服务器或代码。"


def operator_progress(
    incident: dict[str, Any],
    diagnosis: dict[str, Any] | None,
    recommendations: list[dict[str, Any]],
    repairs: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    status = str(incident.get("status") or "")
    return [
        {"step": "detected", "label": "发现问题", "done": True},
        {"step": "diagnosed", "label": "完成诊断", "done": bool(diagnosis)},
        {"step": "planned", "label": "生成方案", "done": bool(recommendations or repairs)},
        {"step": "executed", "label": "执行动作", "done": bool(actions)},
        {
            "step": "verified",
            "label": "验证结果",
            "done": any(str(action.get("verification_status") or "") == "verified_ok" for action in actions),
        },
        {"step": "resolved", "label": "恢复正常", "done": status in DONE_INCIDENT_STATUSES},
    ]


def execution_outcome(kind: str, execution: dict[str, Any]) -> str:
    if kind == "execute_recommendation":
        action = safe_dict(execution.get("action"))
        result = safe_dict(action.get("result"))
        status = str(result.get("status") or safe_dict(execution.get("recommendation")).get("status") or "")
        return "needs_manual" if status in FAILED_ACTION_STATUSES else "completed"
    if kind == "advance_ai_repair":
        status = str(safe_dict(execution.get("repair")).get("status") or "")
        return "needs_manual" if status.endswith("failed") else "completed"
    if kind == "generate_recommendations" and int(execution.get("saved_count") or 0) == 0:
        return "needs_manual"
    if kind == "manual_handoff":
        return "needs_manual"
    if kind == "acknowledge_watch":
        return "waiting"
    return "completed"


def operator_action_comment(kind: str, outcome: str, primary: dict[str, Any]) -> str:
    return f"统一运维入口执行 {kind}: {primary.get('label', '')}; 结果={outcome}"


def outcome_message(outcome: str) -> str:
    return {
        "completed": "推荐动作已完成，系统会继续验证并给出下一步。",
        "waiting": "已确认收到，系统会继续自动监控。",
        "needs_manual": "自动流程没有满足继续执行条件，已停止并转为人工处理。",
    }.get(outcome, "动作已记录。")


def inbox_sort_key(item: dict[str, Any]) -> tuple[int, int, int]:
    state_priority = {"needs_manual": 0, "ready": 1, "waiting": 2, "resolved": 3}
    severity_priority = 0 if item.get("severity") == "critical" else 1
    return state_priority.get(str(item.get("state") or ""), 4), severity_priority, -int(item.get("incident_id") or 0)


def latest_action_failed(actions: list[dict[str, Any]]) -> bool:
    if not actions:
        return False
    latest = actions[0]
    status = str(latest.get("verification_status") or latest.get("status") or "")
    return status in FAILED_ACTION_STATUSES


def unique_strings(values) -> list[str]:
    items: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in items:
            items.append(text)
    return items


def safe_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}
