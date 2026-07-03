from __future__ import annotations

import json
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.remediation.planner import configured_auto_actions, dedupe_actions
from ops_agent.remediation.playbooks import (
    build_playbook_actions,
    playbook_failure_policy,
    playbook_identity,
    playbook_meta,
    remediation_playbooks,
)
from ops_agent.remediation.policy import MUTATING_ACTIONS, apply_policy_defaults, decide_action_policy
from ops_agent.storage import Storage


def list_playbooks(config: AppConfig | None) -> dict:
    playbooks = configured_playbooks(config)
    summaries = [playbook_summary(playbook, index) for index, playbook in enumerate(playbooks)]
    return {
        "count": len(summaries),
        "enabled_count": sum(1 for item in summaries if item["enabled"]),
        "playbooks": summaries,
    }


def get_playbook(config: AppConfig | None, name: str) -> dict | None:
    target = name.strip()
    for index, playbook in enumerate(configured_playbooks(config)):
        if str(playbook.get("name") or "").strip() == target:
            return {
                **playbook_summary(playbook, index),
                "playbook": playbook,
            }
    return None


def preview_incident_playbooks(storage: Storage, config: AppConfig, incident_id: int) -> dict:
    incident = require_incident(storage, incident_id)
    results = incident_check_results(incident)
    preview_actions = planned_playbook_actions(results, config)
    playbooks = matched_playbook_summaries(preview_actions)
    return {
        "incident": incident_overview(incident),
        "result_count": len(results),
        "matched_playbook_count": len(playbooks),
        "action_count": len([item for item in preview_actions if item["policy"]["allowed"]]),
        "denied_action_count": len([item for item in preview_actions if not item["policy"]["allowed"]]),
        "playbooks": playbooks,
        "actions": preview_actions,
    }


def create_incident_playbook_recommendations(storage: Storage, config: AppConfig, incident_id: int) -> dict:
    preview = preview_incident_playbooks(storage, config, incident_id)
    recommendations = [
        action_recommendation(item, position, preview["incident"])
        for position, item in enumerate(preview["actions"], start=1)
        if item["policy"]["allowed"]
    ]
    saved = storage.add_incident_recommendations(incident_id, recommendations, source="playbook_center")
    return {
        **preview,
        "saved_count": len(saved),
        "saved_recommendations": saved,
    }


def configured_playbooks(config: AppConfig | None) -> list[dict[str, Any]]:
    if config is None:
        return []
    remediation = config.raw.get("remediation", {})
    return remediation_playbooks(remediation if isinstance(remediation, dict) else {})


def playbook_summary(playbook: dict[str, Any], index: int) -> dict:
    steps = safe_list(playbook.get("steps"))
    rollback_steps = safe_list(playbook.get("rollback_steps"))
    all_steps = [step for step in [*steps, *rollback_steps] if isinstance(step, dict)]
    action_types = sorted({str(step.get("action_type") or "") for step in all_steps if step.get("action_type")})
    stages = sorted({str(step.get("stage") or "diagnose") for step in all_steps})
    return {
        "index": index,
        "name": str(playbook.get("name") or ""),
        "enabled": bool(playbook.get("enabled", True)),
        "match": dict(playbook.get("match", {})) if isinstance(playbook.get("match"), dict) else {},
        "on_failure": str(playbook.get("on_failure") or "continue"),
        "step_count": len(steps),
        "rollback_step_count": len(rollback_steps),
        "action_types": action_types,
        "stages": stages,
        "has_mutating_steps": any(action_type in MUTATING_ACTIONS for action_type in action_types),
        "steps": [step_summary(step, position) for position, step in enumerate(steps, start=1) if isinstance(step, dict)],
        "rollback_steps": [
            step_summary(step, position) for position, step in enumerate(rollback_steps, start=1) if isinstance(step, dict)
        ],
    }


def step_summary(step: dict[str, Any], position: int) -> dict:
    return {
        "position": position,
        "id": str(step.get("id") or f"step-{position}"),
        "stage": str(step.get("stage") or "diagnose"),
        "action_type": str(step.get("action_type") or ""),
        "title": str(step.get("title") or ""),
        "risk": str(step.get("risk") or "low"),
        "auto_execute": bool(step.get("auto_execute", False)),
        "on_failure": str(step.get("on_failure") or ""),
    }


def planned_playbook_actions(results: list[CheckResult], config: AppConfig) -> list[dict]:
    remediation = config.raw.get("remediation", {})
    remediation_config = remediation if isinstance(remediation, dict) else {}
    auto_actions = configured_auto_actions(remediation_config)
    planned: list[RemediationAction] = []
    for result in results:
        if result.is_problem:
            planned.extend(build_playbook_actions(result, remediation_config, auto_actions, config.classification_rules))

    preview: list[dict] = []
    for action in dedupe_actions(planned):
        decision = decide_action_policy(action, config)
        effective = apply_policy_defaults(action, config) if decision.allowed else action
        preview.append(
            {
                **effective.to_dict(),
                "playbook": playbook_meta(action),
                "playbook_name": playbook_identity(action),
                "on_failure": playbook_failure_policy(action),
                "policy": {
                    "configured": decision.configured,
                    "allowed": decision.allowed,
                    "policy_name": decision.policy_name,
                    "auto_execute": decision.auto_execute,
                    "requires_approval": decision.requires_approval,
                    "verification_required": decision.verification_required,
                    "reason": decision.reason,
                },
            }
        )
    return preview


def matched_playbook_summaries(actions: list[dict]) -> list[dict]:
    summaries: dict[str, dict] = {}
    for item in actions:
        name = str(item.get("playbook_name") or "")
        if not name:
            continue
        meta = safe_dict(item.get("playbook"))
        summary = summaries.setdefault(
            name,
            {
                "name": name,
                "action_count": 0,
                "allowed_action_count": 0,
                "denied_action_count": 0,
                "stages": [],
                "step_ids": [],
            },
        )
        summary["action_count"] += 1
        if safe_dict(item.get("policy")).get("allowed"):
            summary["allowed_action_count"] += 1
        else:
            summary["denied_action_count"] += 1
        append_unique(summary["stages"], str(meta.get("stage") or ""))
        append_unique(summary["step_ids"], str(meta.get("step_id") or ""))
    return list(summaries.values())


def action_recommendation(item: dict, position: int, incident: dict) -> dict:
    policy = safe_dict(item.get("policy"))
    playbook = safe_dict(item.get("playbook"))
    params = safe_dict(item.get("params"))
    return {
        "position": position,
        "category": str(playbook.get("stage") or "diagnose"),
        "action_type": str(item.get("action_type") or ""),
        "title": str(item.get("title") or ""),
        "reason": str(item.get("reason") or ""),
        "risk": str(item.get("risk") or "low"),
        "approval_required": bool(policy.get("requires_approval")),
        "auto_execute": bool(item.get("auto_execute")),
        "verification_required": bool(policy.get("verification_required")),
        "status": "suggested",
        "params": params,
        "environment": str(incident.get("environment") or "prod"),
        "run_type": str(incident.get("run_type") or "normal"),
        "trace_id": str(incident.get("trace_id") or ""),
        "source": "playbook_center",
        "metadata": {
            "playbook": playbook,
            "policy": policy,
        },
    }


def incident_check_results(incident: dict) -> list[CheckResult]:
    raw = parse_json_list(str(incident.get("results_json") or "[]"))
    results: list[CheckResult] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        details = item.get("details", {})
        status = str(item.get("status") or incident.get("severity") or "warning")
        if status not in {"ok", "warning", "critical"}:
            status = "warning"
        results.append(
            CheckResult(
                source=str(item.get("source") or "incident"),
                name=str(item.get("name") or incident.get("title") or ""),
                status=status,  # type: ignore[arg-type]
                summary=str(item.get("summary") or incident.get("last_summary") or ""),
                details=dict(details) if isinstance(details, dict) else {},
                created_at=str(item.get("created_at") or incident.get("created_at") or ""),
                environment=str(item.get("environment") or incident.get("environment") or "prod"),
                run_type=str(item.get("run_type") or incident.get("run_type") or "normal"),
                trace_id=str(item.get("trace_id") or incident.get("trace_id") or ""),
            )
        )
    return results


def require_incident(storage: Storage, incident_id: int) -> dict:
    incident = storage.get_incident(incident_id)
    if not incident:
        raise ValueError(f"incident not found: {incident_id}")
    return incident


def incident_overview(incident: dict) -> dict:
    return {
        "id": incident.get("id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "status": incident.get("status"),
        "environment": incident.get("environment"),
        "run_type": incident.get("run_type"),
        "trace_id": incident.get("trace_id"),
        "classification_category": incident.get("classification_category"),
        "last_summary": incident.get("last_summary"),
    }


def append_unique(values: list, value: str) -> None:
    if value and value not in values:
        values.append(value)


def safe_dict(value: object) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: object) -> list:
    return list(value) if isinstance(value, list) else []


def parse_json_list(value: str) -> list:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []
