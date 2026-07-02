from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ops_agent.ai.learning_review import build_learning_optimization_draft


SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]+")
UNKNOWN_CATEGORIES = {"", "unknown", "unclassified"}


def build_config_patch_from_recommendation(recommendation: dict) -> dict:
    draft = safe_dict(recommendation.get("draft")) or build_learning_optimization_draft(recommendation)
    draft_type = str(draft.get("draft_type") or "")
    if draft_type == "classifier_rule":
        return classifier_rule_patch(recommendation, draft)
    if draft_type == "playbook":
        return playbook_patch(recommendation, draft)
    return review_task_patch(recommendation, draft)


def classifier_rule_patch(recommendation: dict, draft: dict) -> dict:
    candidate = safe_dict(draft.get("candidate"))
    conditions = safe_dict(candidate.get("conditions"))
    category = str(candidate.get("category") or recommendation.get("category") or "unknown").strip()
    keywords = safe_string_list(conditions.get("summary_keywords"))[:6]
    rule_name = learned_name("classifier", recommendation)
    enabled = category not in UNKNOWN_CATEGORIES and bool(keywords)
    value = {
        "name": rule_name,
        "enabled": enabled,
        "category": category or "unknown",
        "confidence": safe_float(candidate.get("confidence_floor"), 0.75),
        "summary": f"Learned classifier rule from recommendation #{recommendation.get('id')}",
        "match": {
            "statuses": ["warning", "critical"],
            "summary_contains": keywords,
        },
        "next_steps": [
            "Review the matched signal and confirm whether the learned classification is still correct.",
            "If false positives appear, disable this generated rule and refine its match conditions.",
        ],
    }
    return base_patch(
        recommendation,
        patch_type="classification_rule",
        title=f"Add classification rule: {rule_name}",
        reason=str(recommendation.get("reason") or ""),
        operation={
            "op": "append_unique",
            "path": ["classification_rules"],
            "identity_key": "name",
            "value": value,
        },
    )


def playbook_patch(recommendation: dict, draft: dict) -> dict:
    candidate = safe_dict(draft.get("candidate"))
    category = str(recommendation.get("category") or draft.get("category") or "")
    playbook_name = learned_name("playbook", recommendation)
    match = safe_dict(candidate.get("match"))
    if category and not match.get("categories"):
        match["categories"] = [category]
    match.pop("fingerprint", None)
    steps = normalize_playbook_steps(safe_list(candidate.get("steps")))
    value = {
        "name": playbook_name,
        "enabled": False,
        "on_failure": "halt",
        "match": match,
        "steps": steps
        or [
            {
                "id": "collect_evidence",
                "stage": "diagnose",
                "action_type": "run_diagnostic_command",
                "title": "Collect service evidence",
                "reason": "Generated from a learning recommendation; review before enabling.",
                "risk": "low",
                "params": {"command": "docker ps"},
                "auto_execute": False,
            }
        ],
    }
    return base_patch(
        recommendation,
        patch_type="playbook",
        title=f"Add remediation playbook: {playbook_name}",
        reason=str(recommendation.get("reason") or ""),
        operation={
            "op": "append_unique",
            "path": ["remediation", "playbooks"],
            "identity_key": "name",
            "value": value,
        },
    )


def review_task_patch(recommendation: dict, draft: dict) -> dict:
    return base_patch(
        recommendation,
        patch_type="review_task",
        title=f"Manual review task for recommendation #{recommendation.get('id')}",
        reason=str(recommendation.get("reason") or ""),
        operation={
            "op": "append_unique",
            "path": ["learning", "manual_review_tasks"],
            "identity_key": "dedupe_key",
            "value": {
                "dedupe_key": recommendation.get("dedupe_key") or f"recommendation-{recommendation.get('id')}",
                "title": recommendation.get("title") or "",
                "reason": recommendation.get("reason") or "",
                "draft": draft,
            },
        },
    )


def base_patch(recommendation: dict, patch_type: str, title: str, reason: str, operation: dict) -> dict:
    return {
        "schema_version": 1,
        "patch_type": patch_type,
        "title": title,
        "reason": reason,
        "recommendation_id": recommendation.get("id"),
        "operations": [operation],
    }


def apply_config_patch(config_path: Path, patch: dict) -> dict:
    if not config_path:
        raise ValueError("config path is not configured")
    config_path = config_path.resolve()
    current = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(current, dict):
        raise ValueError("config file must contain a JSON object")

    updated = deepcopy(current)
    operations = safe_list(patch.get("operations"))
    if not operations:
        raise ValueError("config patch has no operations")
    applied_operations = []
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        applied_operations.append(apply_operation(updated, operation))
    if not applied_operations:
        raise ValueError("config patch did not contain a supported operation")

    backup_path = config_path.with_name(f"{config_path.name}.bak-{timestamp()}")
    backup_path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path = config_path.with_name(f"{config_path.name}.tmp-{timestamp()}")
    temp_path.write_text(json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(config_path)
    return {
        "backup_path": str(backup_path),
        "operation_count": len(applied_operations),
        "operations": applied_operations,
        "config": updated,
    }


def apply_operation(config: dict, operation: dict) -> dict:
    op = str(operation.get("op") or "")
    if op != "append_unique":
        raise ValueError(f"unsupported config patch operation: {op}")
    path = safe_string_list(operation.get("path"))
    if not path:
        raise ValueError("config patch operation path is empty")
    target = ensure_list_path(config, path)
    identity_key = str(operation.get("identity_key") or "name")
    value = safe_dict(operation.get("value"))
    if not value:
        raise ValueError("config patch operation value is empty")
    identity = str(value.get(identity_key) or "").strip()
    if identity and any(isinstance(item, dict) and str(item.get(identity_key) or "") == identity for item in target):
        return {"op": op, "path": path, "status": "already_exists", "identity": identity}
    target.append(value)
    return {"op": op, "path": path, "status": "appended", "identity": identity}


def ensure_list_path(config: dict, path: list[str]) -> list:
    node: Any = config
    for key in path[:-1]:
        if not isinstance(node, dict):
            raise ValueError(f"config patch path is not an object: {'.'.join(path)}")
        current = node.get(key)
        if current is None:
            current = {}
            node[key] = current
        if not isinstance(current, dict):
            raise ValueError(f"config patch path conflicts with non-object key: {key}")
        node = current
    final_key = path[-1]
    current = node.get(final_key)
    if current is None:
        current = []
        node[final_key] = current
    if not isinstance(current, list):
        raise ValueError(f"config patch target is not a list: {'.'.join(path)}")
    return current


def normalize_playbook_steps(steps: list) -> list[dict]:
    normalized: list[dict] = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        action_type = str(step.get("action_type") or "").strip()
        if not action_type:
            continue
        normalized.append(
            {
                "id": str(step.get("id") or f"generated_step_{index}"),
                "stage": str(step.get("stage") or "diagnose"),
                "action_type": action_type,
                "title": str(step.get("title") or f"Generated step {index}"),
                "reason": str(step.get("reason") or "Generated from a learning recommendation."),
                "risk": str(step.get("risk") or ("medium" if action_type.startswith("restart") else "low")),
                "params": safe_dict(step.get("params")),
                "auto_execute": bool(step.get("auto_execute", False)),
            }
        )
    return normalized


def learned_name(prefix: str, recommendation: dict) -> str:
    raw = str(recommendation.get("dedupe_key") or recommendation.get("title") or recommendation.get("id") or "item")
    cleaned = SAFE_NAME_RE.sub("-", raw).strip("-").lower()[:48] or "item"
    return f"learned-{prefix}-{cleaned}"


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def safe_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def safe_string_list(value: Any) -> list[str]:
    return [str(item).strip() for item in safe_list(value) if str(item).strip()]


def safe_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 0.0), 1.0)
