from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ops_agent.ai.classifier import classify_signal
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction

TOKEN_RE = re.compile(r"{{\s*([a-zA-Z][a-zA-Z0-9_.-]*)\s*}}")
PLAYBOOK_META_KEY = "_playbook"
FAILURE_POLICIES = {"continue", "halt", "escalate", "rollback"}
STAGES = {"diagnose", "remediate", "verify", "rollback"}


def build_playbook_actions(
    result: CheckResult,
    remediation: dict[str, Any],
    configured_actions: dict[str, bool],
    classification_rules: list[dict[str, Any]] | None = None,
) -> list[RemediationAction]:
    actions: list[RemediationAction] = []
    for playbook in remediation_playbooks(remediation):
        if not bool(playbook.get("enabled", True)):
            continue
        if not playbook_matches(result, dict(playbook.get("match", {})), classification_rules):
            continue
        actions.extend(actions_from_playbook(result, playbook, configured_actions, classification_rules))
    return actions


def remediation_playbooks(remediation: dict[str, Any]) -> list[dict[str, Any]]:
    playbooks = remediation.get("playbooks", [])
    if not isinstance(playbooks, list):
        return []
    return [item for item in playbooks if isinstance(item, dict)]


def playbook_matches(
    result: CheckResult,
    match: dict[str, Any],
    classification_rules: list[dict[str, Any]] | None = None,
) -> bool:
    if not match:
        return True
    classification = classify_signal(result, classification_rules)
    if not exact_list_matches(result.source, match.get("sources")):
        return False
    if not exact_list_matches(result.status, match.get("statuses")):
        return False
    if not exact_list_matches(classification.category, match.get("categories")):
        return False
    if not contains_any(result.name, match.get("name_contains")):
        return False
    if not contains_any(result.summary, match.get("summary_contains")):
        return False
    if not contains_any(str(result.details.get("url", "")), match.get("url_contains")):
        return False
    if not contains_any(str(result.details.get("path", "")), match.get("path_contains")):
        return False
    return True


def exact_list_matches(value: str, candidates: object) -> bool:
    if not candidates:
        return True
    if not isinstance(candidates, list):
        return False
    normalized = {str(item).strip() for item in candidates if str(item).strip()}
    return "*" in normalized or value in normalized


def contains_any(value: str, candidates: object) -> bool:
    if not candidates:
        return True
    if not isinstance(candidates, list):
        return False
    text = value.casefold()
    return any(str(item).strip().casefold() in text for item in candidates if str(item).strip())


def actions_from_playbook(
    result: CheckResult,
    playbook: dict[str, Any],
    configured_actions: dict[str, bool],
    classification_rules: list[dict[str, Any]] | None = None,
) -> list[RemediationAction]:
    steps = playbook.get("steps", [])
    if not isinstance(steps, list):
        return []

    default_on_failure = normalize_choice(str(playbook.get("on_failure") or "continue"), FAILURE_POLICIES, "continue")
    rollback_actions = [
        action.to_dict()
        for action in actions_from_steps(
            result,
            playbook,
            playbook.get("rollback_steps", []),
            configured_actions,
            classification_rules,
            default_on_failure="continue",
            default_stage="rollback",
            rollback_for="playbook",
        )
    ]
    return actions_from_steps(
        result,
        playbook,
        steps,
        configured_actions,
        classification_rules,
        default_on_failure=default_on_failure,
        default_stage="diagnose",
        rollback_actions=rollback_actions,
    )


def actions_from_steps(
    result: CheckResult,
    playbook: dict[str, Any],
    steps: object,
    configured_actions: dict[str, bool],
    classification_rules: list[dict[str, Any]] | None,
    default_on_failure: str,
    default_stage: str,
    rollback_actions: list[dict[str, Any]] | None = None,
    rollback_for: str = "",
) -> list[RemediationAction]:
    if not isinstance(steps, list):
        return []

    context = template_context(result, classification_rules)
    playbook_name = str(playbook.get("name") or "playbook")
    actions: list[RemediationAction] = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        action_type = str(step.get("action_type", "")).strip()
        if not action_type:
            continue
        params = render_value(step.get("params", {}), context)
        if not isinstance(params, dict):
            params = {}
        step_id = str(step.get("id") or f"step-{index}").strip() or f"step-{index}"
        stage = normalize_choice(str(step.get("stage") or default_stage), STAGES, default_stage)
        on_failure = normalize_choice(str(step.get("on_failure") or default_on_failure), FAILURE_POLICIES, default_on_failure)
        meta: dict[str, Any] = {
            "name": playbook_name,
            "step_id": step_id,
            "step_order": index,
            "stage": stage,
            "on_failure": on_failure,
        }
        if rollback_for:
            meta["rollback_for"] = rollback_for
        if on_failure == "rollback" and rollback_actions:
            meta["rollback_actions"] = rollback_actions
        params[PLAYBOOK_META_KEY] = meta
        title = str(render_value(step.get("title") or f"{playbook_name}: step {index}", context))
        reason = str(render_value(step.get("reason") or f"Matched remediation playbook: {playbook_name}", context))
        actions.append(
            RemediationAction(
                action_type=action_type,
                title=title,
                reason=reason,
                risk=str(step.get("risk") or "low"),  # type: ignore[arg-type]
                params=params,
                auto_execute=bool(step.get("auto_execute", configured_actions.get(action_type, False))),
            )
        )
    return actions


def playbook_meta(action: RemediationAction) -> dict[str, Any]:
    meta = action.params.get(PLAYBOOK_META_KEY)
    return dict(meta) if isinstance(meta, dict) else {}


def playbook_identity(action: RemediationAction) -> str:
    meta = playbook_meta(action)
    return str(meta.get("name") or "")


def playbook_failure_policy(action: RemediationAction) -> str:
    meta = playbook_meta(action)
    return normalize_choice(str(meta.get("on_failure") or "continue"), FAILURE_POLICIES, "continue")


def playbook_rollback_actions(action: RemediationAction) -> list[RemediationAction]:
    meta = playbook_meta(action)
    raw_actions = meta.get("rollback_actions", [])
    if not isinstance(raw_actions, list):
        return []
    from ops_agent.remediation.actions import action_from_dict

    return [action_from_dict(item) for item in raw_actions if isinstance(item, dict)]


def normalize_choice(value: str, allowed: set[str], default: str) -> str:
    normalized = value.strip().lower()
    return normalized if normalized in allowed else default


def template_context(
    result: CheckResult,
    classification_rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    url = str(result.details.get("url", ""))
    host, port = host_port_from_url(url)
    classification = classify_signal(result, classification_rules)
    context: dict[str, Any] = {
        "source": result.source,
        "name": result.name,
        "status": result.status,
        "category": classification.category,
        "classification": classification.category,
        "classification_confidence": f"{classification.confidence:.2f}",
        "classification_summary": classification.summary,
        "summary": result.summary,
        "url": url,
        "host": host,
        "port": port or "",
        "path": str(result.details.get("path", "")),
        "trace_id": result.trace_id,
        "environment": result.environment,
        "run_type": result.run_type,
    }
    for key, value in result.details.items():
        context[f"details.{key}"] = value
    return context


def render_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return render_string(value, context)
    if isinstance(value, list):
        return [render_value(item, context) for item in value]
    if isinstance(value, dict):
        return {str(key): render_value(item, context) for key, item in value.items()}
    return value


def render_string(value: str, context: dict[str, Any]) -> Any:
    full_match = TOKEN_RE.fullmatch(value.strip())
    if full_match:
        return context.get(full_match.group(1), "")

    def replace_token(match: re.Match[str]) -> str:
        replacement = context.get(match.group(1), "")
        return str(replacement)

    return TOKEN_RE.sub(replace_token, value)


def host_port_from_url(url: str) -> tuple[str, int | None]:
    parsed = urlparse(url)
    if not parsed.hostname:
        return "", None
    if parsed.port:
        return parsed.hostname, parsed.port
    if parsed.scheme == "https":
        return parsed.hostname, 443
    if parsed.scheme == "http":
        return parsed.hostname, 80
    return parsed.hostname, None
