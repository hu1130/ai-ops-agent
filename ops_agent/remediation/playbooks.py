from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction

TOKEN_RE = re.compile(r"{{\s*([a-zA-Z][a-zA-Z0-9_.-]*)\s*}}")


def build_playbook_actions(
    result: CheckResult,
    remediation: dict[str, Any],
    configured_actions: dict[str, bool],
) -> list[RemediationAction]:
    actions: list[RemediationAction] = []
    for playbook in remediation_playbooks(remediation):
        if not bool(playbook.get("enabled", True)):
            continue
        if not playbook_matches(result, dict(playbook.get("match", {}))):
            continue
        actions.extend(actions_from_playbook(result, playbook, configured_actions))
    return actions


def remediation_playbooks(remediation: dict[str, Any]) -> list[dict[str, Any]]:
    playbooks = remediation.get("playbooks", [])
    if not isinstance(playbooks, list):
        return []
    return [item for item in playbooks if isinstance(item, dict)]


def playbook_matches(result: CheckResult, match: dict[str, Any]) -> bool:
    if not match:
        return True
    if not exact_list_matches(result.source, match.get("sources")):
        return False
    if not exact_list_matches(result.status, match.get("statuses")):
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
) -> list[RemediationAction]:
    steps = playbook.get("steps", [])
    if not isinstance(steps, list):
        return []

    context = template_context(result)
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


def template_context(result: CheckResult) -> dict[str, Any]:
    url = str(result.details.get("url", ""))
    host, port = host_port_from_url(url)
    context: dict[str, Any] = {
        "source": result.source,
        "name": result.name,
        "status": result.status,
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
