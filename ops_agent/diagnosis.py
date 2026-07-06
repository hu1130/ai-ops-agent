from __future__ import annotations

import json
from typing import Any

from ops_agent.config import AppConfig
from ops_agent.storage import Storage


def build_incident_diagnosis(
    storage: Storage,
    config: AppConfig | None,
    incident_id: int,
    collected_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    incident = storage.get_incident(incident_id)
    if not incident:
        raise ValueError("incident not found")

    results = parse_json_list(str(incident.get("results_json") or "[]"))
    causes = rank_probable_causes(incident, results)
    related = related_incidents(storage, incident, results)
    collection_plan = build_collection_plan(causes, results, config)
    signals = normalize_signals(results)
    change_correlation = storage.correlate_incident_changes(incident, hours=24, limit=10)
    evidence = build_evidence_package(
        incident,
        signals,
        causes,
        collection_plan,
        collected_evidence,
        change_correlation,
    )
    return {
        "incident": incident,
        "context": {
            "environment": incident.get("environment") or "prod",
            "run_type": incident.get("run_type") or "normal",
            "trace_id": incident.get("trace_id") or "",
            "classification_category": incident.get("classification_category") or "",
            "classification_confidence": incident.get("classification_confidence") or 0,
        },
        "signals": signals,
        "probable_causes": causes,
        "evidence": evidence,
        "collection_plan": collection_plan,
        "related_incidents": related,
        "change_correlation": change_correlation,
        "next_decision": next_decision(causes, incident),
    }


def persist_incident_diagnosis(
    storage: Storage,
    config: AppConfig | None,
    incident_id: int,
    collected_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    diagnosis = build_incident_diagnosis(storage, config, incident_id, collected_evidence=collected_evidence)
    diagnosis_id = storage.save_incident_diagnosis(incident_id, diagnosis)
    diagnosis["diagnosis_id"] = diagnosis_id
    return diagnosis


def build_evidence_package(
    incident: dict[str, Any],
    signals: list[dict[str, Any]],
    causes: list[dict[str, Any]],
    collection_plan: list[dict[str, Any]],
    collected_evidence: dict[str, Any] | None,
    change_correlation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    top = causes[0] if causes else {}
    return {
        "source": "ops-agent",
        "incident_summary": {
            "id": incident.get("id"),
            "title": incident.get("title"),
            "severity": incident.get("severity"),
            "status": incident.get("status"),
            "last_summary": incident.get("last_summary") or "",
        },
        "monitor_signals": signals,
        "recent_changes": change_correlation if isinstance(change_correlation, dict) else {},
        "top_cause": {
            "category": top.get("category") or "",
            "confidence": top.get("confidence") or 0,
            "evidence": top.get("evidence") or [],
        },
        "collection_plan": collection_plan,
        "collected": collected_evidence or {},
    }


def diagnostic_snapshot_evidence(snapshot: object) -> dict[str, Any]:
    return {
        "resource_lines": list(getattr(snapshot, "resource_lines", []) or []),
        "docker_lines": list(getattr(snapshot, "docker_lines", []) or []),
        "log_lines": list(getattr(snapshot, "log_lines", []) or []),
        "command_lines": list(getattr(snapshot, "command_lines", []) or []),
    }


def rank_probable_causes(incident: dict[str, Any], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    classification_category = str(incident.get("classification_category") or "")
    if classification_category:
        add_candidate(
            candidates,
            classification_category,
            "Existing classifier category on the incident.",
            0.55 + min(float(incident.get("classification_confidence") or 0), 1.0) * 0.25,
            ["Use the existing category to select a playbook, then confirm with live signals."],
        )

    for result in results:
        source = str(result.get("source") or "")
        summary = str(result.get("summary") or "")
        status = str(result.get("status") or "")
        lowered = summary.lower()
        evidence = f"{source}/{result.get('name')}: {summary}"

        if source == "server" or any(term in lowered for term in ("disk", "cpu", "memory", "load")):
            add_candidate(
                candidates,
                "resource_saturation",
                evidence,
                0.85 if status == "critical" else 0.7,
                [
                    "Check disk, memory, CPU, load average and container resource limits.",
                    "Confirm whether recent traffic or batch jobs changed resource pressure.",
                ],
            )
        if source in {"http", "json", "json_api"} and any(term in lowered for term in ("http 500", "http 502", "http 503", "http 504")):
            add_candidate(
                candidates,
                "application_or_gateway_error",
                evidence,
                0.88,
                [
                    "Inspect reverse proxy logs, application logs and upstream dependency errors.",
                    "Compare with the latest deploy, config change and database availability.",
                ],
            )
        if source in {"http", "json", "json_api"} and "http 404" in lowered:
            add_candidate(
                candidates,
                "route_or_healthcheck_config_mismatch",
                evidence,
                0.82,
                [
                    "Confirm whether the monitored path exists and whether the service has a different health endpoint.",
                    "If only the health endpoint is missing but the website works, update monitor config instead of restarting.",
                ],
            )
        if source in {"http", "json", "json_api"} and any(term in lowered for term in ("request failed", "connection", "timeout", "dns", "ssl")):
            add_candidate(
                candidates,
                "network_or_proxy_unreachable",
                evidence,
                0.82,
                [
                    "Run curl from the server and confirm DNS, TLS certificate, Nginx routing and target port.",
                    "Check whether the container or upstream service is listening on the expected port.",
                ],
            )
        if any(term in lowered for term in ("slow", "latency", "timeout")):
            add_candidate(
                candidates,
                "performance_degraded",
                evidence,
                0.74,
                [
                    "Compare current latency with recent baseline and check external provider latency.",
                    "Check database connection pool, queue backlog and slow application logs.",
                ],
            )
        if source.startswith("log") or any(term in lowered for term in ("exception", "traceback", "fatal", "error")):
            add_candidate(
                candidates,
                "application_log_error",
                evidence,
                0.76,
                [
                    "Open the newest application log lines around the incident time.",
                    "Look for repeated exception types and correlate with recent code or config changes.",
                ],
            )

    if not candidates:
        add_candidate(
            candidates,
            "unknown",
            str(incident.get("last_summary") or incident.get("title") or "No strong signal matched."),
            0.35,
            [
                "Collect service status, logs, resource metrics and recent deployment history.",
                "If this repeats, add a classification rule or playbook after manual confirmation.",
            ],
        )

    rows = list(candidates.values())
    rows.sort(key=lambda item: (-float(item["confidence"]), str(item["category"])))
    return rows[:5]


def add_candidate(
    candidates: dict[str, dict[str, Any]],
    category: str,
    evidence: str,
    confidence: float,
    next_steps: list[str],
) -> None:
    current = candidates.setdefault(
        category,
        {
            "category": category,
            "confidence": 0.0,
            "evidence": [],
            "next_steps": [],
        },
    )
    current["confidence"] = round(max(float(current["confidence"]), min(max(confidence, 0.0), 1.0)), 3)
    if evidence and evidence not in current["evidence"]:
        current["evidence"].append(evidence)
    for step in next_steps:
        if step not in current["next_steps"]:
            current["next_steps"].append(step)


def normalize_signals(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "source": str(result.get("source") or ""),
            "name": str(result.get("name") or ""),
            "status": str(result.get("status") or ""),
            "summary": str(result.get("summary") or ""),
            "environment": str(result.get("environment") or "prod"),
            "run_type": str(result.get("run_type") or "normal"),
            "trace_id": str(result.get("trace_id") or ""),
        }
        for result in results
        if isinstance(result, dict)
    ]


def related_incidents(storage: Storage, incident: dict[str, Any], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    source_names = {f"{row.get('source')}/{row.get('name')}" for row in results if isinstance(row, dict)}
    rows = storage.latest_incidents(
        limit=50,
        environment=str(incident.get("environment") or "prod"),
        run_type=str(incident.get("run_type") or "normal"),
    )
    related = []
    current_id = int(incident.get("id") or 0)
    current_category = str(incident.get("classification_category") or "")
    for row in rows:
        if int(row.get("id") or 0) == current_id:
            continue
        row_results = parse_json_list(str(row.get("results_json") or "[]"))
        row_source_names = {f"{item.get('source')}/{item.get('name')}" for item in row_results if isinstance(item, dict)}
        category_match = current_category and str(row.get("classification_category") or "") == current_category
        target_match = bool(source_names & row_source_names)
        if not category_match and not target_match:
            continue
        related.append(
            {
                "id": row.get("id"),
                "title": row.get("title"),
                "status": row.get("status"),
                "severity": row.get("severity"),
                "latest_at": row.get("last_seen_at") or row.get("updated_at") or row.get("created_at"),
                "match": {
                    "same_category": bool(category_match),
                    "same_target": bool(target_match),
                },
            }
        )
        if len(related) >= 5:
            break
    return related


def build_collection_plan(causes: list[dict[str, Any]], results: list[dict[str, Any]], config: AppConfig | None) -> list[dict[str, Any]]:
    plan = [
        {
            "type": "service_status",
            "title": "Check service and container status",
            "command_hint": "docker ps && systemctl status <service>",
            "reason": "Confirm whether the process or container is alive before changing anything.",
        },
        {
            "type": "recent_logs",
            "title": "Collect recent application and proxy logs",
            "command_hint": "docker logs --tail 120 <container>",
            "reason": "Most application and gateway failures leave direct evidence in logs.",
        },
    ]
    categories = {str(item.get("category") or "") for item in causes}
    if "resource_saturation" in categories:
        plan.append(
            {
                "type": "resource_snapshot",
                "title": "Collect resource snapshot",
                "command_hint": "df -h && free -m && top -b -n1 | head -40",
                "reason": "Resource incidents need current capacity evidence before remediation.",
            }
        )
    if any(str(row.get("source") or "") in {"http", "json", "json_api"} for row in results):
        plan.append(
            {
                "type": "http_repro",
                "title": "Reproduce HTTP/API check from the server",
                "command_hint": "curl -iL <url>",
                "reason": "Server-side reproduction separates real service failure from monitor config mismatch.",
            }
        )
    remediation = config.raw.get("remediation", {}) if config else {}
    if isinstance(remediation, dict) and remediation.get("playbooks"):
        plan.append(
            {
                "type": "playbook_match",
                "title": "Review matching remediation playbooks",
                "command_hint": "GET /api/incidents/<id>/playbook-matches",
                "reason": "Use reviewed playbooks for repeatable diagnosis and recovery.",
            }
        )
    return plan


def next_decision(causes: list[dict[str, Any]], incident: dict[str, Any]) -> dict[str, Any]:
    top = causes[0] if causes else {"category": "unknown", "confidence": 0.0}
    confidence = float(top.get("confidence") or 0)
    if confidence >= 0.8:
        action = "collect_targeted_evidence"
    elif confidence >= 0.6:
        action = "confirm_with_additional_signals"
    else:
        action = "manual_triage"
    return {
        "action": action,
        "reason": f"Top cause {top.get('category')} confidence={confidence}.",
        "safe_to_auto_remediate": False,
        "requires_human_confirmation": str(incident.get("severity") or "") == "critical" or confidence < 0.9,
    }


def parse_json_list(value: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []
