from __future__ import annotations

from typing import Any


UNKNOWN_CATEGORIES = {"", "unknown", "unclassified"}


def build_learning_recommendations(incidents: list[dict], settings: dict | None = None) -> list[dict]:
    settings = settings or {}
    confidence_threshold = safe_float(settings.get("confidence_threshold"), 0.65)
    frequent_occurrence_threshold = safe_int(settings.get("frequent_occurrence_threshold"), 10)
    frequent_open_category_threshold = safe_int(settings.get("frequent_open_category_threshold"), 3)
    min_unknown_count = safe_int(settings.get("min_unknown_count"), 1)
    min_low_confidence_count = safe_int(settings.get("min_low_confidence_count"), 1)

    problem_rows = [row for row in incidents if str(row.get("severity") or "") != "ok"]
    active_problem_rows = [
        row
        for row in problem_rows
        if str(row.get("status") or "open") not in {"resolved", "closed"}
    ]
    recommendations: dict[str, dict] = {}

    unknown_rows = [
        row
        for row in problem_rows
        if incident_category(row) in UNKNOWN_CATEGORIES
    ]
    if len(unknown_rows) >= min_unknown_count:
        add_recommendation(
            recommendations,
            recommendation(
                trigger_type="unknown_classification",
                category="unknown",
                priority="high" if any(is_active(row) for row in unknown_rows) else "medium",
                title="Review unknown or unclassified incident signals",
                reason=(
                    f"{len(unknown_rows)} recent problem incident(s) have no stable classification. "
                    "These signals cannot drive reliable playbooks until they are labeled."
                ),
                recommended_action=(
                    "Review the evidence examples, assign the correct category, then add classifier rules "
                    "or monitor fallback logic for the repeated signal pattern."
                ),
                rows=unknown_rows,
                metrics={
                    "incident_count": len(unknown_rows),
                    "active_count": sum(1 for row in unknown_rows if is_active(row)),
                },
            ),
        )

    for category, rows in grouped_by_category(problem_rows).items():
        if category in UNKNOWN_CATEGORIES:
            continue
        low_confidence_rows = [
            row
            for row in rows
            if 0 < safe_float(row.get("classification_confidence")) < confidence_threshold
        ]
        if len(low_confidence_rows) < min_low_confidence_count:
            continue
        add_recommendation(
            recommendations,
            recommendation(
                trigger_type="low_confidence",
                category=category,
                priority="medium",
                title=f"Improve classifier confidence for {category}",
                reason=(
                    f"{len(low_confidence_rows)} recent {category} incident(s) were classified below "
                    f"confidence threshold {confidence_threshold:.2f}."
                ),
                recommended_action=(
                    "Compare their evidence fields against correctly classified incidents, then add more "
                    "specific keyword, status-code, source, or correlation rules."
                ),
                rows=low_confidence_rows,
                metrics={
                    "incident_count": len(low_confidence_rows),
                    "confidence_threshold": confidence_threshold,
                    "avg_confidence": average_confidence(low_confidence_rows),
                },
            ),
        )

    for row in active_problem_rows:
        occurrence_count = safe_int(row.get("occurrence_count"), 1)
        if occurrence_count < frequent_occurrence_threshold:
            continue
        title = str(row.get("title") or "incident")
        category = incident_category(row)
        add_recommendation(
            recommendations,
            recommendation(
                trigger_type="frequent_unresolved",
                category=category,
                priority="high" if str(row.get("severity") or "") == "critical" else "medium",
                title=f"Add a playbook for recurring incident #{row.get('id')}",
                reason=(
                    f"Incident #{row.get('id')} remains active and has occurred {occurrence_count} times: {title}."
                ),
                recommended_action=(
                    "Turn the repeated manual handling steps into a category or fingerprint-bound playbook, "
                    "and add post-action verification so repeated reminders can close automatically."
                ),
                rows=[row],
                metrics={
                    "occurrence_count": occurrence_count,
                    "threshold": frequent_occurrence_threshold,
                    "fingerprint": row.get("fingerprint") or "",
                },
            ),
        )

    for category, rows in grouped_by_category(active_problem_rows).items():
        if len(rows) < frequent_open_category_threshold:
            continue
        add_recommendation(
            recommendations,
            recommendation(
                trigger_type="frequent_open_category",
                category=category,
                priority="high",
                title=f"Tune remediation for frequent open {category} incidents",
                reason=f"{len(rows)} active problem incident(s) currently share category {category}.",
                recommended_action=(
                    "Review whether the category needs a stronger default playbook, better monitor thresholds, "
                    "or a more precise split into separate root-cause categories."
                ),
                rows=rows,
                metrics={
                    "active_count": len(rows),
                    "threshold": frequent_open_category_threshold,
                },
            ),
        )

    return sorted(
        recommendations.values(),
        key=lambda item: (priority_rank(str(item.get("priority"))), str(item.get("trigger_type")), str(item.get("category"))),
    )


def recommendation(
    trigger_type: str,
    category: str,
    priority: str,
    title: str,
    reason: str,
    recommended_action: str,
    rows: list[dict],
    metrics: dict,
) -> dict:
    dedupe_key = f"{trigger_type}:{category}:{dedupe_scope(rows)}"
    return {
        "dedupe_key": dedupe_key,
        "trigger_type": trigger_type,
        "category": category,
        "priority": priority,
        "title": title,
        "reason": reason,
        "recommended_action": recommended_action,
        "evidence": evidence_from_rows(rows),
        "incident_ids": incident_ids(rows),
        "metrics": metrics,
        "source": "classification_learning",
    }


def add_recommendation(recommendations: dict[str, dict], item: dict) -> None:
    key = str(item.get("dedupe_key") or "")
    if key and key not in recommendations:
        recommendations[key] = item


def grouped_by_category(rows: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(incident_category(row), []).append(row)
    return groups


def incident_category(row: dict) -> str:
    return str(row.get("classification_category") or "unclassified")


def is_active(row: dict) -> bool:
    return str(row.get("status") or "open") not in {"resolved", "closed"}


def incident_ids(rows: list[dict]) -> list[int]:
    ids: list[int] = []
    for row in rows:
        value = safe_int(row.get("id"), 0)
        if value > 0:
            ids.append(value)
    return ids


def evidence_from_rows(rows: list[dict], limit: int = 5) -> list[str]:
    evidence: list[str] = []
    for row in rows[:limit]:
        incident_id = row.get("id")
        category = incident_category(row)
        confidence = safe_float(row.get("classification_confidence"))
        summary = row.get("classification_summary") or row.get("last_summary") or row.get("title") or ""
        evidence.append(
            f"incident #{incident_id}: category={category}, confidence={confidence:.2f}, "
            f"severity={row.get('severity')}, status={row.get('status')}, summary={summary}"
        )
    return evidence


def dedupe_scope(rows: list[dict]) -> str:
    if len(rows) == 1:
        row = rows[0]
        fingerprint = str(row.get("fingerprint") or "").strip()
        if fingerprint:
            return fingerprint
        return f"incident-{row.get('id')}"
    environments = sorted({str(row.get("environment") or "prod") for row in rows})
    run_types = sorted({str(row.get("run_type") or "normal") for row in rows})
    return f"{','.join(environments)}:{','.join(run_types)}"


def average_confidence(rows: list[dict]) -> float:
    values = [safe_float(row.get("classification_confidence")) for row in rows]
    values = [value for value in values if value > 0]
    return round(sum(values) / len(values), 3) if values else 0.0


def priority_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def format_learning_recommendations(recommendations: list[dict]) -> str:
    lines = ["Ops Agent learning optimization suggestions", ""]
    for index, item in enumerate(recommendations, start=1):
        lines.extend(
            [
                f"{index}. [{item.get('priority')}] {item.get('title')}",
                f"   trigger: {item.get('trigger_type')}; category: {item.get('category')}",
                f"   reason: {item.get('reason')}",
                f"   action: {item.get('recommended_action')}",
            ]
        )
    return "\n".join(lines)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
