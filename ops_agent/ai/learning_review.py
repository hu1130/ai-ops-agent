from __future__ import annotations

from typing import Any


CLASSIFIER_TRIGGERS = {"unknown_classification", "low_confidence"}
PLAYBOOK_TRIGGERS = {"frequent_unresolved", "frequent_open_category"}


def build_learning_optimization_draft(recommendation: dict) -> dict:
    trigger_type = str(recommendation.get("trigger_type") or "")
    if trigger_type in CLASSIFIER_TRIGGERS:
        return classifier_rule_draft(recommendation)
    if trigger_type in PLAYBOOK_TRIGGERS:
        return playbook_draft(recommendation)
    return generic_review_draft(recommendation)


def classifier_rule_draft(recommendation: dict) -> dict:
    category = str(recommendation.get("category") or "unknown")
    evidence = safe_list(recommendation.get("evidence"))
    metrics = safe_dict(recommendation.get("metrics"))
    return base_draft(
        recommendation,
        draft_type="classifier_rule",
        recommended_change=(
            "Add or tune classifier rules for this signal pattern. Keep it as a draft until "
            "a human confirms the target category and false-positive risk."
        ),
        candidate={
            "category": "" if category in {"unknown", "unclassified"} else category,
            "conditions": {
                "trigger_type": recommendation.get("trigger_type") or "",
                "source_pattern": infer_source_pattern(evidence),
                "summary_keywords": infer_keywords(evidence),
                "confidence_below": metrics.get("confidence_threshold"),
            },
            "confidence_floor": 0.75,
            "notes": [
                "Confirm the target category before converting this draft into code.",
                "Use at least one negative example to avoid turning a temporary outage into a noisy rule.",
            ],
        },
    )


def playbook_draft(recommendation: dict) -> dict:
    category = str(recommendation.get("category") or "")
    metrics = safe_dict(recommendation.get("metrics"))
    return base_draft(
        recommendation,
        draft_type="playbook",
        recommended_change=(
            "Create or tune a playbook for the repeated signal, then require post-action "
            "verification before the incident is closed."
        ),
        candidate={
            "match": {
                "categories": [category] if category else [],
                "fingerprint": metrics.get("fingerprint") or "",
            },
            "steps": [
                {
                    "action_type": "run_diagnostic_command",
                    "title": "Collect current service evidence",
                    "approval_required": False,
                    "verification_required": False,
                },
                {
                    "action_type": "restart_service",
                    "title": "Restart the affected service when policy allows it",
                    "approval_required": True,
                    "verification_required": True,
                },
            ],
            "notes": [
                "Bind service names through the policy allowlist before enabling restart actions.",
                "Keep this as a draft until the owner confirms the safe remediation path.",
            ],
        },
    )


def generic_review_draft(recommendation: dict) -> dict:
    return base_draft(
        recommendation,
        draft_type="review_task",
        recommended_change="Review this suggestion and decide whether it should become a classifier rule or playbook.",
        candidate={
            "notes": [
                "No specialized draft builder matched this trigger type.",
                "Keep the decision and evidence in the recommendation record.",
            ]
        },
    )


def base_draft(
    recommendation: dict,
    draft_type: str,
    recommended_change: str,
    candidate: dict,
) -> dict:
    return {
        "draft_type": draft_type,
        "status": "draft",
        "title": recommendation.get("title") or "",
        "category": recommendation.get("category") or "",
        "trigger_type": recommendation.get("trigger_type") or "",
        "dedupe_key": recommendation.get("dedupe_key") or "",
        "recommended_change": recommended_change,
        "candidate": candidate,
        "evidence": safe_list(recommendation.get("evidence")),
        "incident_ids": safe_list(recommendation.get("incident_ids")),
        "metrics": safe_dict(recommendation.get("metrics")),
        "review_required": True,
    }


def infer_source_pattern(evidence: list) -> str:
    for value in evidence:
        text = str(value)
        marker = "summary="
        if marker in text:
            prefix = text.split(marker, 1)[0]
            if "/" in prefix:
                return prefix.strip()
    return ""


def infer_keywords(evidence: list, limit: int = 8) -> list[str]:
    words: list[str] = []
    stop_words = {
        "incident",
        "category",
        "confidence",
        "severity",
        "status",
        "summary",
        "unknown",
        "unclassified",
    }
    for value in evidence:
        normalized = "".join(ch.lower() if ch.isalnum() else " " for ch in str(value))
        for word in normalized.split():
            if len(word) < 4 or word in stop_words or word.isdigit():
                continue
            if word not in words:
                words.append(word)
            if len(words) >= limit:
                return words
    return words


def safe_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []
