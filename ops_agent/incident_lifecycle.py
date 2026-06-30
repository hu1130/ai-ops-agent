from __future__ import annotations

from typing import Any

INCIDENT_STATUSES = {
    "open",
    "acknowledged",
    "remediating",
    "verifying",
    "resolved",
    "closed",
}

ALLOWED_TRANSITIONS = {
    "open": {"acknowledged", "remediating", "verifying", "resolved", "closed"},
    "acknowledged": {"remediating", "verifying", "resolved", "closed"},
    "remediating": {"verifying", "resolved", "closed"},
    "verifying": {"remediating", "resolved", "closed"},
    "resolved": {"closed"},
    "closed": set(),
}


def initial_incident_status(severity: str) -> str:
    return "resolved" if severity == "ok" else "open"


def validate_incident_status(value: str) -> str:
    status = value.strip().lower()
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"invalid incident status: {value}")
    return status


def can_transition(from_status: str, to_status: str) -> bool:
    source = validate_incident_status(from_status)
    target = validate_incident_status(to_status)
    return source == target or target in ALLOWED_TRANSITIONS[source]


def validate_transition(from_status: str, to_status: str) -> tuple[str, str]:
    source = validate_incident_status(from_status)
    target = validate_incident_status(to_status)
    if not can_transition(source, target):
        raise ValueError(f"invalid incident transition: {source} -> {target}")
    return source, target


def lifecycle_payload(actor: str = "system", note: str = "", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "actor": actor.strip() or "system",
        "note": note.strip(),
        "metadata": metadata or {},
    }
