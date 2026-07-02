from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Any

from ops_agent.ai.classifier import classify_signal
from ops_agent.events import CheckResult


@dataclass(frozen=True)
class AlertContext:
    severity: str
    title: str
    sources: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    summaries: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    environment: str = "prod"
    run_type: str = "normal"


@dataclass(frozen=True)
class AlertRouteDecision:
    suppressed: bool = False
    reason: str = ""
    route_names: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    dedupe_suffix: str = ""


def alert_context_from_results(
    results: list[CheckResult],
    severity: str = "",
    title: str = "",
    classification_rules: list[dict[str, Any]] | None = None,
) -> AlertContext:
    statuses = unique_texts(result.status for result in results)
    inferred_severity = severity or infer_severity(statuses)
    problem_results = [result for result in results if result.is_problem]
    categories = unique_texts(
        classify_signal(result, classification_rules).category
        for result in problem_results
    )
    return AlertContext(
        severity=inferred_severity,
        title=title,
        sources=unique_texts(result.source for result in results),
        statuses=statuses,
        names=unique_texts(result.name for result in results),
        summaries=unique_texts(result.summary for result in results),
        categories=categories,
        environment=common_text([result.environment for result in results], "prod"),
        run_type=common_text([result.run_type for result in results], "normal"),
    )


def route_alert(
    alerts: dict[str, Any],
    context: AlertContext,
    now: datetime | None = None,
) -> AlertRouteDecision:
    silence = matching_silence_window(alerts, context, now)
    if silence:
        return AlertRouteDecision(
            suppressed=True,
            reason=f"silence window: {silence}",
            dedupe_suffix=f"silenced:{slug(silence)}",
        )

    matched_routes = []
    routes = alerts.get("routes", [])
    if isinstance(routes, list):
        for index, route in enumerate(routes, start=1):
            if not isinstance(route, dict) or not route.get("enabled", True):
                continue
            match = route.get("match", {})
            if isinstance(match, dict) and alert_matches(context, match):
                matched_routes.append((index, route))

    if matched_routes:
        route_names = [
            str(route.get("name") or f"route-{index}").strip()
            for index, route in matched_routes
        ]
        channels = unique_texts(
            channel
            for _, route in matched_routes
            for channel in route_channels(route)
        )
        if not channels:
            channels = default_channels(alerts)
        dedupe_parts = route_names + channels
        return AlertRouteDecision(
            route_names=route_names,
            channels=channels,
            dedupe_suffix=":".join(slug(part) for part in dedupe_parts if part),
        )

    channels = default_channels(alerts)
    if channels:
        return AlertRouteDecision(
            route_names=["default"],
            channels=channels,
            dedupe_suffix=":".join(["default", *[slug(channel) for channel in channels]]),
        )
    return AlertRouteDecision()


def alert_matches(context: AlertContext, match: dict[str, Any]) -> bool:
    if not any_value_matches(context.sources, match.get("sources")):
        return False
    if not any_value_matches(context.statuses, match.get("statuses")):
        return False
    if not exact_value_matches(context.severity, match.get("severities")):
        return False
    if not any_value_matches(context.categories, match.get("categories")):
        return False
    if not any_value_matches(context.names, match.get("names")):
        return False
    if not exact_value_matches(context.environment, match.get("environments")):
        return False
    if not exact_value_matches(context.run_type, match.get("run_types")):
        return False
    if not contains_any(context.names, match.get("name_contains")):
        return False
    if not contains_any(context.summaries, match.get("summary_contains")):
        return False
    if not contains_any([context.title], match.get("title_contains")):
        return False
    return True


def matching_silence_window(
    alerts: dict[str, Any],
    context: AlertContext,
    now: datetime | None = None,
) -> str:
    windows = alerts.get("silence_windows", [])
    if not isinstance(windows, list):
        return ""
    for index, window in enumerate(windows, start=1):
        if not isinstance(window, dict) or not window.get("enabled", True):
            continue
        match = window.get("match", {})
        if isinstance(match, dict) and not alert_matches(context, match):
            continue
        if in_silence_window(window, now):
            return str(window.get("name") or f"window-{index}").strip()
    return ""


def in_silence_window(window: dict[str, Any], now: datetime | None = None) -> bool:
    start = parse_hhmm(str(window.get("start", "")))
    end = parse_hhmm(str(window.get("end", "")))
    if not start or not end:
        return False
    current = now or datetime.now(timezone.utc)
    current = current.astimezone(parse_timezone(str(window.get("timezone", "+00:00"))))
    current_time = current.time().replace(second=0, microsecond=0)
    if start == end:
        return True
    if start < end:
        return start <= current_time < end
    return current_time >= start or current_time < end


def format_routing_header(decision: AlertRouteDecision) -> str:
    if not decision.route_names and not decision.channels:
        return ""
    lines = ["Alert routing:"]
    if decision.route_names:
        lines.append(f"- routes: {', '.join(decision.route_names)}")
    if decision.channels:
        lines.append(f"- channels: {', '.join(decision.channels)}")
    return "\n".join(lines)


def routed_dedupe_key(base_key: str, decision: AlertRouteDecision) -> str:
    if not decision.dedupe_suffix:
        return base_key
    return f"{base_key}|route:{decision.dedupe_suffix}"


def route_channels(route: dict[str, Any]) -> list[str]:
    channels = route.get("channels", [])
    return [str(item).strip() for item in channels if str(item).strip()] if isinstance(channels, list) else []


def default_channels(alerts: dict[str, Any]) -> list[str]:
    channels = alerts.get("default_channels", [])
    return [str(item).strip() for item in channels if str(item).strip()] if isinstance(channels, list) else []


def infer_severity(statuses: list[str]) -> str:
    if "critical" in statuses:
        return "critical"
    if "warning" in statuses:
        return "warning"
    if "ok" in statuses:
        return "ok"
    return ""


def any_value_matches(values: list[str], candidates: object) -> bool:
    if not candidates:
        return True
    candidate_set = normalized_set(candidates)
    if not candidate_set:
        return False
    return "*" in candidate_set or any(value in candidate_set for value in values)


def exact_value_matches(value: str, candidates: object) -> bool:
    if not candidates:
        return True
    candidate_set = normalized_set(candidates)
    if not candidate_set:
        return False
    return "*" in candidate_set or value in candidate_set


def contains_any(values: list[str], candidates: object) -> bool:
    if not candidates:
        return True
    needles = [str(item).strip().casefold() for item in candidates] if isinstance(candidates, list) else []
    if not needles:
        return False
    haystack = "\n".join(values).casefold()
    return any(needle and needle in haystack for needle in needles)


def normalized_set(candidates: object) -> set[str]:
    if not isinstance(candidates, list):
        return set()
    return {str(item).strip() for item in candidates if str(item).strip()}


def parse_hhmm(value: str) -> time | None:
    parts = value.strip().split(":")
    if len(parts) != 2:
        return None
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return None
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return None
    return time(hour, minute)


def parse_timezone(value: str) -> timezone:
    text = value.strip()
    if text in {"Z", "UTC", "+00:00", "-00:00"}:
        return timezone.utc
    sign = 1
    if text.startswith("-"):
        sign = -1
    if not text.startswith(("+", "-")):
        return timezone.utc
    parts = text[1:].split(":")
    if len(parts) != 2:
        return timezone.utc
    try:
        hours = int(parts[0])
        minutes = int(parts[1])
    except ValueError:
        return timezone.utc
    if hours > 23 or minutes > 59:
        return timezone.utc
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def unique_texts(values) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def common_text(values: list[str], default: str) -> str:
    cleaned = unique_texts(values)
    if not cleaned:
        return default
    if len(cleaned) == 1:
        return cleaned[0]
    return "mixed"


def slug(value: str) -> str:
    text = str(value or "").strip().casefold()
    cleaned = []
    for char in text:
        if char.isalnum():
            cleaned.append(char)
        elif char in {"-", "_", "."}:
            cleaned.append(char)
        elif char.isspace() or char in {":", "/", "|", ","}:
            cleaned.append("-")
    return "".join(cleaned).strip("-") or "default"
