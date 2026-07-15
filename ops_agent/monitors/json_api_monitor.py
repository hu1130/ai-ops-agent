from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from ops_agent.events import CheckResult


def run_json_checks(checks: list[dict[str, Any]]) -> list[CheckResult]:
    return [run_json_check(check) for check in checks]


def run_json_check(check: dict[str, Any]) -> CheckResult:
    name = str(check.get("name") or check.get("url") or "JSON API check")
    url = str(check["url"])
    timeout = float(check.get("timeout_seconds", 15))
    expected_status = int(check.get("expected_status", 200))
    max_latency_ms = int(check.get("max_latency_ms", 10000))
    payload = expand_dynamic_values(check.get("json", {}))
    headers = {"Content-Type": "application/json", "User-Agent": "ops-agent/0.1"}
    headers.update({str(key): str(value) for key, value in check.get("headers", {}).items()})

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url=url, data=body, method="POST", headers=headers)
    start = time.perf_counter()

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(int(check.get("max_response_bytes", 65536)))
            status_code = int(response.status)
    except urllib.error.HTTPError as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        error_body = exc.read(2048).decode("utf-8", errors="replace")
        return CheckResult(
            source="json_api",
            name=name,
            status="critical",
            summary=f"HTTP {exc.code} from {url}",
            details={"url": url, "status_code": exc.code, "latency_ms": latency_ms, "error": error_body, **alert_policy_details(check)},
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return CheckResult(
            source="json_api",
            name=name,
            status="critical",
            summary=f"Request failed for {url}: {exc}",
            details={"url": url, "latency_ms": latency_ms, "error": repr(exc), **alert_policy_details(check)},
        )

    latency_ms = int((time.perf_counter() - start) * 1000)
    text = response_body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return CheckResult(
            source="json_api",
            name=name,
            status="critical",
            summary="Response is not valid JSON",
            details={
                "url": url,
                "status_code": status_code,
                "latency_ms": latency_ms,
                "error": str(exc),
                "sample": text[:500],
                **alert_policy_details(check),
            },
        )

    validation_error = validate_json_response(parsed, check)
    bad_phrase = find_bad_phrase(parsed, [str(item) for item in check.get("bad_phrases", [])])

    if status_code != expected_status:
        status = "critical"
        summary = f"Unexpected HTTP {status_code}, expected {expected_status}"
    elif latency_ms > max_latency_ms:
        status = "warning"
        summary = f"Slow response: {latency_ms} ms"
    elif validation_error:
        status = "critical"
        summary = validation_error
    elif bad_phrase:
        status = "warning"
        summary = f"Response contains suspicious phrase: {bad_phrase}"
    else:
        status = "ok"
        summary = f"JSON API OK in {latency_ms} ms"

    return CheckResult(
        source="json_api",
        name=name,
        status=status,
        summary=summary,
        details={
            "url": url,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "response_sample": text[:800],
            **alert_policy_details(check),
        },
    )


def validate_json_response(parsed: Any, check: dict[str, Any]) -> str:
    required_paths = [str(item) for item in check.get("required_paths", [])]
    for path in required_paths:
        value = get_path(parsed, path)
        if value is None:
            return f"Missing required JSON path: {path}"
        if check.get("require_non_empty", True) and value == "":
            return f"Required JSON path is empty: {path}"
        if isinstance(value, list) and check.get("require_non_empty", True) and not value:
            return f"Required JSON path is empty: {path}"
    return ""


def get_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return None
        if current is None:
            return None
    return current


def find_bad_phrase(value: Any, phrases: list[str]) -> str:
    if not phrases:
        return ""
    text = json.dumps(value, ensure_ascii=False).lower()
    for phrase in phrases:
        if phrase.lower() in text:
            return phrase
    return ""


def expand_dynamic_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: expand_dynamic_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [expand_dynamic_values(item) for item in value]
    if isinstance(value, str):
        return (
            value.replace("{{uuid}}", uuid.uuid4().hex)
            .replace("{{timestamp}}", str(int(time.time())))
        )
    return value


def alert_policy_details(check: dict[str, Any]) -> dict[str, Any]:
    details: dict[str, Any] = {}
    value = check.get("alert_after_failures", check.get("consecutive_failures"))
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = 0
    if parsed > 0:
        details["alert_after_failures"] = parsed
    recovery_value = check.get("recovery_after_successes", check.get("consecutive_successes"))
    try:
        recovery_parsed = int(recovery_value)
    except (TypeError, ValueError):
        recovery_parsed = 0
    if recovery_parsed > 0:
        details["recovery_after_successes"] = recovery_parsed
    return details
