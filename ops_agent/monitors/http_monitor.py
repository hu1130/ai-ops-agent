from __future__ import annotations

import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit, urlunsplit
from typing import Any

from ops_agent.events import CheckResult

DEFAULT_FALLBACK_URLS = ["/", "/login", "/signin"]
REACHABLE_STATUS_CODES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}
FALLBACK_DIAGNOSABLE_STATUS_CODES = {400, 401, 403, 404, 405, 410}


def run_http_checks(checks: list[dict[str, Any]]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in checks:
        results.append(run_http_check(check))
    return results


def run_http_check(check: dict[str, Any]) -> CheckResult:
    name = str(check.get("name") or check.get("url") or "HTTP check")
    url = str(check["url"])
    method = str(check.get("method", "GET")).upper()
    timeout = float(check.get("timeout_seconds", 5))
    expected_status = int(check.get("expected_status", 200))
    max_latency_ms = int(check.get("max_latency_ms", 3000))

    request = urllib.request.Request(url=url, method=method, headers={"User-Agent": "ops-agent/0.1"})
    start = time.perf_counter()
    max_response_bytes = int(check.get("max_response_bytes", 4096))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(max_response_bytes)
            status_code = int(response.status)
    except urllib.error.HTTPError as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        attempts = fallback_attempts(check, url, timeout) if should_try_fallback(exc.code, expected_status) else []
        fallback = first_reachable(attempts)
        if fallback:
            return fallback_reachable_result(name, url, exc.code, latency_ms, fallback, check)
        return CheckResult(
            source="http",
            name=name,
            status="critical",
            summary=f"HTTP {exc.code} from {url}",
            details={
                "url": url,
                "status_code": exc.code,
                "latency_ms": latency_ms,
                "error": str(exc),
                "fallback_attempts": attempts,
                **alert_policy_details(check),
            },
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return CheckResult(
            source="http",
            name=name,
            status="critical",
            summary=f"Request failed for {url}: {exc}",
            details={"url": url, "latency_ms": latency_ms, "error": repr(exc), **alert_policy_details(check)},
        )

    latency_ms = int((time.perf_counter() - start) * 1000)
    text = body.decode("utf-8", errors="replace")
    content_error = validate_http_content(text, check)
    if status_code != expected_status:
        attempts = fallback_attempts(check, url, timeout) if should_try_fallback(status_code, expected_status) else []
        fallback = first_reachable(attempts)
        if fallback:
            return fallback_reachable_result(name, url, status_code, latency_ms, fallback, check, expected_status)
        status = "critical"
        summary = f"Unexpected HTTP {status_code}, expected {expected_status}"
    elif latency_ms > max_latency_ms:
        status = "warning"
        summary = f"Slow response: {latency_ms} ms"
    elif content_error:
        status = content_mismatch_status(check)
        summary = content_error
    else:
        status = "ok"
        summary = f"HTTP {status_code} in {latency_ms} ms"

    return CheckResult(
        source="http",
        name=name,
        status=status,
        summary=summary,
        details={
            "url": url,
            "status_code": status_code,
            "expected_status": expected_status,
            "latency_ms": latency_ms,
            "sample": text[:500],
            "content_validation": content_validation_details(check, content_error),
            **alert_policy_details(check),
            "fallback_attempts": attempts if status_code != expected_status else [],
        },
    )


def diagnose_fallback(check: dict[str, Any], primary_url: str, timeout: float) -> dict[str, Any] | None:
    return first_reachable(fallback_attempts(check, primary_url, timeout))


def first_reachable(attempts: list[dict[str, Any]]) -> dict[str, Any] | None:
    for attempt in attempts:
        if attempt.get("reachable"):
            return attempt
    return None


def fallback_attempts(check: dict[str, Any], primary_url: str, timeout: float) -> list[dict[str, Any]]:
    urls = fallback_urls(check, primary_url)
    if not urls:
        return []
    expected_statuses = fallback_expected_statuses(check)
    attempts: list[dict[str, Any]] = []
    for url in urls:
        attempts.append(probe_fallback_url(url, timeout, expected_statuses))
    return attempts


def fallback_urls(check: dict[str, Any], primary_url: str) -> list[str]:
    if check.get("fallback_enabled", True) is False:
        return []
    values = check.get("fallback_urls", DEFAULT_FALLBACK_URLS)
    if not isinstance(values, list) or not values:
        values = DEFAULT_FALLBACK_URLS
    urls: list[str] = []
    seen: set[str] = set()
    primary_key = comparable_url(primary_url)
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        url = urljoin(primary_url, text)
        key = comparable_url(url)
        if key == primary_key or key in seen:
            continue
        seen.add(key)
        urls.append(url)
    return urls


def comparable_url(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


def fallback_expected_statuses(check: dict[str, Any]) -> set[int]:
    values = check.get("fallback_expected_statuses", [])
    if not isinstance(values, list) or not values:
        return set(REACHABLE_STATUS_CODES)
    statuses: set[int] = set()
    for value in values:
        try:
            statuses.add(int(value))
        except (TypeError, ValueError):
            continue
    return statuses or set(REACHABLE_STATUS_CODES)


def probe_fallback_url(url: str, timeout: float, expected_statuses: set[int]) -> dict[str, Any]:
    request = urllib.request.Request(url=url, method="GET", headers={"User-Agent": "ops-agent/0.1"})
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(256)
            status_code = int(response.status)
            latency_ms = int((time.perf_counter() - start) * 1000)
            return {
                "url": url,
                "status_code": status_code,
                "latency_ms": latency_ms,
                "reachable": status_code in expected_statuses,
                "sample": body.decode("utf-8", errors="replace")[:120],
            }
    except urllib.error.HTTPError as exc:
        sample = exc.read(256).decode("utf-8", errors="replace")
        latency_ms = int((time.perf_counter() - start) * 1000)
        return {
            "url": url,
            "status_code": int(exc.code),
            "latency_ms": latency_ms,
            "reachable": int(exc.code) in expected_statuses,
            "error": str(exc),
            "sample": sample[:120],
        }
    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return {
            "url": url,
            "latency_ms": latency_ms,
            "reachable": False,
            "error": repr(exc),
        }


def fallback_reachable_result(
    name: str,
    primary_url: str,
    primary_status_code: int,
    primary_latency_ms: int,
    fallback: dict[str, Any],
    check: dict[str, Any],
    expected_status: int | None = None,
) -> CheckResult:
    status = fallback_success_status(check)
    expected_text = f", expected {expected_status}" if expected_status is not None else ""
    classification = fallback_classification(primary_status_code, expected_status)
    summary = (
        f"{classification}: primary HTTP {primary_status_code}{expected_text}; "
        f"fallback reachable: {fallback['url']} HTTP {fallback.get('status_code')}"
    )
    return CheckResult(
        source="http",
        name=name,
        status=status,
        summary=summary,
        details={
            "url": primary_url,
            "status_code": primary_status_code,
            "latency_ms": primary_latency_ms,
            "classification": classification,
            "fallback": fallback,
            "fallback_success_status": status,
            **alert_policy_details(check),
        },
    )


def should_try_fallback(status_code: int, expected_status: int) -> bool:
    if status_code >= 500:
        return False
    if status_code in FALLBACK_DIAGNOSABLE_STATUS_CODES:
        return True
    return status_code != expected_status


def fallback_classification(primary_status_code: int, expected_status: int | None = None) -> str:
    if primary_status_code in {404, 410}:
        return "primary_route_missing_fallback_reachable"
    if primary_status_code in {401, 403}:
        return "primary_auth_required_fallback_reachable"
    if primary_status_code == 405:
        return "primary_method_not_allowed_fallback_reachable"
    if expected_status is not None and primary_status_code != expected_status:
        return "primary_status_mismatch_fallback_reachable"
    return "primary_failed_fallback_reachable"


def fallback_success_status(check: dict[str, Any]) -> str:
    value = str(check.get("fallback_success_status", "warning")).strip().lower()
    if value in {"ok", "warning", "critical"}:
        return value
    return "warning"


def validate_http_content(text: str, check: dict[str, Any]) -> str:
    required_texts = clean_string_list(check.get("required_texts"))
    for required in required_texts:
        if required not in text:
            return f"Missing required response text: {required}"
    forbidden_texts = clean_string_list(check.get("forbidden_texts"))
    lower_text = text.lower()
    for forbidden in forbidden_texts:
        if forbidden.lower() in lower_text:
            return f"Response contains forbidden text: {forbidden}"
    min_body_bytes = int(check.get("min_body_bytes", 0) or 0)
    if min_body_bytes > 0 and len(text.encode("utf-8")) < min_body_bytes:
        return f"Response body too small: {len(text.encode('utf-8'))} bytes, expected at least {min_body_bytes}"
    return ""


def content_mismatch_status(check: dict[str, Any]) -> str:
    value = str(check.get("status_on_content_mismatch", "critical")).strip().lower()
    if value in {"warning", "critical"}:
        return value
    return "critical"


def content_validation_details(check: dict[str, Any], error: str) -> dict[str, Any]:
    return {
        "required_texts": clean_string_list(check.get("required_texts")),
        "forbidden_texts": clean_string_list(check.get("forbidden_texts")),
        "min_body_bytes": int(check.get("min_body_bytes", 0) or 0),
        "error": error,
    }


def alert_policy_details(check: dict[str, Any]) -> dict[str, Any]:
    value = check.get("alert_after_failures", check.get("consecutive_failures"))
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return {}
    return {"alert_after_failures": parsed} if parsed > 0 else {}


def clean_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]
