from __future__ import annotations

import time
import urllib.error
import urllib.request
from urllib.parse import urljoin
from typing import Any

from ops_agent.events import CheckResult

REACHABLE_STATUS_CODES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}


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
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(512)
            status_code = int(response.status)
    except urllib.error.HTTPError as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        attempts = fallback_attempts(check, url, timeout)
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
            },
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return CheckResult(
            source="http",
            name=name,
            status="critical",
            summary=f"Request failed for {url}: {exc}",
            details={"url": url, "latency_ms": latency_ms, "error": repr(exc)},
        )

    latency_ms = int((time.perf_counter() - start) * 1000)
    if status_code != expected_status:
        attempts = fallback_attempts(check, url, timeout)
        fallback = first_reachable(attempts)
        if fallback:
            return fallback_reachable_result(name, url, status_code, latency_ms, fallback, check, expected_status)
        status = "critical"
        summary = f"Unexpected HTTP {status_code}, expected {expected_status}"
    elif latency_ms > max_latency_ms:
        status = "warning"
        summary = f"Slow response: {latency_ms} ms"
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
            "sample": body.decode("utf-8", errors="replace")[:200],
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
    values = check.get("fallback_urls", [])
    if not isinstance(values, list):
        return []
    urls: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        urls.append(urljoin(primary_url, text))
    return urls


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
    summary = (
        f"Primary HTTP {primary_status_code}{expected_text}; "
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
            "classification": "primary_failed_fallback_reachable",
            "fallback": fallback,
            "fallback_success_status": status,
        },
    )


def fallback_success_status(check: dict[str, Any]) -> str:
    value = str(check.get("fallback_success_status", "warning")).strip().lower()
    if value in {"ok", "warning", "critical"}:
        return value
    return "warning"
