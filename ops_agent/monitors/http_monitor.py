from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Any

from ops_agent.events import CheckResult


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
        return CheckResult(
            source="http",
            name=name,
            status="critical",
            summary=f"HTTP {exc.code} from {url}",
            details={"url": url, "status_code": exc.code, "latency_ms": latency_ms, "error": str(exc)},
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
        },
    )
