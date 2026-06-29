from __future__ import annotations

from dataclasses import dataclass
import time
import urllib.error
import urllib.request
from typing import Any, Literal

from ops_agent.config import AppConfig
from ops_agent.remediation.actions import RemediationAction

VerificationStatus = Literal["verify_skipped", "verified_ok", "verified_failed"]


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    output: str = ""
    error: str = ""


def verify_after_action(action: RemediationAction, config: AppConfig) -> VerificationResult:
    remediation = dict(config.raw.get("remediation", {}))
    verification_config = dict(remediation.get("verification", {}))
    if not verification_config.get("enabled", True):
        return VerificationResult(status="verify_skipped", output="执行后验证已关闭。")

    spec = action.params.get("verify_after")
    if not isinstance(spec, dict):
        return VerificationResult(status="verify_skipped", output="未配置执行后验证。")

    verify_type = str(spec.get("type", "http"))
    if verify_type != "http":
        return VerificationResult(status="verify_skipped", output=f"不支持的验证类型: {verify_type}")

    return verify_http(spec, verification_config)


def verify_http(spec: dict[str, Any], defaults: dict[str, Any]) -> VerificationResult:
    url = str(spec.get("url", "")).strip()
    if not url:
        return VerificationResult(status="verified_failed", error="verify_after.url 不能为空。")

    expected_status = int(spec.get("expected_status", 200))
    timeout = float(spec.get("timeout_seconds", defaults.get("timeout_seconds", 5)))
    wait_seconds = float(spec.get("wait_seconds", defaults.get("default_wait_seconds", 30)))
    retries = int(spec.get("retries", defaults.get("retries", 3)))
    interval_seconds = float(spec.get("interval_seconds", defaults.get("interval_seconds", 5)))

    if wait_seconds > 0:
        time.sleep(wait_seconds)

    last_error = ""
    for attempt in range(1, max(1, retries) + 1):
        try:
            request = urllib.request.Request(url=url, method="GET", headers={"User-Agent": "ops-agent/0.1"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(response.status)
                body = response.read(300).decode("utf-8", errors="replace")
            if status == expected_status:
                return VerificationResult(
                    status="verified_ok",
                    output=f"验证成功: HTTP {status} from {url} (attempt {attempt})",
                )
            last_error = f"HTTP {status}, expected {expected_status}. sample={body[:120]}"
        except urllib.error.HTTPError as exc:
            sample = exc.read(300).decode("utf-8", errors="replace")
            last_error = f"HTTP {exc.code}, expected {expected_status}. sample={sample[:120]}"
        except Exception as exc:
            last_error = str(exc)

        if attempt < retries and interval_seconds > 0:
            time.sleep(interval_seconds)

    return VerificationResult(status="verified_failed", error=f"验证失败: {url}: {last_error}")
