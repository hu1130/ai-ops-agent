from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from ops_agent.config import AppConfig, load_config
from ops_agent.diagnostics.collector import collect_diagnostics, format_snapshot
from ops_agent.events import CheckResult


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Ops Agent tools")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("diagnose", help="Print a local diagnostic snapshot")
    subparsers.add_parser("validate-config", help="Validate config structure and common mistakes")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"配置读取失败: {exc}", file=sys.stderr)
        return 2

    if args.command == "diagnose":
        synthetic = [CheckResult(source="manual", name="diagnose", status="warning", summary="Manual diagnostic run")]
        text = format_snapshot(collect_diagnostics(synthetic, config))
        print(text.strip() or "未采集到诊断信息。")
        return 0

    if args.command == "validate-config":
        errors = validate_config(config)
        if errors:
            print("配置校验未通过:")
            for error in errors:
                print(f"- {error}")
            return 1
        print("配置校验通过。")
        return 0

    return 2


def validate_config(config: AppConfig) -> list[str]:
    errors: list[str] = []
    validate_positive_int(config.app.get("interval_seconds", 60), "app.interval_seconds", errors)

    for index, check in enumerate(config.http_checks):
        validate_url(str(check.get("url", "")), f"http_checks[{index}].url", errors)
        validate_positive_int(check.get("timeout_seconds", 5), f"http_checks[{index}].timeout_seconds", errors)

    for index, check in enumerate(config.json_checks):
        validate_url(str(check.get("url", "")), f"json_checks[{index}].url", errors)
        validate_positive_int(check.get("timeout_seconds", 20), f"json_checks[{index}].timeout_seconds", errors)
        validate_positive_int(check.get("interval_seconds", config.app.get("interval_seconds", 60)), f"json_checks[{index}].interval_seconds", errors)

    for index, check in enumerate(config.log_checks):
        path_value = str(check.get("path", ""))
        if not path_value:
            errors.append(f"log_checks[{index}].path 不能为空")
            continue
        path = config.resolve_path(path_value)
        if not path.exists():
            errors.append(f"log_checks[{index}].path 不存在: {path_value}")

    alerts = config.alerts
    validate_positive_int(alerts.get("consecutive_failures", 2), "alerts.consecutive_failures", errors)
    validate_positive_int(alerts.get("cooldown_seconds", 300), "alerts.cooldown_seconds", errors)

    email = dict(alerts.get("email", {}))
    if email.get("enabled", False):
        required = ["smtp_host", "smtp_port", "username", "password", "to_emails"]
        for key in required:
            if not email.get(key):
                errors.append(f"alerts.email.{key} 不能为空")

    return errors


def validate_url(value: str, field: str, errors: list[str]) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        errors.append(f"{field} 必须是 http/https URL")


def validate_positive_int(value: object, field: str, errors: list[str]) -> None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        errors.append(f"{field} 必须是数字")
        return
    if number <= 0:
        errors.append(f"{field} 必须大于 0")


if __name__ == "__main__":
    raise SystemExit(main())
