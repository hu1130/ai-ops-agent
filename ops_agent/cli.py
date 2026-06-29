from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from ops_agent.config import AppConfig, load_config
from ops_agent.diagnostics.collector import collect_diagnostics, format_snapshot
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import RemediationAction
from ops_agent.remediation.executor import execute_action, format_action_plan
from ops_agent.remediation.planner import build_remediation_plan
from ops_agent.storage import Storage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Ops Agent tools")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("diagnose", help="Print a local diagnostic snapshot")
    subparsers.add_parser("validate-config", help="Validate config structure and common mistakes")

    plan_parser = subparsers.add_parser("remediation-plan", help="Build a remediation plan for a synthetic issue")
    plan_parser.add_argument("--source", default="json_api", help="Issue source, for example http/json_api/log/server")
    plan_parser.add_argument("--name", default="Manual issue", help="Issue name")
    plan_parser.add_argument("--status", default="warning", choices=["warning", "critical"], help="Issue severity")
    plan_parser.add_argument("--summary", default="Manual remediation planning", help="Issue summary")
    plan_parser.add_argument("--url", default="", help="Related URL for http/json_api issues")
    plan_parser.add_argument("--path", default="", help="Related log path for log issues")

    run_parser = subparsers.add_parser("run-action", help="Run a single safe remediation action")
    run_parser.add_argument("--type", required=True, help="Action type")
    run_parser.add_argument("--host", default="", help="Host for check_port")
    run_parser.add_argument("--port", type=int, default=0, help="Port for check_port")
    run_parser.add_argument("--command", dest="diagnostic_command", default="", help="Read-only diagnostic command")
    run_parser.add_argument("--execute", action="store_true", help="Actually execute safe actions; default is dry-run")

    subparsers.add_parser("action-logs", help="Show latest remediation action audit logs")
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

    if args.command == "remediation-plan":
        details = {}
        if args.url:
            details["url"] = args.url
        if args.path:
            details["path"] = args.path
        issue = CheckResult(
            source=args.source,
            name=args.name,
            status=args.status,
            summary=args.summary,
            details=details,
        )
        actions = build_remediation_plan([issue], config)
        print(format_action_plan(actions) or "没有生成处置计划。")
        return 0

    if args.command == "run-action":
        action = build_cli_action(args)
        result = execute_action(action, config, dry_run=not args.execute)
        storage = open_storage(config)
        storage.save_action_log(
            action.action_type,
            action.title,
            action.risk,
            result.status,
            action.reason,
            action.params,
            result.output,
            result.error,
        )
        storage.close()
        print(format_action_plan([action], [result]))
        return 0 if result.status in {"dry_run", "executed"} else 1

    if args.command == "action-logs":
        storage = open_storage(config)
        rows = storage.latest_action_logs(20)
        storage.close()
        if not rows:
            print("暂无处置动作日志。")
            return 0
        for row in rows:
            print(f"[{row['created_at']}] {row['status']} {row['action_type']} {row['title']}")
            if row.get("error"):
                print(f"  error: {row['error']}")
        return 0

    return 2


def open_storage(config: AppConfig) -> Storage:
    database_path = config.resolve_path(str(config.app.get("database_path", "data/ops_agent.db")))
    return Storage(database_path)


def build_cli_action(args: argparse.Namespace) -> RemediationAction:
    if args.type == "check_port":
        return RemediationAction(
            action_type="check_port",
            title=f"检查端口连通性 {args.host}:{args.port}",
            reason="手动执行端口检查。",
            params={"host": args.host, "port": args.port},
            auto_execute=True,
        )
    if args.type == "run_diagnostic_command":
        return RemediationAction(
            action_type="run_diagnostic_command",
            title="执行只读诊断命令",
            reason="手动执行只读诊断命令。",
            params={"command": args.diagnostic_command},
            auto_execute=True,
        )
    return RemediationAction(
        action_type=args.type,
        title=f"手动动作 {args.type}",
        reason="手动执行处置动作。",
        risk="medium",
        params={},
    )


def validate_config(config: AppConfig) -> list[str]:
    errors: list[str] = []
    validate_positive_int(config.app.get("interval_seconds", 60), "app.interval_seconds", errors)

    for index, check in enumerate(config.http_checks):
        validate_url(str(check.get("url", "")), f"http_checks[{index}].url", errors)
        validate_positive_int(check.get("timeout_seconds", 5), f"http_checks[{index}].timeout_seconds", errors)

    for index, check in enumerate(config.json_checks):
        validate_url(str(check.get("url", "")), f"json_checks[{index}].url", errors)
        validate_positive_int(check.get("timeout_seconds", 20), f"json_checks[{index}].timeout_seconds", errors)
        validate_positive_int(
            check.get("interval_seconds", config.app.get("interval_seconds", 60)),
            f"json_checks[{index}].interval_seconds",
            errors,
        )

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

    remediation = dict(config.raw.get("remediation", {}))
    if remediation:
        mode = str(remediation.get("mode", "suggest"))
        if mode not in {"off", "suggest", "auto"}:
            errors.append("remediation.mode 必须是 off/suggest/auto")
        validate_positive_int(remediation.get("command_timeout_seconds", 8), "remediation.command_timeout_seconds", errors)
        allowed_actions = remediation.get("allowed_actions", [])
        if allowed_actions and not isinstance(allowed_actions, list):
            errors.append("remediation.allowed_actions 必须是数组")

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
