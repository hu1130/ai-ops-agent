from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlparse

from ops_agent.alerts.notifier import Notifier
from ops_agent.config import AppConfig, load_config
from ops_agent.diagnostics.collector import collect_diagnostics, format_snapshot
from ops_agent.events import CheckResult, RunContext
from ops_agent.incident_lifecycle import INCIDENT_STATUSES
from ops_agent.remediation.actions import ActionResult, RemediationAction
from ops_agent.remediation.executor import MUTATING_ACTIONS, execute_action, format_action_plan
from ops_agent.remediation.planner import build_remediation_plan
from ops_agent.remediation.policy import apply_policy_defaults, decide_action_policy, format_policy_decision
from ops_agent.remediation.verifier import VerificationResult, verify_after_action
from ops_agent.retention import format_retention_result, run_retention_cleanup
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

    run_parser = subparsers.add_parser("run-action", help="Run or request a remediation action")
    run_parser.add_argument("--type", required=True, help="Action type")
    run_parser.add_argument("--host", default="", help="Host for check_port")
    run_parser.add_argument("--port", type=int, default=0, help="Port for check_port")
    run_parser.add_argument("--command", dest="diagnostic_command", default="", help="Read-only diagnostic command")
    run_parser.add_argument("--service", default="", help="Service name for restart_service")
    run_parser.add_argument("--container", default="", help="Container name for restart_docker_container")
    run_parser.add_argument("--incident-id", type=int, default=0, help="Related incident id")
    run_parser.add_argument("--execute", action="store_true", help="Actually execute safe actions; default is dry-run")
    add_verify_args(run_parser)

    approve_parser = subparsers.add_parser("approve-action", help="Approve and execute a pending action")
    approve_parser.add_argument("--id", type=int, required=True, help="Action log id")
    approve_parser.add_argument("--by", default="operator", help="Approver name")
    approve_parser.add_argument("--execute", action="store_true", help="Required to execute after approval")

    retention_parser = subparsers.add_parser("retention-cleanup", help="Preview or execute retention cleanup")
    retention_parser.add_argument("--execute", action="store_true", help="Actually delete expired records")

    subparsers.add_parser("incidents", help="Show latest incidents")
    incident_events_parser = subparsers.add_parser("incident-events", help="Show incident lifecycle events")
    incident_events_parser.add_argument("--id", type=int, required=True, help="Incident id")
    transition_parser = subparsers.add_parser("incident-transition", help="Transition incident lifecycle status")
    transition_parser.add_argument("--id", type=int, required=True, help="Incident id")
    transition_parser.add_argument("--status", required=True, choices=sorted(INCIDENT_STATUSES), help="Target status")
    transition_parser.add_argument("--actor", default="operator", help="Actor name")
    transition_parser.add_argument("--note", default="", help="Transition note")

    action_logs_parser = subparsers.add_parser("action-logs", help="Show latest remediation action audit logs")
    action_logs_parser.add_argument("--incident-id", type=int, default=0, help="Filter by incident id")
    return parser.parse_args()


def add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verify-url", default="", help="HTTP URL to check after successful execution")
    parser.add_argument("--verify-expected-status", type=int, default=200, help="Expected verification HTTP status")
    parser.add_argument("--verify-wait-seconds", type=float, default=0, help="Seconds to wait before verification")
    parser.add_argument("--verify-retries", type=int, default=1, help="Verification retry count")
    parser.add_argument("--verify-interval-seconds", type=float, default=1, help="Seconds between verification retries")
    parser.add_argument("--verify-timeout-seconds", type=float, default=5, help="HTTP verification timeout")


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
        return run_action_command(args, config)

    if args.command == "approve-action":
        return approve_action_command(args, config)

    if args.command == "retention-cleanup":
        storage = open_storage(config)
        result = run_retention_cleanup(storage, dict(config.raw.get("retention", {})), dry_run=not args.execute)
        storage.close()
        print(format_retention_result(result))
        return 0

    if args.command == "incidents":
        return incidents_command(config)

    if args.command == "incident-events":
        return incident_events_command(args, config)

    if args.command == "incident-transition":
        return incident_transition_command(args, config)

    if args.command == "action-logs":
        storage = open_storage(config)
        rows = storage.latest_action_logs(20, incident_id=args.incident_id or None)
        storage.close()
        if not rows:
            print("暂无处置动作日志。")
            return 0
        for row in rows:
            line = f"#{row['id']} [{row['created_at']}] {row['status']} {row['action_type']} {row['title']}"
            if row.get("incident_id"):
                line += f" incident_id={row['incident_id']}"
            if row.get("approved_by"):
                line += f" approved_by={row['approved_by']}"
            if row.get("verify_status"):
                line += f" verify={row['verify_status']}"
            print(line)
            if row.get("error"):
                print(f"  error: {row['error']}")
            if row.get("verify_output"):
                print(f"  verify: {row['verify_output']}")
        return 0

    return 2


def run_action_command(args: argparse.Namespace, config: AppConfig) -> int:
    action = build_cli_action(args)
    policy_decision = decide_action_policy(action, config)
    if policy_decision.configured and policy_decision.allowed:
        action = apply_policy_defaults(action, config)

    storage = open_storage(config)
    context = build_cli_context(config)

    if policy_decision.configured and not policy_decision.allowed:
        error = format_policy_decision(policy_decision)
        result = ActionResult(action=action, status="skipped", error=error)
        storage.save_action_log(
            action.action_type,
            action.title,
            action.risk,
            result.status,
            action.reason,
            action.params,
            result.output,
            result.error,
            environment=context.environment,
            run_type=context.run_type,
            trace_id=context.trace_id,
            incident_id=args.incident_id or None,
        )
        storage.close()
        print(format_action_plan([action], [result]))
        return 1

    if (
        policy_decision.configured
        and action.action_type in MUTATING_ACTIONS
        and policy_decision.verification_required
        and not action.params.get("verify_after")
    ):
        result = ActionResult(action=action, status="skipped", error="policy requires verify_after")
        storage.save_action_log(
            action.action_type,
            action.title,
            action.risk,
            result.status,
            action.reason,
            action.params,
            result.output,
            result.error,
            environment=context.environment,
            run_type=context.run_type,
            trace_id=context.trace_id,
            incident_id=args.incident_id or None,
        )
        storage.close()
        print(format_action_plan([action], [result]))
        return 1

    if action.action_type in MUTATING_ACTIONS and not args.execute:
        action_id = storage.save_action_log(
            action.action_type,
            action.title,
            action.risk,
            "pending_approval",
            action.reason,
            action.params,
            "等待人工确认。执行 approve-action --id 后才会尝试执行。",
            "",
            environment=context.environment,
            run_type=context.run_type,
            trace_id=context.trace_id,
            incident_id=args.incident_id or None,
        )
        storage.close()
        print(f"动作已进入待确认队列: #{action_id}")
        print(format_action_plan([action]))
        return 0

    result = execute_action(action, config, dry_run=not args.execute, approved=False)
    action_id = storage.save_action_log(
        action.action_type,
        action.title,
        action.risk,
        result.status,
        action.reason,
        action.params,
        result.output,
        result.error,
        environment=context.environment,
        run_type=context.run_type,
        trace_id=context.trace_id,
        incident_id=args.incident_id or None,
    )
    verification = verify_and_record(action_id, action, result.status, config, storage)
    storage.close()
    print(format_action_plan([action], [result]))
    print(format_verification(verification))
    return 0 if final_success(result.status, verification) else 1


def incidents_command(config: AppConfig) -> int:
    storage = open_storage(config)
    rows = storage.latest_incidents(30)
    storage.close()
    if not rows:
        print("No incidents.")
        return 0
    for row in rows:
        print(
            f"#{row['id']} [{row.get('status', 'open')}] {row['severity']} "
            f"{row['title']} trace={row.get('trace_id', '')}"
        )
    return 0


def incident_events_command(args: argparse.Namespace, config: AppConfig) -> int:
    storage = open_storage(config)
    incident = storage.get_incident(args.id)
    rows = storage.latest_incident_events(args.id)
    storage.close()
    if not incident:
        print(f"Incident not found: #{args.id}")
        return 1
    print(f"#{incident['id']} [{incident.get('status', 'open')}] {incident['title']}")
    for row in rows:
        print(
            f"- [{row['created_at']}] {row['from_status']} -> {row['to_status']} "
            f"actor={row['actor']} note={row['note']}"
        )
    return 0


def incident_transition_command(args: argparse.Namespace, config: AppConfig) -> int:
    storage = open_storage(config)
    try:
        row = storage.transition_incident(
            args.id,
            args.status,
            actor=args.actor,
            note=args.note,
            metadata={"source": "cli"},
        )
    except ValueError as exc:
        storage.close()
        print(str(exc))
        return 1
    storage.close()
    print(f"Incident #{row['id']} status={row['status']}")
    return 0


def approve_action_command(args: argparse.Namespace, config: AppConfig) -> int:
    if not args.execute:
        print("确认执行必须显式加 --execute。")
        return 1

    storage = open_storage(config)
    row = storage.get_action_log(args.id)
    if not row:
        storage.close()
        print(f"动作不存在: #{args.id}")
        return 1
    if row["status"] not in {"pending_approval", "skipped", "failed"}:
        storage.close()
        print(f"动作当前状态不允许确认执行: {row['status']}")
        return 1

    action = action_from_log(row)
    result = execute_action(action, config, dry_run=False, approved=True)
    storage.update_action_log(
        args.id,
        result.status,
        result.output,
        result.error,
        approved_by=args.by,
    )
    verification = verify_and_record(args.id, action, result.status, config, storage)
    storage.close()
    print(format_action_plan([action], [result]))
    print(format_verification(verification))
    return 0 if final_success(result.status, verification) else 1


def verify_and_record(
    action_id: int,
    action: RemediationAction,
    action_status: str,
    config: AppConfig,
    storage: Storage,
) -> VerificationResult | None:
    if action_status != "executed":
        return None
    verification = verify_after_action(action, config)
    if verification.status != "verify_skipped":
        output = verification.output or verification.error
        storage.update_action_verification(action_id, verification.status, output)
        notify_verification_result(config, action, verification)
    update_related_incident_after_action(storage, action_id, action, verification)
    return verification


def update_related_incident_after_action(
    storage: Storage,
    action_id: int,
    action: RemediationAction,
    verification: VerificationResult,
) -> None:
    if action.action_type not in MUTATING_ACTIONS:
        return
    row = storage.get_action_log(action_id)
    if not row or not row.get("incident_id"):
        return
    incident_id = int(row["incident_id"])
    if verification.status == "verified_ok":
        target = "resolved"
        note = "remediation action verified"
    elif verification.status == "verified_failed":
        target = "remediating"
        note = "remediation verification failed"
    else:
        target = "verifying"
        note = "remediation action executed"
    try:
        storage.transition_incident(
            incident_id,
            target,
            actor="ops-agent",
            note=note,
            metadata={"action_id": action_id, "verification_status": verification.status},
        )
    except ValueError:
        return


def notify_verification_result(config: AppConfig, action: RemediationAction, verification: VerificationResult) -> None:
    if action.action_type not in MUTATING_ACTIONS:
        return
    verification_config = dict(config.raw.get("remediation", {}).get("verification", {}))
    if not verification_config.get("notify", True):
        return
    title = "Ops Agent self-heal verified" if verification.status == "verified_ok" else "Ops Agent self-heal failed"
    text = (
        f"动作: {action.title}\n"
        f"状态: {verification.status}\n"
        f"输出: {verification.output}\n"
        f"错误: {verification.error}"
    )
    notifier = Notifier(
        webhook_url=str(config.alerts.get("webhook_url", "")),
        cooldown_seconds=int(config.alerts.get("cooldown_seconds", 300)),
        email=dict(config.alerts.get("email", {})),
    )
    notifier.send(title, text, dedupe_key=f"verification:{action.action_type}:{action.title}:{verification.status}")


def final_success(action_status: str, verification: VerificationResult | None) -> bool:
    if action_status != "executed":
        return False
    if verification and verification.status == "verified_failed":
        return False
    return True


def format_verification(verification: VerificationResult | None) -> str:
    if verification is None:
        return ""
    if verification.status == "verify_skipped":
        return f"\n执行后验证: {verification.output}"
    lines = [f"\n执行后验证: {verification.status}"]
    if verification.output:
        lines.append(f"输出: {verification.output}")
    if verification.error:
        lines.append(f"错误: {verification.error}")
    return "\n".join(lines)


def open_storage(config: AppConfig) -> Storage:
    database_path = config.resolve_path(str(config.app.get("database_path", "data/ops_agent.db")))
    return Storage(database_path)


def build_cli_context(config: AppConfig) -> RunContext:
    app = dict(config.app)
    return RunContext(
        environment=str(app.get("environment") or "prod").strip() or "prod",
        run_type=str(app.get("cli_run_type") or "manual").strip() or "manual",
    )


def build_cli_action(args: argparse.Namespace) -> RemediationAction:
    verify_after = build_verify_after(args)
    if args.type == "check_port":
        return RemediationAction(
            action_type="check_port",
            title=f"检查端口连通性 {args.host}:{args.port}",
            reason="手动执行端口检查。",
            params=with_verify({"host": args.host, "port": args.port}, verify_after),
            auto_execute=True,
        )
    if args.type == "run_diagnostic_command":
        return RemediationAction(
            action_type="run_diagnostic_command",
            title="执行只读诊断命令",
            reason="手动执行只读诊断命令。",
            params=with_verify({"command": args.diagnostic_command}, verify_after),
            auto_execute=True,
        )
    if args.type == "restart_service":
        return RemediationAction(
            action_type="restart_service",
            title=f"重启服务 {args.service}",
            reason="人工请求重启 systemd 服务。",
            risk="medium",
            params=with_verify({"service": args.service}, verify_after),
        )
    if args.type == "restart_docker_container":
        return RemediationAction(
            action_type="restart_docker_container",
            title=f"重启容器 {args.container}",
            reason="人工请求重启 Docker 容器。",
            risk="medium",
            params=with_verify({"container": args.container}, verify_after),
        )
    return RemediationAction(
        action_type=args.type,
        title=f"手动动作 {args.type}",
        reason="手动执行处置动作。",
        risk="medium",
        params=with_verify({}, verify_after),
    )


def build_verify_after(args: argparse.Namespace) -> dict | None:
    if not getattr(args, "verify_url", ""):
        return None
    return {
        "type": "http",
        "url": args.verify_url,
        "expected_status": args.verify_expected_status,
        "wait_seconds": args.verify_wait_seconds,
        "retries": args.verify_retries,
        "interval_seconds": args.verify_interval_seconds,
        "timeout_seconds": args.verify_timeout_seconds,
    }


def with_verify(params: dict, verify_after: dict | None) -> dict:
    if verify_after:
        params["verify_after"] = verify_after
    return params


def action_from_log(row: dict) -> RemediationAction:
    try:
        params = json.loads(row.get("params_json") or "{}")
    except json.JSONDecodeError:
        params = {}
    return RemediationAction(
        action_type=str(row["action_type"]),
        title=str(row["title"]),
        reason=str(row["reason"]),
        risk=str(row["risk"]),  # type: ignore[arg-type]
        params=params,
        auto_execute=True,
    )


def validate_config(config: AppConfig) -> list[str]:
    errors: list[str] = []
    validate_positive_int(config.app.get("interval_seconds", 60), "app.interval_seconds", errors)
    validate_context_name(config.app.get("environment", "prod"), "app.environment", errors)
    validate_context_name(config.app.get("run_type", "normal"), "app.run_type", errors)
    if config.app.get("cli_run_type"):
        validate_context_name(config.app.get("cli_run_type"), "app.cli_run_type", errors)

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
        container_value = str(check.get("container", "")).strip()
        if container_value:
            validate_context_name(container_value, f"log_checks[{index}].container", errors)
            continue
        path_value = str(check.get("path", ""))
        if not path_value:
            errors.append(f"log_checks[{index}].path 或 container 不能为空")
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
        validate_remediation_policies(remediation, errors)

    retention = dict(config.raw.get("retention", {}))
    if retention:
        validate_positive_int(retention.get("check_results_days", 30), "retention.check_results_days", errors)
        validate_positive_int(retention.get("problem_results_days", 90), "retention.problem_results_days", errors)
        validate_positive_int(retention.get("incidents_days", 90), "retention.incidents_days", errors)
        validate_positive_int(retention.get("action_logs_days", 90), "retention.action_logs_days", errors)
        validate_positive_int(retention.get("test_results_days", 7), "retention.test_results_days", errors)
        validate_positive_int(retention.get("test_incidents_days", 7), "retention.test_incidents_days", errors)
        validate_positive_int(retention.get("test_action_logs_days", 7), "retention.test_action_logs_days", errors)
        validate_string_list(retention.get("test_environments", ["test"]), "retention.test_environments", errors)
        validate_string_list(retention.get("test_run_types", ["manual_test", "synthetic_test"]), "retention.test_run_types", errors)
        try:
            cleanup_hour = int(retention.get("cleanup_hour", 3))
        except (TypeError, ValueError):
            errors.append("retention.cleanup_hour 必须是数字")
        else:
            if cleanup_hour < 0 or cleanup_hour > 23:
                errors.append("retention.cleanup_hour 必须在 0-23 之间")

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


def validate_context_name(value: object, field: str, errors: list[str]) -> None:
    text = str(value or "").strip()
    if not text:
        errors.append(f"{field} 不能为空")
        return
    if any(char.isspace() for char in text):
        errors.append(f"{field} 不能包含空格")


def validate_string_list(value: object, field: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{field} 必须是数组")
        return
    if any(not str(item).strip() for item in value):
        errors.append(f"{field} 不能包含空值")


def validate_remediation_policies(remediation: dict, errors: list[str]) -> None:
    policies = remediation.get("policies", [])
    if not policies:
        return
    if not isinstance(policies, list):
        errors.append("remediation.policies 必须是数组")
        return

    for index, policy in enumerate(policies):
        field = f"remediation.policies[{index}]"
        if not isinstance(policy, dict):
            errors.append(f"{field} 必须是对象")
            continue

        action_type = str(policy.get("action_type", "")).strip()
        if not action_type:
            errors.append(f"{field}.action_type 不能为空")

        for bool_field in ("enabled", "auto_execute", "requires_approval", "verification_required"):
            if bool_field in policy and not isinstance(policy[bool_field], bool):
                errors.append(f"{field}.{bool_field} 必须是 true/false")

        if "targets" in policy:
            validate_string_list(policy["targets"], f"{field}.targets", errors)

        targets = policy.get("targets", [])
        enabled = bool(policy.get("enabled", True))
        if action_type in MUTATING_ACTIONS and enabled:
            if not isinstance(targets, list) or not targets:
                errors.append(f"{field}.targets 修改类动作必须显式配置目标")
            elif any(str(item).strip() == "*" for item in targets):
                errors.append(f"{field}.targets 修改类动作不能使用 *")

        verify_after = policy.get("verify_after")
        if verify_after is not None and not isinstance(verify_after, dict):
            errors.append(f"{field}.verify_after 必须是对象")
        elif isinstance(verify_after, dict) and verify_after:
            if verify_after.get("type", "http") != "http":
                errors.append(f"{field}.verify_after.type 目前只支持 http")
            if verify_after.get("url"):
                validate_url(str(verify_after["url"]), f"{field}.verify_after.url", errors)


if __name__ == "__main__":
    raise SystemExit(main())
