from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from urllib.parse import urlparse

from ops_agent.alerts.notifier import Notifier
from ops_agent.auth import API_TOKEN_ROLES
from ops_agent.config import AppConfig, load_config
from ops_agent.diagnostics.collector import collect_diagnostics, format_snapshot
from ops_agent.enterprise import enterprise_readiness_snapshot, format_enterprise_readiness
from ops_agent.events import CheckResult, RunContext
from ops_agent.fleet import run_fleet_agent
from ops_agent.incident_lifecycle import INCIDENT_STATUSES
from ops_agent.mysql_migration import MysqlExportOptions, export_sqlite_to_mysql, format_mysql_export_result
from ops_agent.remediation import approval
from ops_agent.remediation.actions import ActionResult, RemediationAction
from ops_agent.remediation.executor import MUTATING_ACTIONS, execute_action, format_action_plan
from ops_agent.remediation.planner import build_remediation_plan
from ops_agent.remediation.playbooks import FAILURE_POLICIES, STAGES
from ops_agent.remediation.policy import apply_policy_defaults, decide_action_policy, format_policy_decision
from ops_agent.remediation.verifier import VerificationResult, verify_after_action
from ops_agent.retention import format_retention_result, run_retention_cleanup
from ops_agent.storage import Storage
from ops_agent.storage_factory import open_configured_storage


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Ops Agent tools")
    parser.add_argument("--config", default="config.json", help="Path to config JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("diagnose", help="Print a local diagnostic snapshot")
    subparsers.add_parser("validate-config", help="Validate config structure and common mistakes")
    enterprise_parser = subparsers.add_parser("enterprise-readiness", help="Assess enterprise readiness")
    enterprise_parser.add_argument("--json", action="store_true", help="Print JSON payload")
    mysql_export_parser = subparsers.add_parser("mysql-export", help="Export the SQLite database as MySQL SQL")
    mysql_export_parser.add_argument("--sqlite", default="", help="SQLite database path; default uses app.database_path")
    mysql_export_parser.add_argument("--output", default="", help="Output SQL path; default data/mysql_migration.sql")
    mysql_export_parser.add_argument("--database-name", default="", help="Optional MySQL database name to create/use")
    mysql_export_parser.add_argument("--schema-only", action="store_true", help="Export schema without data")
    mysql_export_parser.add_argument("--data-only", action="store_true", help="Export data without schema")
    mysql_export_parser.add_argument("--batch-size", type=int, default=200, help="INSERT batch size")

    fleet_parser = subparsers.add_parser("fleet-agent", help="Report this server to a central Ops Agent")
    fleet_parser.add_argument("--server-url", default="", help="Central Ops Agent URL; or OPS_AGENT_FLEET_SERVER_URL")
    fleet_parser.add_argument("--node-id", default="", help="Stable node id; default uses the hostname")
    fleet_parser.add_argument("--name", default="", help="Human-readable server name")
    fleet_parser.add_argument("--token-env", default="OPS_AGENT_FLEET_ENROLLMENT_TOKEN", help="Enrollment token environment variable")
    fleet_parser.add_argument("--interval-seconds", type=int, default=60, help="Heartbeat interval")
    fleet_parser.add_argument("--timeout-seconds", type=int, default=10, help="Central server request timeout")
    fleet_parser.add_argument("--once", action="store_true", help="Send one heartbeat and exit")

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
    run_parser.add_argument("--cleanup-path", action="append", default=[], help="Path for cleanup_temp_files; can repeat")
    run_parser.add_argument("--max-age-hours", type=float, default=72, help="Minimum file age for cleanup_temp_files")
    run_parser.add_argument("--max-files", type=int, default=500, help="Maximum files to delete in one cleanup action")
    run_parser.add_argument("--max-bytes", type=int, default=0, help="Maximum bytes to delete in one cleanup action; 0 disables")
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
    audit_logs_parser = subparsers.add_parser("audit-logs", help="Show latest API operation audit logs")
    audit_logs_parser.add_argument("--limit", type=int, default=20, help="Number of audit rows to show")
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

    if args.command == "enterprise-readiness":
        snapshot = enterprise_readiness_snapshot(config)
        if args.json:
            print(json.dumps(snapshot, ensure_ascii=False, indent=2))
        else:
            print(format_enterprise_readiness(snapshot))
        return 1 if snapshot.get("summary", {}).get("blockers", 0) else 0

    if args.command == "mysql-export":
        if args.schema_only and args.data_only:
            print("--schema-only and --data-only cannot be used together", file=sys.stderr)
            return 2
        sqlite_path = config.resolve_path(args.sqlite) if args.sqlite else database_path_from_config(config)
        output_path = config.resolve_path(args.output) if args.output else config.resolve_path("data/mysql_migration.sql")
        result = export_sqlite_to_mysql(
            MysqlExportOptions(
                sqlite_path=sqlite_path,
                output_path=output_path,
                database_name=str(args.database_name or ""),
                schema_only=bool(args.schema_only),
                data_only=bool(args.data_only),
                batch_size=max(1, int(args.batch_size or 200)),
            )
        )
        print(format_mysql_export_result(result))
        return 0

    if args.command == "fleet-agent":
        server_url = str(args.server_url or os.environ.get("OPS_AGENT_FLEET_SERVER_URL", "")).strip()
        token = os.environ.get(str(args.token_env or "OPS_AGENT_FLEET_ENROLLMENT_TOKEN"), "").strip()
        node_id = str(args.node_id or socket.gethostname()).strip()
        try:
            return run_fleet_agent(
                config,
                server_url,
                token,
                node_id,
                name=str(args.name or ""),
                once=bool(args.once),
                interval_seconds=max(15, int(args.interval_seconds or 60)),
                timeout_seconds=max(1, int(args.timeout_seconds or 10)),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Fleet agent failed: {exc}", file=sys.stderr)
            return 1

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
            if row.get("decision"):
                line += f" decision={row['decision']}"
            if row.get("decision_by"):
                line += f" decision_by={row['decision_by']}"
            if row.get("verify_status"):
                line += f" verify={row['verify_status']}"
            print(line)
            if row.get("error"):
                print(f"  error: {row['error']}")
            if row.get("verify_output"):
                print(f"  verify: {row['verify_output']}")
        return 0

    if args.command == "audit-logs":
        storage = open_storage(config)
        rows = storage.latest_api_audit_logs(args.limit)
        storage.close()
        if not rows:
            print("暂无 API 操作审计日志。")
            return 0
        for row in rows:
            target = row.get("target_type") or "-"
            if row.get("target_id") is not None:
                target = f"{target}#{row['target_id']}"
            print(
                f"#{row['id']} [{row['created_at']}] {row['outcome']} "
                f"{row['method']} {row['operation']} target={target} "
                f"actor={row['actor'] or '-'} ip={row['source_ip'] or '-'} status={row['status_code']}"
            )
            if row.get("message"):
                print(f"  message: {row['message']}")
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
            approval_expires_at=approval.approval_expiry_from_config(config),
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
    try:
        decision = approval.approve_action_log(storage, config, args.id, actor=args.by)
    except ValueError as exc:
        storage.close()
        print(str(exc))
        return 1
    storage.close()
    print(format_action_plan([decision.action], [decision.result]))
    print(format_verification(decision.verification))
    return 0 if final_success(decision.result.status, decision.verification) else 1


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
    return open_configured_storage(config)


def database_path_from_config(config: AppConfig) -> Path:
    return config.resolve_path(str(config.app.get("database_path", "data/ops_agent.db")))


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
    if args.type == "cleanup_temp_files":
        paths = list(getattr(args, "cleanup_path", []) or [])
        return RemediationAction(
            action_type="cleanup_temp_files",
            title="清理临时文件",
            reason="人工请求清理白名单路径里的过期临时文件。",
            risk="medium",
            params=with_verify(
                {
                    "paths": paths,
                    "max_age_hours": args.max_age_hours,
                    "max_files": args.max_files,
                    "max_bytes": args.max_bytes,
                },
                verify_after,
            ),
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
    validate_api_auth_config(config.app, errors)
    validate_projects(config.raw, errors)

    for index, check in enumerate(config.http_checks):
        validate_url(str(check.get("url", "")), f"http_checks[{index}].url", errors)
        validate_positive_int(check.get("timeout_seconds", 5), f"http_checks[{index}].timeout_seconds", errors)
        validate_positive_int(check.get("expected_status", 200), f"http_checks[{index}].expected_status", errors)
        validate_positive_int(check.get("max_latency_ms", 3000), f"http_checks[{index}].max_latency_ms", errors)
        validate_optional_positive_int(check.get("max_response_bytes"), f"http_checks[{index}].max_response_bytes", errors)
        validate_optional_positive_int(check.get("min_body_bytes"), f"http_checks[{index}].min_body_bytes", errors)
        validate_optional_positive_int(check.get("alert_after_failures"), f"http_checks[{index}].alert_after_failures", errors)
        validate_optional_positive_int(check.get("consecutive_failures"), f"http_checks[{index}].consecutive_failures", errors)
        validate_string_list(check.get("required_texts", []), f"http_checks[{index}].required_texts", errors)
        validate_string_list(check.get("forbidden_texts", []), f"http_checks[{index}].forbidden_texts", errors)
        if "status_on_content_mismatch" in check:
            mismatch_status = str(check["status_on_content_mismatch"]).strip().lower()
            if mismatch_status not in {"warning", "critical"}:
                errors.append(f"http_checks[{index}].status_on_content_mismatch 必须是 warning/critical")
        if "fallback_enabled" in check and not isinstance(check["fallback_enabled"], bool):
            errors.append(f"http_checks[{index}].fallback_enabled 必须是 true/false")
        if "fallback_urls" in check:
            validate_string_list(check["fallback_urls"], f"http_checks[{index}].fallback_urls", errors)
            if isinstance(check["fallback_urls"], list):
                for fallback_index, fallback_url in enumerate(check["fallback_urls"]):
                    fallback_text = str(fallback_url or "").strip()
                    if fallback_text.startswith(("http://", "https://")):
                        validate_url(fallback_text, f"http_checks[{index}].fallback_urls[{fallback_index}]", errors)
        if "fallback_expected_statuses" in check:
            validate_status_code_list(
                check["fallback_expected_statuses"],
                f"http_checks[{index}].fallback_expected_statuses",
                errors,
            )
        if "fallback_success_status" in check:
            fallback_status = str(check["fallback_success_status"]).strip().lower()
            if fallback_status not in {"ok", "warning", "critical"}:
                errors.append(f"http_checks[{index}].fallback_success_status 必须是 ok/warning/critical")

    for index, check in enumerate(config.json_checks):
        validate_url(str(check.get("url", "")), f"json_checks[{index}].url", errors)
        validate_positive_int(check.get("timeout_seconds", 20), f"json_checks[{index}].timeout_seconds", errors)
        validate_positive_int(
            check.get("interval_seconds", config.app.get("interval_seconds", 60)),
            f"json_checks[{index}].interval_seconds",
            errors,
        )
        validate_optional_positive_int(check.get("alert_after_failures"), f"json_checks[{index}].alert_after_failures", errors)
        validate_optional_positive_int(check.get("consecutive_failures"), f"json_checks[{index}].consecutive_failures", errors)

    validate_business_flow_checks(config, errors)

    for index, check in enumerate(config.docker_checks):
        container_value = str(check.get("container", "")).strip()
        if not container_value:
            errors.append(f"docker_checks[{index}].container 不能为空")
        else:
            validate_context_name(container_value, f"docker_checks[{index}].container", errors)
        validate_positive_int(check.get("timeout_seconds", 5), f"docker_checks[{index}].timeout_seconds", errors)
        validate_optional_positive_int(check.get("fallback_timeout_seconds"), f"docker_checks[{index}].fallback_timeout_seconds", errors)
        validate_optional_positive_int(check.get("interval_seconds"), f"docker_checks[{index}].interval_seconds", errors)
        validate_optional_positive_int(check.get("alert_after_failures"), f"docker_checks[{index}].alert_after_failures", errors)
        validate_optional_positive_int(check.get("consecutive_failures"), f"docker_checks[{index}].consecutive_failures", errors)
        if "fallback_url" in check:
            validate_url(str(check.get("fallback_url", "")), f"docker_checks[{index}].fallback_url", errors)
        if "fallback_urls" in check:
            validate_string_list(check["fallback_urls"], f"docker_checks[{index}].fallback_urls", errors)
            if isinstance(check["fallback_urls"], list):
                for fallback_index, fallback_url in enumerate(check["fallback_urls"]):
                    fallback_text = str(fallback_url or "").strip()
                    if fallback_text:
                        validate_url(fallback_text, f"docker_checks[{index}].fallback_urls[{fallback_index}]", errors)
        if "fallback_expected_statuses" in check:
            validate_status_code_list(
                check["fallback_expected_statuses"],
                f"docker_checks[{index}].fallback_expected_statuses",
                errors,
            )
        if "fallback_success_status" in check:
            fallback_status = str(check["fallback_success_status"]).strip().lower()
            if fallback_status not in {"ok", "warning", "critical"}:
                errors.append(f"docker_checks[{index}].fallback_success_status 必须是 ok/warning/critical")
        for status_key in (
            "not_running_status",
            "unhealthy_status",
            "missing_status",
            "missing_healthcheck_status",
            "unknown_health_status",
            "docker_unavailable_status",
        ):
            if status_key in check:
                configured_status = str(check[status_key]).strip().lower()
                if configured_status not in {"warning", "critical"}:
                    errors.append(f"docker_checks[{index}].{status_key} 必须是 warning/critical")
        if "require_healthcheck" in check and not isinstance(check["require_healthcheck"], bool):
            errors.append(f"docker_checks[{index}].require_healthcheck 必须是 true/false")

    for index, check in enumerate(config.database_checks):
        field = f"database_checks[{index}]"
        engine = str(check.get("engine") or "mysql_docker").strip().lower()
        if engine not in {"mysql_docker", "mysql"}:
            errors.append(f"{field}.engine 必须是 mysql_docker/mysql")
        if engine == "mysql_docker":
            container = str(check.get("container") or "").strip()
            if not container:
                errors.append(f"{field}.container 不能为空")
            else:
                validate_context_name(container, f"{field}.container", errors)
        if engine == "mysql":
            if not str(check.get("host") or "").strip():
                errors.append(f"{field}.host 不能为空")
            if not str(check.get("username") or check.get("user") or "").strip():
                errors.append(f"{field}.username 不能为空")
            if not str(check.get("password") or check.get("password_env") or "").strip():
                errors.append(f"{field}.password 或 password_env 不能为空")
            validate_positive_int(check.get("port", 3306), f"{field}.port", errors)
        validate_positive_int(check.get("timeout_seconds", 10), f"{field}.timeout_seconds", errors)
        validate_optional_positive_int(check.get("interval_seconds"), f"{field}.interval_seconds", errors)
        validate_optional_positive_int(check.get("alert_after_failures"), f"{field}.alert_after_failures", errors)
        validate_optional_positive_int(check.get("recovery_after_successes"), f"{field}.recovery_after_successes", errors)
        validate_positive_int(check.get("max_query_latency_ms", 3000), f"{field}.max_query_latency_ms", errors)
        validate_positive_int(check.get("max_running_threads", 20), f"{field}.max_running_threads", errors)

    for index, check in enumerate(config.log_checks):
        if "enabled" in check and not isinstance(check["enabled"], bool):
            errors.append(f"log_checks[{index}].enabled 必须是 true/false")
        validate_optional_positive_int(check.get("alert_after_failures"), f"log_checks[{index}].alert_after_failures", errors)
        validate_optional_positive_int(check.get("consecutive_failures"), f"log_checks[{index}].consecutive_failures", errors)
        if "status_on_match" in check:
            match_status = str(check["status_on_match"]).strip().lower()
            if match_status not in {"warning", "critical"}:
                errors.append(f"log_checks[{index}].status_on_match 必须是 warning/critical")
        container_value = str(check.get("container", "")).strip()
        if container_value:
            validate_context_name(container_value, f"log_checks[{index}].container", errors)
            continue
        path_value = str(check.get("path", ""))
        if not path_value:
            errors.append(f"log_checks[{index}].path 或 container 不能为空")
            continue
        path = config.resolve_path(path_value)
        if check.get("enabled", True) and not path.exists():
            errors.append(f"log_checks[{index}].path 不存在: {path_value}")

    alerts = config.alerts
    validate_positive_int(alerts.get("consecutive_failures", 2), "alerts.consecutive_failures", errors)
    validate_positive_int(alerts.get("cooldown_seconds", 300), "alerts.cooldown_seconds", errors)
    validate_positive_int(
        alerts.get("repeat_notification_interval_seconds", 3600),
        "alerts.repeat_notification_interval_seconds",
        errors,
    )
    validate_positive_int(alerts.get("escalation_after_seconds", 1800), "alerts.escalation_after_seconds", errors)
    validate_positive_int(
        alerts.get("escalation_critical_occurrences", 10),
        "alerts.escalation_critical_occurrences",
        errors,
    )
    validate_alert_routing(alerts, errors)
    validate_classification_rules(config.raw, errors)

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
        validate_remediation_playbooks(remediation, errors)

    retention = dict(config.raw.get("retention", {}))
    if retention:
        validate_positive_int(retention.get("check_results_days", 30), "retention.check_results_days", errors)
        validate_positive_int(retention.get("problem_results_days", 90), "retention.problem_results_days", errors)
        validate_positive_int(retention.get("incidents_days", 90), "retention.incidents_days", errors)
        validate_positive_int(retention.get("action_logs_days", 90), "retention.action_logs_days", errors)
        validate_positive_int(retention.get("api_audit_logs_days", 180), "retention.api_audit_logs_days", errors)
        validate_positive_int(retention.get("test_results_days", 7), "retention.test_results_days", errors)
        validate_positive_int(retention.get("test_incidents_days", 7), "retention.test_incidents_days", errors)
        validate_positive_int(retention.get("test_action_logs_days", 7), "retention.test_action_logs_days", errors)
        validate_positive_int(
            retention.get("test_api_audit_logs_days", 7),
            "retention.test_api_audit_logs_days",
            errors,
        )
        validate_positive_int(retention.get("notification_logs_days", 180), "retention.notification_logs_days", errors)
        validate_positive_int(
            retention.get("test_notification_logs_days", 7),
            "retention.test_notification_logs_days",
            errors,
        )
        validate_positive_int(
            retention.get("auto_close_resolved_after_days", 7),
            "retention.auto_close_resolved_after_days",
            errors,
        )
        validate_positive_int(
            retention.get("test_auto_close_resolved_after_days", 1),
            "retention.test_auto_close_resolved_after_days",
            errors,
        )
        validate_string_list(retention.get("test_environments", ["test"]), "retention.test_environments", errors)
        validate_string_list(retention.get("test_run_types", ["manual_test", "synthetic_test"]), "retention.test_run_types", errors)
        try:
            cleanup_hour = int(retention.get("cleanup_hour", 3))
        except (TypeError, ValueError):
            errors.append("retention.cleanup_hour 必须是数字")
        else:
            if cleanup_hour < 0 or cleanup_hour > 23:
                    errors.append("retention.cleanup_hour 必须在 0-23 之间")

    discovery = dict(config.raw.get("asset_discovery", {}))
    if discovery:
        validate_optional_positive_int(discovery.get("interval_seconds"), "asset_discovery.interval_seconds", errors)
        validate_positive_int(discovery.get("timeout_seconds", 8), "asset_discovery.timeout_seconds", errors)
        validate_optional_positive_int(discovery.get("alert_after_failures"), "asset_discovery.alert_after_failures", errors)
        validate_optional_positive_int(
            discovery.get("recovery_after_successes"),
            "asset_discovery.recovery_after_successes",
            errors,
        )
        validate_string_list(discovery.get("ignored_containers", []), "asset_discovery.ignored_containers", errors)
        validate_string_list(discovery.get("candidate_patterns", []), "asset_discovery.candidate_patterns", errors)
        validate_string_list(
            discovery.get("infrastructure_patterns", []),
            "asset_discovery.infrastructure_patterns",
            errors,
        )

    fleet = dict(config.raw.get("fleet", {}))
    if fleet:
        if "enabled" in fleet and not isinstance(fleet["enabled"], bool):
            errors.append("fleet.enabled 必须是 true/false")
        validate_positive_int(fleet.get("heartbeat_interval_seconds", 60), "fleet.heartbeat_interval_seconds", errors)
        validate_positive_int(fleet.get("offline_after_seconds", 180), "fleet.offline_after_seconds", errors)
        validate_optional_positive_int(fleet.get("alert_after_failures"), "fleet.alert_after_failures", errors)
        validate_optional_positive_int(fleet.get("recovery_after_successes"), "fleet.recovery_after_successes", errors)
        token_env = fleet.get("enrollment_token_env", "OPS_AGENT_FLEET_ENROLLMENT_TOKEN")
        if not isinstance(token_env, str) or not token_env.strip():
            errors.append("fleet.enrollment_token_env 必须是非空字符串")
        resource_thresholds = fleet.get("resource_thresholds", {})
        if resource_thresholds and not isinstance(resource_thresholds, dict):
            errors.append("fleet.resource_thresholds 必须是对象")
        elif isinstance(resource_thresholds, dict):
            defaults = {
                "cpu_warning": 90,
                "cpu_critical": 98,
                "memory_warning": 85,
                "memory_critical": 95,
                "disk_warning": 85,
                "disk_critical": 95,
            }
            for key, default in defaults.items():
                value = resource_thresholds.get(key, default)
                validate_positive_number(value, f"fleet.resource_thresholds.{key}", errors)
                try:
                    if float(value) > 100:
                        errors.append(f"fleet.resource_thresholds.{key} 不能大于 100")
                except (TypeError, ValueError):
                    pass
            for prefix in ("cpu", "memory", "disk"):
                try:
                    warning = float(resource_thresholds.get(f"{prefix}_warning", defaults[f"{prefix}_warning"]))
                    critical = float(resource_thresholds.get(f"{prefix}_critical", defaults[f"{prefix}_critical"]))
                    if warning >= critical:
                        errors.append(f"fleet.resource_thresholds.{prefix}_warning 必须小于 critical")
                except (TypeError, ValueError):
                    pass

    backups = dict(config.raw.get("backups", {}))
    if backups:
        if "enabled" in backups and not isinstance(backups["enabled"], bool):
            errors.append("backups.enabled 必须是 true/false")
        targets = backups.get("targets", [])
        if not isinstance(targets, list):
            errors.append("backups.targets 必须是数组")
        else:
            seen_target_ids: set[str] = set()
            for index, target in enumerate(targets):
                field = f"backups.targets[{index}]"
                if not isinstance(target, dict):
                    errors.append(f"{field} 必须是对象")
                    continue
                target_id = str(target.get("id") or "").strip()
                if not target_id:
                    errors.append(f"{field}.id 不能为空")
                elif target_id in seen_target_ids:
                    errors.append(f"{field}.id 重复: {target_id}")
                else:
                    seen_target_ids.add(target_id)
                    validate_context_name(target_id, f"{field}.id", errors)
                engine = str(target.get("engine") or "sqlite")
                if engine not in {"sqlite", "mysql_docker"}:
                    errors.append(f"{field}.engine 必须是 sqlite/mysql_docker")
                if engine == "sqlite" and not str(target.get("path") or config.app.get("database_path") or "").strip():
                    errors.append(f"{field}.path 不能为空")
                if engine == "mysql_docker":
                    container = str(target.get("container") or "").strip()
                    if not container:
                        errors.append(f"{field}.container 不能为空")
                    else:
                        validate_context_name(container, f"{field}.container", errors)
                validate_positive_number(target.get("interval_hours", 24), f"{field}.interval_hours", errors)
                validate_positive_int(target.get("retention_days", 14), f"{field}.retention_days", errors)
                validate_positive_int(target.get("minimum_backups", 3), f"{field}.minimum_backups", errors)
                if "max_total_bytes" in target:
                    validate_positive_int(target.get("max_total_bytes"), f"{field}.max_total_bytes", errors)
                validate_optional_positive_int(target.get("alert_after_failures"), f"{field}.alert_after_failures", errors)
                validate_optional_positive_int(target.get("recovery_after_successes"), f"{field}.recovery_after_successes", errors)
                drill = target.get("restore_drill", {})
                if drill and not isinstance(drill, dict):
                    errors.append(f"{field}.restore_drill 必须是对象")
                elif isinstance(drill, dict):
                    validate_positive_number(drill.get("interval_days", 7), f"{field}.restore_drill.interval_days", errors)
                    validate_positive_int(drill.get("minimum_tables", 1), f"{field}.restore_drill.minimum_tables", errors)

    email = dict(alerts.get("email", {}))
    if email.get("enabled", False):
        required = ["smtp_host", "smtp_port", "username", "password", "to_emails"]
        for key in required:
            if not email.get(key):
                errors.append(f"alerts.email.{key} 不能为空")

    return errors


def validate_business_flow_checks(config: AppConfig, errors: list[str]) -> None:
    allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
    for index, check in enumerate(config.business_flow_checks):
        field = f"business_flow_checks[{index}]"
        validate_positive_int(check.get("timeout_seconds", 15), f"{field}.timeout_seconds", errors)
        validate_optional_positive_int(check.get("interval_seconds"), f"{field}.interval_seconds", errors)
        validate_optional_positive_int(check.get("max_latency_ms"), f"{field}.max_latency_ms", errors)
        validate_optional_positive_int(check.get("max_total_latency_ms"), f"{field}.max_total_latency_ms", errors)
        validate_optional_positive_int(check.get("max_response_bytes"), f"{field}.max_response_bytes", errors)
        validate_optional_positive_int(check.get("alert_after_failures"), f"{field}.alert_after_failures", errors)
        validate_optional_positive_int(check.get("consecutive_failures"), f"{field}.consecutive_failures", errors)
        if "failure_status" in check:
            validate_problem_status(check["failure_status"], f"{field}.failure_status", errors)
        if "headers" in check and not isinstance(check["headers"], dict):
            errors.append(f"{field}.headers 必须是对象")
        if "variables" in check and not isinstance(check["variables"], dict):
            errors.append(f"{field}.variables 必须是对象")

        steps = check.get("steps", [])
        if not isinstance(steps, list) or not steps:
            errors.append(f"{field}.steps 必须是非空数组")
            continue

        for step_index, step in enumerate(steps):
            step_field = f"{field}.steps[{step_index}]"
            if not isinstance(step, dict):
                errors.append(f"{step_field} 必须是对象")
                continue
            url = str(step.get("url", "")).strip()
            if not url:
                errors.append(f"{step_field}.url 不能为空")
            else:
                validate_business_flow_url(url, f"{step_field}.url", errors)
            method = str(step.get("method", "POST" if any(key in step for key in ("json", "form", "body")) else "GET")).upper()
            if method not in allowed_methods:
                errors.append(f"{step_field}.method 必须是 GET/POST/PUT/PATCH/DELETE/HEAD")
            validate_optional_positive_int(step.get("timeout_seconds"), f"{step_field}.timeout_seconds", errors)
            validate_optional_positive_int(step.get("max_latency_ms"), f"{step_field}.max_latency_ms", errors)
            validate_optional_positive_int(step.get("max_response_bytes"), f"{step_field}.max_response_bytes", errors)
            validate_optional_positive_int(step.get("min_body_bytes"), f"{step_field}.min_body_bytes", errors)
            validate_optional_positive_int(step.get("expected_status"), f"{step_field}.expected_status", errors)
            if "expected_statuses" in step:
                validate_status_code_list(step["expected_statuses"], f"{step_field}.expected_statuses", errors)
            if "failure_status" in step:
                validate_problem_status(step["failure_status"], f"{step_field}.failure_status", errors)
            validate_string_list(step.get("required_texts", []), f"{step_field}.required_texts", errors)
            validate_string_list(step.get("forbidden_texts", []), f"{step_field}.forbidden_texts", errors)
            validate_string_list(step.get("required_json_paths", step.get("required_paths", [])), f"{step_field}.required_json_paths", errors)
            validate_string_list(step.get("bad_phrases", []), f"{step_field}.bad_phrases", errors)
            if "headers" in step and not isinstance(step["headers"], dict):
                errors.append(f"{step_field}.headers 必须是对象")
            if "json" in step and not isinstance(step["json"], (dict, list)):
                errors.append(f"{step_field}.json 必须是对象或数组")
            if "form" in step and not isinstance(step["form"], dict):
                errors.append(f"{step_field}.form 必须是对象")
            if "extract" in step and not isinstance(step["extract"], dict):
                errors.append(f"{step_field}.extract 必须是对象")


def validate_problem_status(value: object, field: str, errors: list[str]) -> None:
    status = str(value).strip().lower()
    if status not in {"warning", "critical"}:
        errors.append(f"{field} 必须是 warning/critical")


def validate_business_flow_url(value: str, field: str, errors: list[str]) -> None:
    text = value.strip()
    if text.startswith("{{") and "}}" in text:
        return
    validate_url(text, field, errors)


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


def validate_positive_number(value: object, field: str, errors: list[str]) -> None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        errors.append(f"{field} 必须是数字")
        return
    if number <= 0:
        errors.append(f"{field} 必须大于 0")


def validate_optional_positive_int(value: object, field: str, errors: list[str]) -> None:
    if value is None:
        return
    validate_positive_int(value, field, errors)


def validate_context_name(value: object, field: str, errors: list[str]) -> None:
    text = str(value or "").strip()
    if not text:
        errors.append(f"{field} 不能为空")
        return
    if any(char.isspace() for char in text):
        errors.append(f"{field} 不能包含空格")


def validate_projects(raw: dict, errors: list[str]) -> None:
    projects = raw.get("projects", [])
    if not projects:
        return
    if not isinstance(projects, list):
        errors.append("projects 必须是数组")
        return
    seen: set[str] = set()
    for index, project in enumerate(projects):
        field = f"projects[{index}]"
        if not isinstance(project, dict):
            errors.append(f"{field} 必须是对象")
            continue
        project_id = str(project.get("id") or project.get("key") or "").strip()
        if project_id:
            validate_context_name(project_id, f"{field}.id", errors)
            if project_id in seen:
                errors.append(f"{field}.id 不能重复")
            seen.add(project_id)
        validate_context_name(project.get("environment", "prod"), f"{field}.environment", errors)
        if "run_type" in project:
            validate_context_name(project.get("run_type"), f"{field}.run_type", errors)
        if "run_types" in project:
            validate_string_list(project["run_types"], f"{field}.run_types", errors)
            if isinstance(project["run_types"], list):
                for run_type_index, run_type in enumerate(project["run_types"]):
                    validate_context_name(run_type, f"{field}.run_types[{run_type_index}]", errors)
        if "enabled" in project and not isinstance(project["enabled"], bool):
            errors.append(f"{field}.enabled 必须是 true/false")
        if "tags" in project:
            validate_string_list(project["tags"], f"{field}.tags", errors)


def validate_string_list(value: object, field: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{field} 必须是数组")
        return
    if any(not str(item).strip() for item in value):
        errors.append(f"{field} 不能包含空值")


def validate_status_code_list(value: object, field: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{field} 必须是数组")
        return
    if not value:
        errors.append(f"{field} 不能为空")
        return
    for index, item in enumerate(value):
        try:
            status_code = int(item)
        except (TypeError, ValueError):
            errors.append(f"{field}[{index}] 必须是数字")
            continue
        if status_code < 100 or status_code > 599:
            errors.append(f"{field}[{index}] 必须在 100-599 之间")


def validate_alert_routing(alerts: dict, errors: list[str]) -> None:
    if "default_channels" in alerts:
        validate_string_list(alerts["default_channels"], "alerts.default_channels", errors)

    routes = alerts.get("routes", [])
    if routes:
        if not isinstance(routes, list):
            errors.append("alerts.routes must be a list")
        else:
            for index, route in enumerate(routes):
                field = f"alerts.routes[{index}]"
                if not isinstance(route, dict):
                    errors.append(f"{field} must be an object")
                    continue
                if "enabled" in route and not isinstance(route["enabled"], bool):
                    errors.append(f"{field}.enabled must be true/false")
                if "channels" in route:
                    validate_string_list(route["channels"], f"{field}.channels", errors)
                if "match" in route:
                    validate_alert_match(route["match"], f"{field}.match", errors)

    windows = alerts.get("silence_windows", [])
    if not windows:
        return
    if not isinstance(windows, list):
        errors.append("alerts.silence_windows must be a list")
        return
    for index, window in enumerate(windows):
        field = f"alerts.silence_windows[{index}]"
        if not isinstance(window, dict):
            errors.append(f"{field} must be an object")
            continue
        if "enabled" in window and not isinstance(window["enabled"], bool):
            errors.append(f"{field}.enabled must be true/false")
        if not is_hhmm(str(window.get("start", ""))):
            errors.append(f"{field}.start must be HH:MM")
        if not is_hhmm(str(window.get("end", ""))):
            errors.append(f"{field}.end must be HH:MM")
        if not is_timezone_offset(str(window.get("timezone", "+00:00"))):
            errors.append(f"{field}.timezone must be like +08:00")
        if "match" in window:
            validate_alert_match(window["match"], f"{field}.match", errors)


def validate_alert_match(value: object, field: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{field} must be an object")
        return
    list_fields = {
        "sources",
        "statuses",
        "severities",
        "categories",
        "names",
        "environments",
        "run_types",
        "name_contains",
        "summary_contains",
        "title_contains",
    }
    for key in sorted(list_fields):
        if key in value:
            validate_string_list(value[key], f"{field}.{key}", errors)


def is_hhmm(value: str) -> bool:
    parts = value.strip().split(":")
    if len(parts) != 2:
        return False
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return False
    return 0 <= hour <= 23 and 0 <= minute <= 59


def is_timezone_offset(value: str) -> bool:
    text = value.strip()
    if text in {"Z", "UTC"}:
        return True
    if len(text) != 6 or text[0] not in "+-" or text[3] != ":":
        return False
    try:
        hour = int(text[1:3])
        minute = int(text[4:6])
    except ValueError:
        return False
    return 0 <= hour <= 23 and 0 <= minute <= 59


def validate_api_auth_config(app: dict, errors: list[str]) -> None:
    if "api_auth_required_for_reads" in app and not isinstance(app["api_auth_required_for_reads"], bool):
        errors.append("app.api_auth_required_for_reads 必须是 true/false")
    if "api_token" in app and app["api_token"] is not None and not isinstance(app["api_token"], str):
        errors.append("app.api_token 必须是字符串")

    tokens = app.get("api_tokens", [])
    if not tokens:
        return
    if isinstance(tokens, list):
        for index, item in enumerate(tokens):
            field = f"app.api_tokens[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{field} 必须是对象")
                continue
            if "token" in item and not isinstance(item["token"], str):
                errors.append(f"{field}.token 必须是字符串")
            role = str(item.get("role", "viewer")).strip().lower()
            if role not in API_TOKEN_ROLES:
                errors.append(f"{field}.role 必须是 viewer/operator/admin")
        return
    if isinstance(tokens, dict):
        for name, value in tokens.items():
            field = f"app.api_tokens.{name}"
            if isinstance(value, dict):
                if "token" in value and not isinstance(value["token"], str):
                    errors.append(f"{field}.token 必须是字符串")
                role = str(value.get("role", "viewer")).strip().lower()
                if role not in API_TOKEN_ROLES:
                    errors.append(f"{field}.role 必须是 viewer/operator/admin")
            elif not isinstance(value, str):
                errors.append(f"{field} 必须是字符串或对象")
        return
    errors.append("app.api_tokens 必须是数组或对象")


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


def validate_remediation_playbooks(remediation: dict, errors: list[str]) -> None:
    playbooks = remediation.get("playbooks", [])
    if not playbooks:
        return
    if not isinstance(playbooks, list):
        errors.append("remediation.playbooks 必须是数组")
        return

    for index, playbook in enumerate(playbooks):
        field = f"remediation.playbooks[{index}]"
        if not isinstance(playbook, dict):
            errors.append(f"{field} 必须是对象")
            continue

        if not str(playbook.get("name", "")).strip():
            errors.append(f"{field}.name 不能为空")
        if "enabled" in playbook and not isinstance(playbook["enabled"], bool):
            errors.append(f"{field}.enabled 必须是 true/false")
        if "on_failure" in playbook and str(playbook["on_failure"]) not in FAILURE_POLICIES:
            errors.append(f"{field}.on_failure 必须是 continue/halt/escalate/rollback")

        match = playbook.get("match", {})
        if match and not isinstance(match, dict):
            errors.append(f"{field}.match 必须是对象")
        elif isinstance(match, dict):
            for key in (
                "sources",
                "statuses",
                "categories",
                "name_contains",
                "summary_contains",
                "url_contains",
                "path_contains",
            ):
                if key in match:
                    validate_string_list(match[key], f"{field}.match.{key}", errors)

        steps = playbook.get("steps", [])
        if not isinstance(steps, list) or not steps:
            errors.append(f"{field}.steps 必须是非空数组")
            continue

        for step_index, step in enumerate(steps):
            validate_playbook_step(step, f"{field}.steps[{step_index}]", errors)

        rollback_steps = playbook.get("rollback_steps", [])
        if rollback_steps:
            if not isinstance(rollback_steps, list):
                errors.append(f"{field}.rollback_steps 必须是数组")
            else:
                for step_index, step in enumerate(rollback_steps):
                    validate_playbook_step(step, f"{field}.rollback_steps[{step_index}]", errors)


def validate_classification_rules(raw: dict, errors: list[str]) -> None:
    rules = raw.get("classification_rules", [])
    if not rules:
        return
    if not isinstance(rules, list):
        errors.append("classification_rules 必须是数组")
        return
    for index, rule in enumerate(rules):
        field = f"classification_rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{field} 必须是对象")
            continue
        if "enabled" in rule and not isinstance(rule["enabled"], bool):
            errors.append(f"{field}.enabled 必须是 true/false")
        if not str(rule.get("category", "")).strip():
            errors.append(f"{field}.category 不能为空")
        confidence = rule.get("confidence")
        if confidence is not None:
            try:
                confidence_value = float(confidence)
            except (TypeError, ValueError):
                errors.append(f"{field}.confidence 必须是 0 到 1 之间的数字")
            else:
                if confidence_value < 0 or confidence_value > 1:
                    errors.append(f"{field}.confidence 必须是 0 到 1 之间的数字")
        if "next_steps" in rule:
            validate_string_list(rule["next_steps"], f"{field}.next_steps", errors)
        match = rule.get("match", {})
        if match and not isinstance(match, dict):
            errors.append(f"{field}.match 必须是对象")
            continue
        if isinstance(match, dict):
            for key in (
                "sources",
                "statuses",
                "name_contains",
                "summary_contains",
                "url_contains",
                "path_contains",
            ):
                if key in match:
                    validate_string_list(match[key], f"{field}.match.{key}", errors)
            if "status_codes" in match:
                validate_status_code_list(match["status_codes"], f"{field}.match.status_codes", errors)


def validate_playbook_step(step: object, field: str, errors: list[str]) -> None:
    if not isinstance(step, dict):
        errors.append(f"{field} 必须是对象")
        return
    action_type = str(step.get("action_type", "")).strip()
    if not action_type:
        errors.append(f"{field}.action_type 不能为空")
    if "risk" in step and str(step["risk"]) not in {"low", "medium", "high"}:
        errors.append(f"{field}.risk 必须是 low/medium/high")
    if "auto_execute" in step and not isinstance(step["auto_execute"], bool):
        errors.append(f"{field}.auto_execute 必须是 true/false")
    if "params" in step and not isinstance(step["params"], dict):
        errors.append(f"{field}.params 必须是对象")
    if "stage" in step and str(step["stage"]) not in STAGES:
        errors.append(f"{field}.stage 必须是 diagnose/remediate/verify/rollback")
    if "on_failure" in step and str(step["on_failure"]) not in FAILURE_POLICIES:
        errors.append(f"{field}.on_failure 必须是 continue/halt/escalate/rollback")


if __name__ == "__main__":
    raise SystemExit(main())
