from __future__ import annotations

from typing import Any

from ops_agent.ai.classifier import IncidentClassification
from ops_agent.events import CheckResult
from ops_agent.remediation.actions import ActionResult
from ops_agent.remediation.policy import MUTATING_ACTIONS


AI_REPAIR_REVIEW_STATUSES = {
    "dry_run_passed",
    "needs_dry_run",
    "needs_sandbox",
    "ready_for_approval",
    "review_only",
}


def build_operator_brief(
    results: list[CheckResult],
    classification: IncidentClassification,
    action_results: list[ActionResult],
    auto_repair: dict[str, Any] | None,
    incident_id: int,
    recovery_after_successes: int,
) -> str:
    severity = "critical" if any(result.status == "critical" for result in results) else "warning"
    action_state = summarize_actions(action_results, auto_repair or {})
    lines = [
        "先看结论",
        f"- 事件编号: #{incident_id}",
        f"- 当前判断: {classification.label}（可信度 {classification.confidence:.0%}）",
        f"- 业务影响: {business_impact(classification.category, severity)}",
        f"- 你现在要做: {operator_action(classification.category, severity, action_state)}",
        f"- 系统已完成: {action_state['summary']}",
        (
            "- 接下来: 系统会继续自动复测；"
            f"连续 {max(1, recovery_after_successes)} 次正常后才会通知恢复，持续异常会升级提醒。"
        ),
        "",
        "以下是给技术人员的详细信息:",
    ]
    return "\n".join(lines)


def summarize_actions(action_results: list[ActionResult], auto_repair: dict[str, Any]) -> dict[str, Any]:
    failed = [result for result in action_results if result.status in {"failed", "verified_failed"}]
    changed = [
        result
        for result in action_results
        if result.action.action_type in MUTATING_ACTIONS
        and result.status in {"executed", "verified_ok", "verified_failed"}
    ]
    verified = [result for result in changed if result.status == "verified_ok"]
    read_only_executed = [
        result
        for result in action_results
        if result.action.action_type not in MUTATING_ACTIONS
        and result.status in {"executed", "verified_ok"}
    ]
    proposed = [result for result in action_results if result.status in {"planned", "dry_run", "pending_approval"}]
    ai_status = str(auto_repair.get("status") or "")

    if failed:
        return {
            "needs_human": True,
            "approval_only": False,
            "summary": "自动处置没有成功，错误信息和现场证据已经保存，未继续冒险操作。",
        }
    if verified:
        titles = compact_titles(verified)
        return {
            "needs_human": False,
            "approval_only": False,
            "summary": f"已自动执行并验证安全动作: {titles}。",
        }
    if changed:
        titles = compact_titles(changed)
        return {
            "needs_human": False,
            "approval_only": False,
            "summary": f"已自动执行安全动作: {titles}；正在等待监控复测确认。",
        }
    if ai_status in AI_REPAIR_REVIEW_STATUSES:
        return {
            "needs_human": False,
            "approval_only": True,
            "summary": "AI 已生成修复建议并完成安全检查，尚未修改代码，正在等待人工审核。",
        }
    if proposed:
        return {
            "needs_human": False,
            "approval_only": any(result.status == "pending_approval" for result in proposed),
            "summary": "已完成诊断并生成处理方案，目前没有修改服务器或业务代码。",
        }
    if read_only_executed:
        return {
            "needs_human": False,
            "approval_only": False,
            "summary": "已自动完成只读排查并保存证据，没有修改服务器或业务代码。",
        }
    return {
        "needs_human": False,
        "approval_only": False,
        "summary": "已完成异常判断和证据留存，没有执行重启、配置修改或代码修改。",
    }


def business_impact(category: str, severity: str) -> str:
    if category == "probe_config_issue":
        return "业务入口大概率仍可用，当前更像监控地址、鉴权或预期状态配置不正确。"
    if category == "synthetic_quality_fail":
        return "接口可能仍能访问，但返回内容或 AI 回答质量没有达到要求。"
    if category == "performance_degraded":
        return "服务仍可使用，但响应变慢；持续恶化时可能影响用户体验。"
    if category == "resource_pressure":
        return "服务器资源接近风险线，继续升高可能造成服务变慢或不可用。"
    if category == "container_unhealthy":
        return "容器健康检查异常，服务可能仍可访问，但稳定性存在风险。"
    if category in {"service_unavailable", "dependency_failure", "business_flow_failure"}:
        return "可能已经影响用户访问或核心业务流程。"
    if category == "node_offline":
        return "中心端无法确认这台服务器及其项目状态，服务器可能断网、关机或采集服务停止。"
    if category == "remote_project_missing":
        return "服务器仍在线，但已绑定项目没有运行，可能已经影响该项目用户。"
    if severity == "critical":
        return "这是严重异常，可能已经影响用户，需要尽快确认。"
    return "当前是警告级异常，尚未确认造成真实业务中断。"


def operator_action(category: str, severity: str, action_state: dict[str, Any]) -> str:
    if action_state["needs_human"]:
        return "需要人工处理。请把事件编号发给项目负责人，优先查看自动处置失败原因。"
    if action_state["approval_only"]:
        if severity == "critical":
            return "需要处理。请让项目负责人确认用户影响并审核修复建议；审核前系统不会修改代码。"
        return "只需审核系统生成的修复建议；审核前系统不会修改代码。"
    if category == "probe_config_issue":
        return "现在不用按网站宕机处理；安排同事修正监控配置即可。"
    if category == "node_offline":
        return "先确认服务器能否登录，再检查 ops-agent-fleet 服务；不要同时重启服务器上的所有项目。"
    if category == "remote_project_missing":
        return "确认是否计划停机；若不是，联系项目负责人查看容器和最近部署记录。"
    if severity == "critical":
        return "需要处理。请让项目负责人确认用户是否受影响，并查看最近发布或配置变更。"
    if category == "unknown":
        return "请让项目负责人确认一次；证据不足时系统不会擅自修复。"
    return "暂时不用操作，等待系统自动复测；只有持续异常或升级时再处理。"


def compact_titles(results: list[ActionResult]) -> str:
    titles: list[str] = []
    for result in results:
        title = result.action.title.strip()
        if title and title not in titles:
            titles.append(title)
    return "、".join(titles[:3]) or "安全处置动作"
