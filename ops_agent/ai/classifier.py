from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ops_agent.events import CheckResult

CATEGORY_LABELS = {
    "probe_config_issue": "监控探针或配置问题",
    "service_unavailable": "服务不可用",
    "dependency_failure": "依赖故障",
    "performance_degraded": "性能下降",
    "container_unhealthy": "容器健康异常",
    "log_error_spike": "日志错误增加",
    "synthetic_quality_fail": "合成测试质量失败",
    "resource_pressure": "服务器资源压力",
    "database_failure": "数据库故障",
    "monitor_coverage_gap": "监控覆盖缺口",
    "backup_failure": "备份或恢复演练失败",
    "node_offline": "服务器失联",
    "remote_project_missing": "远程项目停止运行",
    "unknown": "未知异常",
}
CATEGORY_LABELS["business_flow_failure"] = "业务流程失败"


@dataclass
class IncidentClassification:
    category: str
    confidence: float
    summary: str
    evidence: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)


def classify_incident(
    results: list[CheckResult],
    classification_rules: list[dict[str, Any]] | None = None,
) -> IncidentClassification:
    problems = [result for result in results if result.is_problem]
    if not problems:
        return IncidentClassification(
            category="unknown",
            confidence=0.0,
            summary="本轮没有异常信号。",
            evidence=[],
            next_steps=["继续观察下一轮巡检结果。"],
        )

    signal_classifications = [classify_signal(result, classification_rules) for result in problems]
    correlated = correlate_signals(problems, signal_classifications)
    if correlated:
        return correlated
    return max(signal_classifications, key=lambda item: item.confidence)


def classify_signal(
    result: CheckResult,
    classification_rules: list[dict[str, Any]] | None = None,
) -> IncidentClassification:
    configured = classify_by_configured_rules(result, classification_rules)
    if configured:
        return configured
    if result.source == "http":
        return classify_http(result)
    if result.source in {"json", "json_api"}:
        return classify_json_api(result)
    if result.source == "business_flow":
        return classify_business_flow(result)
    if result.source == "log":
        return classify_log(result)
    if result.source == "docker":
        return classify_docker(result)
    if result.source == "server":
        return classify_server(result)
    if result.source == "fleet_resource":
        return classify_server(result)
    if result.source == "database":
        return classify_database(result)
    if result.source == "discovery":
        return classify_discovery(result)
    if result.source == "backup":
        return classify_backup(result)
    if result.source in {"fleet", "fleet_project"}:
        return classify_fleet(result)
    return unknown_classification(result)


def classify_by_configured_rules(
    result: CheckResult,
    classification_rules: list[dict[str, Any]] | None,
) -> IncidentClassification | None:
    for rule in classification_rules or []:
        if not isinstance(rule, dict) or not bool(rule.get("enabled", True)):
            continue
        match = rule.get("match", {})
        if not isinstance(match, dict) or not configured_rule_matches(result, match):
            continue
        category = str(rule.get("category") or "unknown").strip() or "unknown"
        confidence = bounded_float(rule.get("confidence"), default=0.75)
        summary = str(rule.get("summary") or f"Matched configured classifier rule: {rule.get('name') or category}")
        next_steps = safe_list(rule.get("next_steps")) or [
            "Review the matched configured classification rule and related signal evidence."
        ]
        evidence = [f"configured_rule={rule.get('name') or category}"]
        evidence.extend(base_evidence(result))
        return IncidentClassification(
            category=category,
            confidence=confidence,
            summary=summary,
            evidence=[str(item) for item in evidence],
            next_steps=[str(item) for item in next_steps],
        )
    return None


def classify_http(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    classification = str(details.get("classification", ""))
    status_code = int_or_none(details.get("status_code"))
    latency_ms = int_or_none(details.get("latency_ms"))
    evidence = base_evidence(result)

    if classification.endswith("_fallback_reachable"):
        fallback = safe_dict(details.get("fallback"))
        if fallback:
            evidence.append(
                f"备用入口 {fallback.get('url')} 返回 HTTP {fallback.get('status_code')}，说明同域名仍可访问。"
            )
        return IncidentClassification(
            category="probe_config_issue",
            confidence=0.9,
            summary="主探针失败，但备用入口可达，更像健康检查路径、鉴权或预期状态配置问题。",
            evidence=evidence,
            next_steps=[
                "确认监控 URL 是否应该改为真实健康接口。",
                "如果项目没有健康接口，补充 /health 或 /healthz，而不是长期用页面入口代替。",
                "检查 expected_status、请求方法和鉴权要求是否符合实际。",
            ],
        )

    if status_code is not None and status_code >= 500:
        return IncidentClassification(
            category="service_unavailable",
            confidence=0.86,
            summary="HTTP 5xx 表示应用、网关或上游服务返回错误，优先按真实服务故障处理。",
            evidence=evidence,
            next_steps=[
                "查看 Nginx/网关和应用容器日志。",
                "确认应用进程、端口、数据库和外部依赖是否正常。",
                "对照最近发布、重启和配置变更。",
            ],
        )

    if "slow response" in result.summary.lower() or latency_too_high(details):
        return IncidentClassification(
            category="performance_degraded",
            confidence=0.78,
            summary="HTTP 请求成功但响应时间超过阈值，属于性能下降。",
            evidence=evidence,
            next_steps=[
                "查看慢接口日志和上游依赖耗时。",
                "确认 CPU、内存、数据库连接池和外部 API 是否存在等待。",
            ],
        )

    if "request failed" in result.summary.lower():
        return IncidentClassification(
            category="service_unavailable",
            confidence=0.8,
            summary="HTTP 请求未成功建立或读取，优先判断为服务不可达或网络/代理故障。",
            evidence=evidence,
            next_steps=[
                "确认 DNS、证书、Nginx 反代和目标端口。",
                "从服务器本机 curl 目标地址复现问题。",
            ],
        )

    return unknown_classification(result)


def classify_json_api(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    status_code = int_or_none(details.get("status_code"))
    latency_ms = int_or_none(details.get("latency_ms"))
    summary = result.summary.lower()
    evidence = base_evidence(result)

    if "suspicious phrase" in summary or "required json path" in summary or "not valid json" in summary:
        return IncidentClassification(
            category="synthetic_quality_fail",
            confidence=0.82,
            summary="合成请求返回了异常结构、异常话术或不合格内容，属于业务质量异常。",
            evidence=evidence,
            next_steps=[
                "查看接口实际返回内容和提示词/知识库配置。",
                "确认是否走到了兜底回复、空回复或错误包装。",
                "补充多问题合成测试，避免单个问题误判。",
            ],
        )

    if status_code is not None and status_code >= 500:
        return IncidentClassification(
            category="dependency_failure",
            confidence=0.8,
            summary="JSON/API 探针返回 5xx，常见原因是模型服务、数据库、缓存或应用依赖异常。",
            evidence=evidence,
            next_steps=[
                "检查 API 服务日志和上游依赖日志。",
                "确认数据库、Redis、模型供应商或内部服务是否可用。",
            ],
        )

    if "slow response" in summary or latency_too_high(details):
        return IncidentClassification(
            category="performance_degraded",
            confidence=0.78,
            summary="合成 API 请求成功但响应过慢，属于性能下降。",
            evidence=evidence,
            next_steps=[
                "拆分接口耗时：应用处理、数据库、模型请求、网络调用。",
                "检查是否有排队、限流或外部模型响应变慢。",
            ],
        )

    if "request failed" in summary:
        return IncidentClassification(
            category="service_unavailable",
            confidence=0.76,
            summary="合成 API 请求失败，优先判断为接口不可达或服务链路异常。",
            evidence=evidence,
            next_steps=[
                "从服务器本机重放请求，确认网络和鉴权。",
                "检查 API 服务进程、容器状态和最近错误日志。",
            ],
        )

    return unknown_classification(result)


def classify_business_flow(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    failed_step = safe_dict(details.get("failed_step"))
    status_code = int_or_none(failed_step.get("status_code") or details.get("status_code"))
    summary = result.summary.lower()
    evidence = base_evidence(result)
    if failed_step:
        evidence.append(
            f"Business flow failed at step {failed_step.get('index')}: "
            f"{failed_step.get('name')} {failed_step.get('url')}"
        )
    if status_code is not None:
        evidence.append(f"Failed step HTTP status: {status_code}")

    if status_code in {401, 403} or "login" in summary or "auth" in summary or "unauthorized" in summary:
        return IncidentClassification(
            category="business_flow_failure",
            confidence=0.9,
            summary="Authenticated business flow failed. The site may open, but login/session/permission path is broken.",
            evidence=evidence,
            next_steps=[
                "Replay the failed synthetic flow step with the same test account and headers.",
                "Check login/session/token issuance, permission checks, and recently changed auth configuration.",
                "Inspect application logs around the failed step URL and related user/test account.",
            ],
        )

    if status_code is not None and status_code >= 500:
        return IncidentClassification(
            category="service_unavailable",
            confidence=0.88,
            summary="A real business flow step returned 5xx, so this is likely an application or dependency outage.",
            evidence=evidence,
            next_steps=[
                "Inspect gateway and application logs for the failed business endpoint.",
                "Check database/cache/model/provider dependencies used by this step.",
                "Compare the failure with the latest deploy and configuration changes.",
            ],
        )

    if "missing required" in summary or "forbidden text" in summary or "suspicious phrase" in summary:
        return IncidentClassification(
            category="business_flow_failure",
            confidence=0.86,
            summary="Business flow returned HTTP success but content or JSON assertions failed.",
            evidence=evidence,
            next_steps=[
                "Open the failed step response sample and confirm whether the page/API entered the expected business state.",
                "Check whether the user was redirected to login, fallback, empty data, or an error wrapper.",
                "Update assertions only after confirming the product behavior intentionally changed.",
            ],
        )

    if "slow" in summary:
        return IncidentClassification(
            category="performance_degraded",
            confidence=0.78,
            summary="Business flow completed but exceeded latency threshold.",
            evidence=evidence,
            next_steps=[
                "Break down latency by step and inspect the slow endpoint.",
                "Check database queries, queue backlog, upstream APIs, and resource pressure.",
            ],
        )

    return IncidentClassification(
        category="business_flow_failure",
        confidence=0.78,
        summary="A configured business flow failed; this should be treated as a user-path problem until proven otherwise.",
        evidence=evidence,
        next_steps=[
            "Replay the flow manually or with curl using the same configured test account.",
            "Inspect failed step logs and dependency status.",
            "Add or adjust assertions only after the actual business behavior is confirmed.",
        ],
    )


def classify_log(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    match_count = int_or_none(details.get("match_count")) or 0
    evidence = base_evidence(result)
    matches = details.get("matches")
    if isinstance(matches, list) and matches:
        evidence.append(f"最近匹配日志样例: {str(matches[-1])[:180]}")

    if "unhealthy" in result.summary.lower() or any("unhealthy" in str(item).lower() for item in safe_list(matches)):
        return IncidentClassification(
            category="container_unhealthy",
            confidence=0.78,
            summary="日志或容器输出出现 unhealthy 信号，需要区分容器健康检查异常和业务不可用。",
            evidence=evidence,
            next_steps=[
                "查看容器 healthcheck 命令和 docker inspect 健康详情。",
                "同时验证业务入口是否可访问，避免只凭容器状态误报。",
            ],
        )

    if match_count > 0:
        return IncidentClassification(
            category="log_error_spike",
            confidence=0.76,
            summary="日志中出现错误关键词，说明应用内部可能存在异常。",
            evidence=evidence,
            next_steps=[
                "查看错误前后上下文，定位具体接口、任务或依赖。",
                "统计相同错误是否连续出现，判断是否升级为服务故障。",
            ],
        )

    if "not found" in result.summary.lower() or "read failed" in result.summary.lower():
        return IncidentClassification(
            category="probe_config_issue",
            confidence=0.62,
            summary="日志读取失败或路径不存在，更像日志探针配置问题。",
            evidence=evidence,
            next_steps=[
                "确认日志路径、容器名和读取权限。",
                "容器重建后优先使用稳定容器名，不要写死容器 ID 路径。",
            ],
        )

    return unknown_classification(result)


def classify_docker(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    evidence = base_evidence(result)
    summary = result.summary.lower()
    container_status = str(details.get("container_status") or "").strip().lower()
    health_status = str(details.get("health_status") or "").strip().lower()
    running = details.get("running")
    classification = str(details.get("classification") or "")

    if classification.endswith("_fallback_reachable"):
        fallback = safe_dict(details.get("fallback"))
        if fallback:
            evidence.append(f"备用入口 {fallback.get('url')} 返回 HTTP {fallback.get('status_code')}，说明业务入口仍可访问。")
        return IncidentClassification(
            category="probe_config_issue",
            confidence=0.88,
            summary="Docker healthcheck 失败，但备用业务入口可达，更像容器健康检查路径配置问题。",
            evidence=evidence,
            next_steps=[
                "把 Docker healthcheck 改为真实存在的健康接口，或在应用里补充 /healthz。",
                "继续保留业务入口 HTTP 探针，确保真实用户路径不可访问时仍会 critical 告警。",
            ],
        )

    if health_status == "unhealthy" or "unhealthy" in summary:
        return IncidentClassification(
            category="container_unhealthy",
            confidence=0.9,
            summary="Docker 容器 healthcheck 已经返回 unhealthy，需要优先查看容器健康检查、应用日志和业务入口。",
            evidence=evidence,
            next_steps=[
                "执行 docker inspect 查看 Health 日志和最近失败原因。",
                "查看容器最新应用日志，定位 healthcheck 失败对应的接口、依赖或进程状态。",
                "同时复测业务入口，确认是否已经影响用户访问。",
            ],
        )

    if running is False or container_status in {"exited", "dead", "restarting", "removing", "paused"}:
        return IncidentClassification(
            category="container_unhealthy",
            confidence=0.88,
            summary="Docker 容器没有处于稳定运行状态，业务服务可能已经退出、重启循环或被暂停。",
            evidence=evidence,
            next_steps=[
                "查看 docker ps -a 和 docker logs，确认退出码和最后错误。",
                "对照最近部署、配置和依赖变更。",
                "重启前先确认数据写入、任务队列和外部依赖状态。",
            ],
        )

    if "docker command is not available" in summary or "docker inspect failed" in summary:
        return IncidentClassification(
            category="probe_config_issue",
            confidence=0.72,
            summary="Docker 探针无法读取容器状态，可能是 Docker 不可用、容器名错误或权限不足。",
            evidence=evidence,
            next_steps=[
                "确认服务器上 docker 命令可用且 ops-agent 有读取 Docker 状态的权限。",
                "确认 docker_checks.container 是否是稳定容器名，而不是旧容器 ID。",
            ],
        )

    if "no docker healthcheck" in summary:
        return IncidentClassification(
            category="probe_config_issue",
            confidence=0.66,
            summary="容器正在运行，但缺少 Docker healthcheck，监控无法判断容器内部健康状态。",
            evidence=evidence,
            next_steps=[
                "为容器补充 Docker healthcheck 或关闭 require_healthcheck。",
                "同时配置 HTTP/API 业务入口探针覆盖真实用户路径。",
            ],
        )

    return unknown_classification(result)


def classify_server(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    evidence = base_evidence(result)
    used_percent = details.get("used_percent")
    threshold = details.get("threshold")
    if used_percent is not None and threshold is not None:
        evidence.append(f"资源使用率 {used_percent}% 已达到阈值 {threshold}%。")

    return IncidentClassification(
        category="resource_pressure",
        confidence=0.84,
        summary="服务器资源超过阈值，可能影响应用、数据库或日志写入。",
        evidence=evidence,
        next_steps=[
            "先定位占用最高的进程、容器或目录。",
            "确认是否存在日志暴涨、批处理任务、异常循环或连接堆积。",
            "清理或重启前先保留关键诊断信息。",
        ],
    )


def classify_database(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    evidence = base_evidence(result)
    classification = str(details.get("classification") or "")
    if details.get("container"):
        evidence.append(f"数据库容器: {details.get('container')}")
    if details.get("database"):
        evidence.append(f"数据库名: {details.get('database')}")
    if classification == "database_unavailable" or result.status == "critical":
        return IncidentClassification(
            category="database_failure",
            confidence=0.92,
            summary="数据库真实查询失败，可能已经影响依赖它的接口和业务流程。",
            evidence=evidence,
            next_steps=[
                "检查 MySQL 容器状态和数据库错误日志。",
                "确认磁盘空间、连接数、账号权限和最近数据库变更。",
                "恢复前先确认备份状态，避免直接执行高风险数据库操作。",
            ],
        )
    return IncidentClassification(
        category="resource_pressure" if classification == "database_pressure" else "database_failure",
        confidence=0.84,
        summary="数据库查询仍可完成，但连接、线程、容量或响应耗时达到警告阈值。",
        evidence=evidence,
        next_steps=[
            "查看连接使用率、运行线程和慢查询。",
            "检查应用连接池、长事务和数据库容量趋势。",
        ],
    )


def classify_discovery(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    evidence = base_evidence(result)
    candidates = safe_list(details.get("unmonitored_applications"))
    for item in candidates[:5]:
        payload = safe_dict(item)
        evidence.append(f"未监控容器: {payload.get('name')} image={payload.get('image')}")
    if str(details.get("classification") or "") == "asset_discovery_unavailable":
        return IncidentClassification(
            category="probe_config_issue",
            confidence=0.76,
            summary="自动发现无法读取 Docker 运行资产，需要检查 Docker 权限或命令状态。",
            evidence=evidence,
            next_steps=["确认 ops-agent 可以执行 docker ps。", "检查 Docker 服务和运行权限。"],
        )
    return IncidentClassification(
        category="monitor_coverage_gap",
        confidence=0.9,
        summary="发现正在运行的业务容器没有任何容器、日志、数据库或备份监控。",
        evidence=evidence,
        next_steps=[
            "确认容器属于需要维护的启用项目。",
            "为业务入口、容器状态和关键日志至少补充一种监控。",
            "如果容器属于停用项目或基础设施，将其加入忽略规则。",
        ],
    )


def classify_backup(result: CheckResult) -> IncidentClassification:
    evidence = base_evidence(result)
    details = result.details or {}
    latest = safe_dict(details.get("latest_backup"))
    drill = safe_dict(details.get("latest_restore_drill"))
    if latest:
        evidence.append(f"最近备份: {latest.get('completed_at')} status={latest.get('status')}")
    if drill:
        evidence.append(f"最近恢复演练: {drill.get('completed_at')} status={drill.get('status')}")
    return IncidentClassification(
        category="backup_failure",
        confidence=0.92,
        summary="备份缺失、过期、执行失败或隔离恢复演练未通过，发生故障时可能无法可靠恢复数据。",
        evidence=evidence,
        next_steps=[
            "先修复备份失败原因，不要删除现有可用备份。",
            "重新执行备份并在隔离目标中完成恢复演练。",
            "确认备份文件大小、校验和和恢复后的表数量。",
        ],
    )


def classify_fleet(result: CheckResult) -> IncidentClassification:
    details = result.details or {}
    evidence = base_evidence(result)
    node_id = str(details.get("node_id") or "")
    if node_id:
        evidence.append(f"服务器节点: {node_id}")
    if result.source == "fleet_project":
        return IncidentClassification(
            category="remote_project_missing",
            confidence=0.94,
            summary="远程服务器仍在线，但已绑定项目不再出现在运行容器中。",
            evidence=evidence,
            next_steps=[
                "先确认项目是否计划停机、改名或迁移到了其他服务器。",
                "如果不是计划变更，查看该服务器上的容器状态和最近部署记录。",
                "恢复项目后等待连续两次上报正常，系统会自动关闭事件。",
            ],
        )
    discovery = safe_dict(details.get("discovery"))
    if discovery.get("status") not in {"", "ok"}:
        return IncidentClassification(
            category="probe_config_issue",
            confidence=0.84,
            summary="服务器仍在上报，但暂时无法读取 Docker 项目列表，系统未把项目误判为停机。",
            evidence=evidence + [f"项目探测错误: {discovery.get('error') or discovery.get('status')}"],
            next_steps=["检查该服务器的 Docker 服务和采集进程权限。", "无需逐个重启业务项目。"],
        )
    return IncidentClassification(
        category="node_offline",
        confidence=0.96,
        summary="中心端超过允许时间没有收到服务器心跳，无法确认该服务器上的项目状态。",
        evidence=evidence,
        next_steps=[
            "确认服务器是否关机、断网或迁移。",
            "检查远程 ops-agent-fleet 服务是否正在运行。",
            "服务器恢复上报后等待连续两次正常，系统会自动关闭事件。",
        ],
    )


def correlate_signals(
    results: list[CheckResult],
    classifications: list[IncidentClassification],
) -> IncidentClassification | None:
    categories = {item.category for item in classifications}
    sources = {result.source for result in results}
    evidence = merge_evidence(classifications)

    if "resource_pressure" in categories and ({"http", "json_api", "business_flow"} & sources):
        return IncidentClassification(
            category="dependency_failure",
            confidence=0.87,
            summary="资源压力和业务探针异常同时出现，优先怀疑资源压力引发服务或依赖故障。",
            evidence=evidence + ["同一轮巡检同时出现资源异常和业务探针异常。"],
            next_steps=[
                "先处理资源瓶颈，再复测业务入口。",
                "查看资源最高的进程/容器是否属于当前异常项目。",
            ],
        )

    if "log_error_spike" in categories and ({"http", "json_api", "business_flow"} & sources):
        return IncidentClassification(
            category="service_unavailable",
            confidence=0.86,
            summary="业务探针异常和应用日志错误同时出现，更像真实应用故障。",
            evidence=evidence + ["HTTP/API 异常与日志错误在同一事件中同时出现。"],
            next_steps=[
                "以日志错误为入口定位具体代码路径或依赖。",
                "复测 HTTP/API 探针，确认影响范围。",
                "对照最近发布和配置变更。",
            ],
        )

    if "probe_config_issue" in categories and len(categories) == 1:
        return IncidentClassification(
            category="probe_config_issue",
            confidence=max(item.confidence for item in classifications),
            summary="所有异常信号都指向探针或配置问题，暂不按真实业务故障处理。",
            evidence=evidence,
            next_steps=[
                "修正监控地址、鉴权、请求方法或日志路径。",
                "修正后手动跑一轮巡检，确认事件自动恢复。",
            ],
        )

    return None


def format_incident_classification(classification: IncidentClassification) -> str:
    lines = [
        "",
        "通用异常分类:",
        f"- 主分类: {classification.category}（{classification.label}）",
        f"- 置信度: {classification.confidence:.2f}",
        f"- 判断: {classification.summary}",
        "",
        "证据链:",
    ]
    if classification.evidence:
        lines.extend(f"{index}. {item}" for index, item in enumerate(classification.evidence, start=1))
    else:
        lines.append("1. 暂无足够证据。")
    lines.append("")
    lines.append("下一步动作:")
    lines.extend(f"{index}. {item}" for index, item in enumerate(classification.next_steps, start=1))
    return "\n".join(lines)


def base_evidence(result: CheckResult) -> list[str]:
    evidence = [f"{result.source}/{result.name}: {result.summary}"]
    details = result.details or {}
    if details.get("url"):
        evidence.append(f"目标 URL: {details.get('url')}")
    if details.get("status_code") is not None:
        evidence.append(f"HTTP 状态码: {details.get('status_code')}")
    if details.get("latency_ms") is not None:
        evidence.append(f"响应耗时: {details.get('latency_ms')} ms")
    if details.get("path"):
        evidence.append(f"路径: {details.get('path')}")
    if details.get("container"):
        evidence.append(f"容器: {details.get('container')}")
    return evidence


def merge_evidence(classifications: list[IncidentClassification]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for classification in classifications:
        for item in classification.evidence:
            if item in seen:
                continue
            seen.add(item)
            merged.append(item)
            if len(merged) >= 8:
                return merged
    return merged


def unknown_classification(result: CheckResult) -> IncidentClassification:
    return IncidentClassification(
        category="unknown",
        confidence=0.4,
        summary="当前信号不足以稳定判断根因类型。",
        evidence=base_evidence(result),
        next_steps=[
            "先确认异常是否可复现。",
            "补充日志、资源、HTTP/API 等更多信号后再做关联判断。",
        ],
    )


def int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def latency_too_high(details: dict[str, Any]) -> bool:
    latency = int_or_none(details.get("latency_ms"))
    threshold = int_or_none(details.get("max_latency_ms"))
    return latency is not None and threshold is not None and latency > threshold


def configured_rule_matches(result: CheckResult, match: dict[str, Any]) -> bool:
    if not exact_list_matches(result.source, match.get("sources")):
        return False
    if not exact_list_matches(result.status, match.get("statuses")):
        return False
    if not status_code_matches(result.details.get("status_code"), match.get("status_codes")):
        return False
    if not contains_any(result.name, match.get("name_contains")):
        return False
    if not contains_any(result.summary, match.get("summary_contains")):
        return False
    if not contains_any(str(result.details.get("url", "")), match.get("url_contains")):
        return False
    if not contains_any(str(result.details.get("path", "")), match.get("path_contains")):
        return False
    return True


def exact_list_matches(value: str, candidates: object) -> bool:
    if not candidates:
        return True
    if not isinstance(candidates, list):
        return False
    normalized = {str(item).strip() for item in candidates if str(item).strip()}
    return "*" in normalized or value in normalized


def contains_any(value: str, candidates: object) -> bool:
    if not candidates:
        return True
    if not isinstance(candidates, list):
        return False
    text = value.casefold()
    return any(str(item).strip().casefold() in text for item in candidates if str(item).strip())


def status_code_matches(value: object, candidates: object) -> bool:
    if not candidates:
        return True
    if not isinstance(candidates, list):
        return False
    status_code = int_or_none(value)
    if status_code is None:
        return False
    normalized = {int_or_none(item) for item in candidates}
    return status_code in normalized


def bounded_float(value: object, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 0.0), 1.0)


def safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
