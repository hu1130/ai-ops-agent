from __future__ import annotations

import json
import os
import urllib.request

from ops_agent.ai.classifier import classify_incident, format_incident_classification
from ops_agent.events import CheckResult


def analyze_incident(results: list[CheckResult], ai_config: dict) -> str:
    problems = [result for result in results if result.is_problem]
    if not problems:
        return "本轮巡检未发现异常。"

    classification_text = format_incident_classification(classify_incident(problems))

    if ai_config.get("enabled", True) and os.getenv("OPENAI_API_KEY"):
        try:
            analysis = openai_compatible_analysis(problems, int(ai_config.get("max_log_chars", 4000)))
            return f"{classification_text}\n\n{analysis}"
        except Exception as exc:
            rule_text = rule_based_analysis(problems)
            return f"{classification_text}\n\n{rule_text}\n\nAI 分析调用失败，已使用规则分析。错误：{exc}"

    return f"{classification_text}\n\n{rule_based_analysis(problems)}"


def rule_based_analysis(problems: list[CheckResult]) -> str:
    critical = [item for item in problems if item.status == "critical"]
    warnings = [item for item in problems if item.status == "warning"]
    lines = [
        "AI 运维分析（规则模式）",
        f"严重异常：{len(critical)} 个；警告：{len(warnings)} 个。",
        "",
        "异常摘要：",
    ]
    for item in problems:
        lines.append(f"- [{item.status.upper()}] {item.source}/{item.name}: {item.summary}")

    suggestions: list[str] = []
    if any(item.source == "http" for item in problems):
        suggestions.append("检查应用服务是否在线、反向代理配置、最近发布记录以及核心依赖服务。")
    if any(item.source in {"json", "json_api"} for item in problems):
        suggestions.append("检查 API 服务日志、上游模型/外部接口、数据库连接和合成请求返回内容。")
    if any(item.source == "log" for item in problems):
        suggestions.append("优先查看最新 ERROR/Exception 前后的完整日志上下文，确认是否集中在同一个接口或任务。")
    if any(item.source == "server" and "Disk" in item.name for item in problems):
        suggestions.append("磁盘异常时先确认日志、上传文件、备份文件是否快速增长。")
    if any(item.source == "server" and "Memory" in item.name for item in problems):
        suggestions.append("内存异常时检查进程占用、连接池、缓存增长和是否存在内存泄漏。")
    if any(item.source == "server" and "CPU" in item.name for item in problems):
        suggestions.append("CPU 异常时检查批处理任务、异常循环、爬虫流量或模型请求堆积。")
    if not suggestions:
        suggestions.append("先确认异常是否可复现，再对照最近变更、外部依赖和资源指标逐项排查。")

    lines.extend(["", "建议处理："])
    lines.extend(f"{index}. {text}" for index, text in enumerate(suggestions, start=1))
    return "\n".join(lines)


def openai_compatible_analysis(problems: list[CheckResult], max_chars: int) -> str:
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    api_key = os.environ["OPENAI_API_KEY"]
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是公司内部 AI 运维助手。请用中文输出简洁、可执行的故障分析，"
                    "包含影响、可能原因、排查步骤和优先级。"
                ),
            },
            {
                "role": "user",
                "content": json.dumps([result.__dict__ for result in problems], ensure_ascii=False)[:max_chars],
            },
        ],
        "temperature": 0.2,
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url=f"{base_url}/chat/completions",
        data=data,
        method="POST",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read().decode("utf-8"))
    return str(body["choices"][0]["message"]["content"])
