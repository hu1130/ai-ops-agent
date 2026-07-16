from __future__ import annotations

from ops_agent.events import CheckResult


def build_action_suggestions(results: list[CheckResult]) -> str:
    suggestions: list[str] = []

    if any(result.source in {"json", "json_api"} for result in results):
        suggestions.append("AI 客服慢或失败时，先看接口日志、模型供应商响应时间、数据库连接和最近发布。")
    if any(result.source == "http" for result in results):
        suggestions.append("官网/API 不通时，先确认域名解析、Nginx 反代、容器状态和应用健康接口。")
    if any(result.source == "log" for result in results):
        suggestions.append("日志出现 ERROR/Exception 时，优先查看报错前后 100 行，定位具体接口、任务或用户请求。")
    if any(result.source == "server" and "Disk" in result.name for result in results):
        suggestions.append("磁盘告警时，先查日志、上传目录、备份文件是否快速增长，再清理低风险临时文件。")
    if any(result.source == "server" and "Memory" in result.name for result in results):
        suggestions.append("内存告警时，先查占用最高的进程、容器内存和是否存在请求堆积。")
    if any(result.source == "server" and "CPU" in result.name for result in results):
        suggestions.append("CPU 告警时，先确认是否有批处理任务、异常循环、爬虫流量或模型请求堆积。")
    if any(result.source == "database" for result in results):
        suggestions.append("数据库告警时，先确认真实查询、连接使用率、运行线程、磁盘空间和最近表结构变更。")
    if any(result.source == "backup" for result in results):
        suggestions.append("备份告警时，先保留现有备份，再检查备份文件、校验和、空间和隔离恢复演练结果。")

    if not suggestions:
        suggestions.append("先确认异常是否连续出现，再对照最近发布、外部依赖和服务器资源逐项排查。")

    lines = ["", "下一步建议:"]
    lines.extend(f"{index}. {text}" for index, text in enumerate(suggestions, start=1))
    return "\n".join(lines)
