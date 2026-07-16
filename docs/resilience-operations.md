# 数据库、资产发现与备份恢复

本文说明数据库专项监控、运行时资产发现、自动备份和恢复演练的配置与安全边界。

## 数据库专项监控

`database_checks` 支持宿主机 MySQL 客户端和 Docker 内 MySQL 两种方式。Docker 模式从容器环境读取现有账号，不需要把数据库密码复制到运维配置中。

监控只执行只读状态查询，采集连接使用率、运行线程、慢查询计数、查询耗时、数据库大小、只读状态和运行时间。查询失败为严重异常；连接压力、线程过多、查询过慢或数据库过大为警告。

```json
{
  "name": "Sales MySQL",
  "engine": "mysql_docker",
  "container": "sales-ai-mysql",
  "interval_seconds": 60,
  "timeout_seconds": 10,
  "max_connection_usage_percent": 80,
  "max_running_threads": 20,
  "max_query_latency_ms": 3000,
  "alert_after_failures": 2,
  "recovery_after_successes": 2
}
```

## 运行时资产发现

`asset_discovery` 定时读取正在运行的 Docker 容器，并与 Docker、日志、数据库和备份监控配置进行比对。发现疑似业务应用尚未纳管时产生 `warning`，不会自动修改配置或重启容器。

数据库、Redis、MinIO、Chroma、Adminer、Syncthing、Prometheus 和 Grafana 等基础设施默认不会作为独立业务项目报警。已停用项目的容器也会被忽略。确实不需要监控的容器可加入 `ignored_containers`。

```json
{
  "enabled": true,
  "name": "Runtime asset coverage",
  "interval_seconds": 900,
  "unmonitored_status": "warning",
  "ignored_containers": [],
  "alert_after_failures": 2,
  "recovery_after_successes": 2
}
```

查看发现结果：`GET /api/discovery`。

## 自动备份

`backups.targets` 支持 SQLite 和 Docker MySQL。每个目标独立设置备份周期、文件保留天数、至少保留份数和恢复演练周期。备份文件保存在 `base_dir`，MySQL 备份使用 gzip 压缩并记录 SHA-256 校验值。

```json
{
  "enabled": true,
  "base_dir": "data/backups",
  "targets": [
    {
      "id": "sales-mysql",
      "engine": "mysql_docker",
      "container": "sales-ai-mysql",
      "interval_hours": 24,
      "retention_days": 14,
      "minimum_backups": 3,
      "restore_drill": {
        "enabled": true,
        "interval_days": 7
      }
    }
  ]
}
```

接口：

- `GET /api/backups`：查看策略、最近运行和健康状态。
- `POST /api/backups/run`：立即备份指定目标，请求体为 `{"target_id":"sales-mysql"}`。
- `POST /api/backups/drill`：立即恢复演练指定目标，请求体同上。

## 恢复演练安全边界

SQLite 演练恢复到临时文件，执行完整性检查后删除临时文件。MySQL 演练只允许创建名称以 `ops_restore_drill_` 开头的临时数据库，恢复并验证表数量后立即删除。演练代码不会删除、覆盖或改写生产数据库。

备份成功不等于可恢复。企业环境应持续观察备份新鲜度、最近一次恢复演练结果和磁盘容量，并定期把备份复制到服务器之外的独立存储。
