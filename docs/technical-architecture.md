# AI 自动化运维工具 V1 技术架构

## 1. 当前形态

系统采用“中心端 + 轻量节点”的私有化架构。

- 中心端：监控调度、事件中心、规则与 AI 诊断、修复审批、管理页面、告警和审计。
- 节点端：部署在客户 Linux 服务器，采集心跳、资源指标和 Docker 项目，不持有中心管理权限。
- 数据库：开发和单机模式支持 SQLite，生产支持 MySQL。
- 部署：中心端和节点端均由 systemd 守护。

## 2. 核心数据流

监控链路：

1. HTTP、JSON API、业务流程、日志、Docker、数据库、服务器和节点探针产生 CheckResult。
2. 调度器为结果补充 organization_id、project_id、environment、run_type 和 trace_id。
3. 告警状态机执行连续失败、连续恢复、冷却、重复提醒和升级策略。
4. 异常形成 Incident，分类、证据、诊断、建议、动作和通知全部落库。
5. 页面和邮件只展示当前授权项目的数据。

AI 修复链路：

1. 从事件、诊断、最近动作和代码仓库提取受限上下文。
2. 规则引擎或 DeepSeek 生成结构化修复提案和 unified diff。
3. 防护层阻止越界路径、敏感文件和不安全命令。
4. 补丁只在隔离副本中应用并运行项目测试。
5. 人工审批后创建受控分支和 Pull Request。
6. PR 合并后才允许部署；健康验证失败时恢复上一提交并执行回滚命令。
7. 所有状态变化、命令摘要和结果写入审计与变更事件。

## 3. 身份和隔离

- Organization：一次私有化部署默认一个组织，数据表保留组织字段。
- User：PBKDF2-SHA256 加盐密码，Owner、Admin、Operator、Viewer 四级角色。
- Session：随机令牌只保存 SHA-256 摘要，支持过期、撤销和密码变更后失效。
- API Credential：可限制角色与项目，明文只在创建时返回一次。
- Project Scope：结果、事件、建议、动作和 AI 修复在 API 与存储查询两层校验。
- Fleet Enrollment：节点令牌可绑定 node_id、设置有效期并随时撤销，只能调用心跳接口。

## 4. 主要模块

- ops_agent/scheduler.py：巡检、状态机、事件、通知和定时任务编排。
- ops_agent/storage.py：SQLite/MySQL 兼容存储、迁移和审计查询。
- ops_agent/dashboard.py：认证、授权、项目隔离和管理 API。
- ops_agent/simple_dashboard.py：面向非专业人员的极简操作页面。
- ops_agent/fleet.py：节点接入、项目发现、资源快照、离线和版本判断。
- ops_agent/ai/repair.py：代码上下文、补丁、沙箱、审批、PR、部署和回滚。
- ops_agent/remediation：动作白名单、就绪拦截、执行和验证。
- ops_agent/enterprise.py：交付前企业就绪检查。

## 5. 安全原则

- 默认不自动批准生产代码修改。
- DeepSeek、SMTP、MySQL 和 Git 凭据只从环境变量或受限环境文件读取。
- 代码补丁限制仓库根目录，敏感文件和大文件不进入模型上下文。
- 变更命令必须通过白名单；不安全命令在执行前被阻断。
- 节点安装使用 HTTPS，发布包可配置 SHA-256；启动失败自动切回上一版本。
- 最后一个 Owner 不能被停用或降级，用户不能停用自己的当前账号。

## 6. 运维和扩展

- 数据保留策略定时清理过期巡检、测试事件、通知和审计记录。
- 备份支持容量上限、最少保留数和隔离恢复演练。
- required_agent_version 用于识别落后节点，升级仍需管理员确认。
- 新监控器继续输出统一 CheckResult，无需改动事件状态机。
- 新修复动作必须先加入动作白名单、就绪检查、验证和回滚策略。

## 7. 外部依赖边界

系统代码无法自行提供以下客户环境资源：

- HTTPS 域名与证书。
- 客户代码仓库的 Git 推送权限。
- DeepSeek 和通知渠道凭据。
- 位于中心服务器之外的 dead-man heartbeat 服务。

缺少这些条件时，企业就绪检查会明确报告，不允许通过绕开审批或直接改生产代码来降级。
