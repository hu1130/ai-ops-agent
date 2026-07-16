# 统一运维入口 API

这组接口把事件诊断、处置建议、审批执行、AI 修复和验证结果合并为一个简单工作流。调用方不需要理解底层模块，只需要展示系统给出的唯一 `primary_action`。

## 1. 运维待办箱

```text
GET /api/operator/inbox?limit=50
```

返回所有未恢复、未关闭且不是误报的事件，并按“需要人工、可以处理、系统等待”排序。

每个待办包含：

- `headline`: 人话结论
- `business_impact`: 对用户或业务的影响
- `what_system_did`: 系统已经完成的工作
- `primary_action`: 当前唯一推荐动作
- `progress`: 发现、诊断、方案、执行、验证、恢复六步进度
- `blockers`: 阻止自动处理的安全条件

## 2. 单个事件操作指引

```text
GET /api/incidents/{incident_id}/operator-guide
```

`primary_action` 中的重要字段：

- `label`: 直接展示给用户的按钮文字
- `reason`: 为什么推荐这一步
- `changes_system`: 是否可能修改系统状态或代码
- `requires_confirmation`: 是否需要用户确认
- `executable`: 当前是否可以执行
- `path`: 统一执行地址

## 3. 执行唯一推荐动作

```text
POST /api/incidents/{incident_id}/operator-action
Authorization: Bearer <operator-token>
Content-Type: application/json

{
  "note": "负责人确认执行"
}
```

接口会重新计算当前推荐动作，避免执行过期决定，然后调用已有的诊断、白名单策略、审批、AI 修复、验证和审计模块。

结果状态：

- `completed`: 本步完成，读取 `after.primary_action` 获取下一步
- `waiting`: 已确认收到，系统继续自动复测
- `needs_manual`: 安全条件不足或动作失败，系统已停止重试并转人工

## 4. 安全约束

- 写操作必须使用 `operator` 或 `admin` 角色令牌。
- 每次执行前都会重新检查策略白名单和 readiness 条件。
- 修改类动作仍然必须满足人工确认和执行后验证。
- 失败动作不会在统一入口中无限重试。
- 每次统一入口操作都会写入 API 审计、事件评论和事件时间线。
