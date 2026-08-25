# rust-access-window

项目介绍：临时访问窗口控制服务，用于管理访问申请、时间窗口、审批、激活和撤销，重点考察 Rust、SQLite、时间校验、状态机和审计记录。

## 启动

```bash
cargo run
```

- 监听端口：`18123`
- SQLite 文件：默认 `./access_window.db`（可用环境变量 `DB_PATH` 覆盖）
- 首次启动自动建表：`requests`、`windows`、`approvals`、`activations`、`revocations`

## 状态机

```
draft → submitted → approved → active → expired / revoked
                  ↘ rejected        ↘ revoked / expired
```

- 激活（activate）仅当当前时间落入窗口起止范围内才允许
- 过期（expire）仅当当前时间超过 end_time 才允许

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/requests` | 创建申请（draft），字段：applicant、resource、reason、start_time、end_time（RFC3339）、risk_level |
| POST | `/requests/:id/submit` | 提交审批（draft → submitted） |
| POST | `/requests/:id/approve` | 批准（→ approved，并生成访问窗口），body：`{"approver":"bob","comment":"ok"}` |
| POST | `/requests/:id/reject` | 驳回（→ rejected），body：`{"approver":"bob","comment":"..."}` |
| POST | `/requests/:id/activate` | 激活窗口（approved → active，校验当前时间在窗口内） |
| POST | `/requests/:id/revoke` | 撤销窗口（approved/active → revoked），body：`{"revoked_by":"admin","reason":"..."}` |
| POST | `/requests/:id/expire` | 标记过期（approved/active → expired，要求 end_time 已过） |
| GET | `/requests/:id/history` | 查询申请完整历史（申请 + 窗口 + 审批/激活/撤销记录） |
| GET | `/resources/:resource/active-windows` | 按资源查询当前有效（active 且在时间范围内）的窗口 |

## 操作流程示例（申请 → 撤销）

```bash
# 1. 创建申请（窗口：过去 1 小时 ~ 未来 2 小时）
curl -X POST localhost:18123/requests -H 'Content-Type: application/json' -d '{
  "applicant": "alice",
  "resource": "test-env-1",
  "reason": "debug issue",
  "start_time": "2026-08-25T11:00:00Z",
  "end_time": "2026-08-25T14:00:00Z",
  "risk_level": "high"
}'

# 2. 提交审批
curl -X POST localhost:18123/requests/1/submit

# 3. 批准（生成访问窗口）
curl -X POST localhost:18123/requests/1/approve -H 'Content-Type: application/json' \
  -d '{"approver":"bob","comment":"ok"}'

# 4. 激活窗口（当前时间必须在窗口范围内）
curl -X POST localhost:18123/requests/1/activate

# 5. 查看该资源当前有效窗口
curl localhost:18123/resources/test-env-1/active-windows

# 6. 撤销窗口
curl -X POST localhost:18123/requests/1/revoke -H 'Content-Type: application/json' \
  -d '{"revoked_by":"admin","reason":"done early"}'

# 7. 查看完整历史
curl localhost:18123/requests/1/history
```
