# rust-access-window

临时访问窗口控制服务：管理工程师对测试环境的临时访问权限。用户提交访问申请（申请人、目标资源、访问原因、起止时间、风险等级），经审批通过后生成访问窗口；窗口只有在当前时间落入起止范围时才能激活，到期可标记过期，也可随时被撤销。所有审批、激活、撤销动作均留审计记录。

- 语言/框架：Rust + tiny_http（HTTP）+ rusqlite/bundled（SQLite）+ chrono（时间校验）
- 监听端口：**18123**
- 存储：SQLite，默认数据库文件为项目运行目录下的 **`data/access_window.db`**（启动时自动创建，可用环境变量 `ACCESS_DB_PATH` 覆盖）

## 启动命令

```bash
# 开发模式运行
cargo run

# 或编译后运行（release）
cargo build --release
./target/release/rust-access-window

# 自定义数据库文件位置
ACCESS_DB_PATH=/var/lib/access-window/access.db cargo run
```

启动后看到如下输出即成功：

```
rust-access-window 服务已启动: http://0.0.0.0:18123
SQLite 数据库文件: data/access_window.db
```

健康检查：`curl http://127.0.0.1:18123/health`

## SQLite 数据表

| 表 | 说明 |
| --- | --- |
| `requests` | 访问申请单（申请人、资源、原因、起止时间、风险等级、状态） |
| `windows` | 审批通过后生成的访问窗口（窗口状态、批准人、激活/撤销/过期时间） |
| `approval_records` | 审批记录（批准 approved / 驳回 rejected，审批人、意见） |
| `activation_records` | 激活记录（激活人、激活时间） |
| `revocation_records` | 撤销记录（撤销人、撤销原因、撤销时间） |
| `history_events` | 申请单完整事件流（created/submitted/approved/rejected/activated/revoked/expired） |

## 状态机

申请单状态：`draft → submitted → approved → active → expired`，其中 `submitted` 可被 `rejected`，`approved/active` 可被 `revoked`。

```
draft ──submit──> submitted ──approve──> approved ──activate(时间在窗口内)──> active ──expire──> expired
                       │                     │                                   │
                       └──reject──> rejected  └─────────────revoke──────────────┴──> revoked
```

关键时间校验：**激活**要求服务器当前时间满足 `start_time <= now <= end_time`，未到开始时间或已过结束时间均返回 409；**标记过期**要求 `now > end_time`。时间字段统一使用 RFC3339（如 `2026-08-25T10:00:00Z`），内部按 UTC 存储比较。

## 并发与一致性保证

每个状态流转（submit/approve/reject/activate/revoke/expire）都在**一个 SQLite IMMEDIATE 事务**里完成，事务内包含：条件状态更新、窗口写入、审计记录写入、历史事件写入，全部成功才提交，任何一步失败整体回滚：

- **不会出现半套数据**：「改了 request 状态但没建窗口 / 没写审批记录 / 没写历史」这类中间态不可能落库——它们要么随事务一起提交，要么随回滚一起消失。
- **不会同时变成 active 和 revoked**：状态更新全部是带前置条件的原子语句，例如 `UPDATE windows SET status='active' WHERE id=? AND status='approved'`、`UPDATE requests SET status='revoked' WHERE id=? AND status IN ('approved','active')`。`BEGIN IMMEDIATE` 立即获取写锁（另设 10 秒 busy_timeout 让并发请求排队而非报错），并发流转串行化；条件更新影响 0 行即说明状态已被别的操作抢先改变，该请求返回 409（`申请/窗口状态已被并发操作改变，请刷新后重试`），request 与 window 状态永远不会分叉。
- **历史记录顺序不会错乱**：状态变更与对应的 history_event 在同一事务中提交，SQLite 写事务天然串行，`history_events` 自增 id 的顺序就是各流转真实的提交顺序；激活/撤销记录与事件严格同生共死。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/requests` | 创建申请（draft） |
| GET | `/requests` | 申请列表 |
| GET | `/requests/{id}` | 申请详情（含窗口、审批/激活/撤销记录） |
| POST | `/requests/{id}/submit` | 提交审批（draft → submitted） |
| POST | `/requests/{id}/approve` | 批准，生成访问窗口（submitted → approved） |
| POST | `/requests/{id}/reject` | 驳回（submitted → rejected） |
| POST | `/requests/{id}/activate` | 激活窗口，需当前时间在窗口内（approved → active） |
| POST | `/requests/{id}/revoke` | 撤销窗口（approved/active → revoked） |
| POST | `/requests/{id}/expire` | 标记过期，需已过结束时间（approved/active → expired） |
| GET | `/requests/{id}/history` | 查询某申请的完整历史事件流 |
| GET | `/resources/{resource}/active-windows` | 按资源查看当前有效（active 且时间在范围内）窗口 |

创建申请请求体：

```json
{
  "applicant": "alice",
  "resource": "test-env-01",
  "reason": "排查线上故障",
  "start_time": "2026-08-25T10:00:00Z",
  "end_time": "2026-08-25T12:00:00Z",
  "risk_level": "high"
}
```

`risk_level` 取值：`low` / `medium` / `high` / `critical`。非法状态流转返回 409，参数错误返回 400，资源不存在返回 404，响应体均为 JSON。

## 完整操作流程：从申请到撤销

下面用一串可直接复制执行的 curl 走完「创建申请 → 提交 → 批准 → 激活 → 查询有效窗口 → 撤销 → 查历史」全流程。时间窗口用 `date` 动态生成（开始于 1 小时前、结束于 2 小时后，保证激活时当前时间落在窗口内）：

```bash
BASE=http://127.0.0.1:18123
START=$(date -u -v-1H +"%Y-%m-%dT%H:%M:%SZ")   # Linux 改为 date -u -d '1 hour ago'
END=$(date -u -v+2H +"%Y-%m-%dT%H:%M:%SZ")     # Linux 改为 date -u -d '2 hours later'

# 1. 工程师 alice 创建访问申请（draft）
curl -s -X POST $BASE/requests -H 'Content-Type: application/json' -d "{
  \"applicant\": \"alice\",
  \"resource\": \"test-env-01\",
  \"reason\": \"排查线上故障\",
  \"start_time\": \"$START\",
  \"end_time\": \"$END\",
  \"risk_level\": \"high\"
}"
# => 返回 {"request": {"id": 1, "status": "draft", ...}}

# 2. 提交审批（draft -> submitted）
curl -s -X POST $BASE/requests/1/submit -H 'Content-Type: application/json' \
  -d '{"actor": "alice"}'

# 3. 审批人 bob 批准（submitted -> approved），同时生成访问窗口
curl -s -X POST $BASE/requests/1/approve -H 'Content-Type: application/json' \
  -d '{"approver": "boss-bob", "comment": "允许在窗口期访问"}'

# 4. 当前时间在 [start, end] 内，激活窗口（approved -> active）
curl -s -X POST $BASE/requests/1/activate -H 'Content-Type: application/json' \
  -d '{"actor": "alice"}'

# 5. 按资源查看当前有效窗口（此时应能看到 test-env-01 上 alice 的窗口）
curl -s $BASE/resources/test-env-01/active-windows

# 6. 安全负责人 carol 提前撤销窗口（active -> revoked）
curl -s -X POST $BASE/requests/1/revoke -H 'Content-Type: application/json' \
  -d '{"revoker": "security-carol", "reason": "故障已恢复，提前收回权限"}'

# 7. 查询该申请的完整历史（created -> submitted -> approved -> activated -> revoked）
curl -s $BASE/requests/1/history
```

补充场景：

```bash
# 窗口已过结束时间且未撤销时，标记过期（approved/active -> expired）
curl -s -X POST $BASE/requests/2/expire -H 'Content-Type: application/json' -d '{}'

# 审批不通过，驳回（submitted -> rejected）
curl -s -X POST $BASE/requests/3/reject -H 'Content-Type: application/json' \
  -d '{"approver": "boss-bob", "comment": "理由不充分"}'
```

也可以直接用 sqlite3 查看落库数据：

```bash
sqlite3 data/access_window.db "SELECT id, applicant, resource, status FROM requests;"
sqlite3 data/access_window.db "SELECT * FROM history_events WHERE request_id = 1;"
```
