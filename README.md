# rust-access-window

临时访问窗口控制服务。用于管理"某个工程师只能在指定时间段访问某个测试环境"这类需求：
提交访问申请 → 审批 → 生成访问窗口 → 在时间窗口内激活 → 到期或提前撤销，全过程留痕审计。

- HTTP API 基于 [axum](https://github.com/tokio-rs/axum)，监听 **18123** 端口。
- 数据持久化到 **SQLite**，包含申请、访问窗口、审批记录、激活记录、撤销记录五类表。
- 激活受时间校验约束：只有当前时间落入窗口的 `[start_time, end_time]` 区间时才能激活。

## 状态机

申请（application）状态：

```
draft ──submit──> submitted ──approve──> approved ──activate──> active
                      │                      │                     │
                      └──reject──> rejected  ├──revoke──> revoked <─┤
                                             └──expire──> expired <─┘（窗口到期）
```

访问窗口（access_window）状态：`approved → active → (expired | revoked)`，
`approved` 未激活时也可直接 `revoked` 或（超过结束时间后）`expired`。

风险等级 `risk_level`：`low` / `medium` / `high`。

## 启动

需要 Rust 工具链（cargo）。在项目根目录执行：

```bash
# 令牌格式：token:username:role，多个用逗号分隔；role ∈ operator|approver|admin
ACCESS_WINDOW_TOKENS='tok-alice:alice:operator,tok-bob:bob:approver' cargo run --release
```

> **必须**设置 `ACCESS_WINDOW_TOKENS`，否则服务拒绝启动（fail-closed），不会以匿名方式对外提供服务。

启动后监听 `0.0.0.0:18123`。健康检查（无需鉴权）：

```bash
curl http://localhost:18123/health
# {"status":"ok"}
```

日志级别可用环境变量控制，例如 `RUST_LOG=debug cargo run`。

## 鉴权与角色

除 `/health` 外，所有接口都需要携带令牌，二选一：

- `Authorization: Bearer <token>`
- `X-Api-Key: <token>`

**操作人身份（申请人 / 审批人 / 激活人 / 撤销人）一律来自令牌解析出的账号，绝不从请求体读取**，
因此无法冒充他人。角色权限：

| 角色 | 权限 |
| --- | --- |
| `operator` | 创建申请、提交、激活自己名下的窗口 |
| `approver` | 审批（批准/驳回）、撤销、标记过期 |
| `admin` | 允许任意操作 |

额外的归属校验：`submit` 和 `activate` 仅允许该申请的申请人本人（或 `admin`）操作。

鉴权失败返回 `401`（缺少/无效令牌），角色或归属不符返回 `403`。

## SQLite 文件位置

数据库文件为 **`access_window.db`**，位于**进程启动时的当前工作目录**（即项目根目录，
`cargo run` 时就是仓库根）。首次启动会自动建表。WAL 模式下会额外生成
`access_window.db-wal` 和 `access_window.db-shm` 两个附属文件。

审批、激活、撤销等涉及多张表的写入均在**单个 SQLite 事务**中完成，要么全部成功要么全部回滚，
不会出现"审批记录已写入但访问窗口缺失"这类中间态。

## API 一览

所有接口（除 `/health`）都需要令牌。请求体中不再包含 `applicant` / `approver` /
`activated_by` / `revoked_by` 字段（由令牌决定）。

| 方法 & 路径 | 所需角色 | 说明 |
| --- | --- | --- |
| `POST /applications` | 任意登录用户 | 创建申请（申请人=令牌账号，状态 `draft`） |
| `GET  /applications/{id}` | 任意登录用户 | 查询单个申请 |
| `POST /applications/{id}/submit` | 申请人本人 / admin | 提交审批（`draft → submitted`） |
| `POST /applications/{id}/approve` | approver / admin | 批准，生成访问窗口（`submitted → approved`） |
| `POST /applications/{id}/reject` | approver / admin | 驳回（`submitted → rejected`） |
| `GET  /applications/{id}/history` | 任意登录用户 | 查询该申请的完整历史（申请、窗口、审批/激活/撤销记录） |
| `POST /windows/{id}/activate` | 申请人本人 / admin | 激活窗口，需当前时间落入起止范围（`approved → active`） |
| `POST /windows/{id}/revoke` | approver / admin | 撤销窗口（`approved`/`active → revoked`） |
| `POST /windows/{id}/expire` | approver / admin | 标记过期，需已超过结束时间（`approved`/`active → expired`） |
| `GET  /resources/{resource}/active-windows` | 任意登录用户 | 按资源查看当前有效（active 且在有效期内）的窗口，可选 `?at=RFC3339` 指定参考时间 |

时间字段统一使用 **RFC3339**（如 `2026-08-25T09:00:00+00:00`）。

## 从申请到撤销的完整操作流程

以下示例假设服务以 `ACCESS_WINDOW_TOKENS='tok-alice:alice:operator,tok-bob:bob:approver'`
启动，当前时间落入窗口区间，便于演示激活。

```bash
# 1) 创建申请（draft）——申请人由 alice 的令牌决定
curl -X POST http://localhost:18123/applications \
  -H 'Authorization: Bearer tok-alice' \
  -H 'Content-Type: application/json' \
  -d '{
    "target_resource": "test-env-db",
    "reason": "排查线上类似问题",
    "start_time": "2026-08-25T09:00:00+00:00",
    "end_time":   "2026-08-25T12:00:00+00:00",
    "risk_level": "medium"
  }'
# 返回 {"id":1, "applicant":"alice", "status":"draft", ...}

# 2) 提交审批（draft → submitted）——仅申请人本人
curl -X POST http://localhost:18123/applications/1/submit \
  -H 'Authorization: Bearer tok-alice'

# 3) 审批通过，自动生成访问窗口（submitted → approved）——approver 角色
curl -X POST http://localhost:18123/applications/1/approve \
  -H 'Authorization: Bearer tok-bob' \
  -H 'Content-Type: application/json' \
  -d '{"comment": "同意，限时访问"}'
# approver 记录为 bob（来自令牌），返回含新建 window

# 4) 激活窗口（必须当前时间落入 [start,end]，否则 409；仅申请人本人）
curl -X POST http://localhost:18123/windows/1/activate \
  -H 'Authorization: Bearer tok-alice'

# 5) 按资源查看当前有效窗口
curl http://localhost:18123/resources/test-env-db/active-windows \
  -H 'Authorization: Bearer tok-alice'

# 6) 撤销窗口（approved/active → revoked）——approver 角色
curl -X POST http://localhost:18123/windows/1/revoke \
  -H 'Authorization: Bearer tok-bob' \
  -H 'Content-Type: application/json' \
  -d '{"reason": "任务提前完成"}'

# 7) 查看该申请的完整历史（申请 + 窗口 + 审批/激活/撤销记录）
curl http://localhost:18123/applications/1/history \
  -H 'Authorization: Bearer tok-alice'
```

驳回与过期分支：

```bash
# 驳回：submitted → rejected（approver 角色）
curl -X POST http://localhost:18123/applications/{id}/reject \
  -H 'Authorization: Bearer tok-bob' \
  -H 'Content-Type: application/json' \
  -d '{"comment": "风险过高"}'

# 标记过期：窗口结束时间已过后，approved/active → expired（approver 角色）
curl -X POST http://localhost:18123/windows/{id}/expire \
  -H 'Authorization: Bearer tok-bob'
```

## 错误约定

- `400 Bad Request`：参数缺失、时间格式非法、`end_time <= start_time`、风险等级非法。
- `401 Unauthorized`：缺少或无效的令牌。
- `403 Forbidden`：角色不足或非归属人操作（如 operator 尝试审批、他人激活你的窗口）。
- `404 Not Found`：申请或窗口不存在。
- `409 Conflict`：状态机不允许的操作（如非 `draft` 提交、激活时不在时间窗口内等）。
- `500 Internal Server Error`：数据库异常等（如库中存在无法识别的状态值），响应体仍为 JSON，服务不会中断后续请求。

错误响应体统一为 `{"error": "..."}`。

## 项目结构

```
src/
  main.rs     # axum 路由、HTTP 处理器、状态机、时间校验、事务
  auth.rs     # 令牌解析、身份鉴权与角色授权
  db.rs       # SQLite 连接与建表
  models.rs   # 领域模型、状态枚举、请求体定义
```
