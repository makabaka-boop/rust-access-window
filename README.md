# rust-access-window

临时访问窗口控制服务，用于管理工程师对测试环境的限时访问申请、审批、激活与撤销。

## 技术栈

- Rust + Tokio 异步运行时
- Axum HTTP 框架
- SQLite（通过 rusqlite，bundled 模式自动编译）
- 端口：**18123**

## 启动命令

```bash
# 编译并运行（debug 模式）
cargo run

# 生产编译后运行
cargo build --release
./target/release/rust-access-window
```

服务启动后监听 `http://0.0.0.0:18123`。

## SQLite 文件位置

数据库文件位于运行目录下：

```
./access_window.db
```

首次启动时自动创建，包含以下表：

| 表名 | 说明 |
|------|------|
| `applications` | 访问申请主表 |
| `access_windows` | 审批通过后生成的访问窗口 |
| `approval_records` | 审批记录（批准/驳回） |
| `activation_records` | 窗口激活记录 |
| `revocation_records` | 窗口撤销记录 |

## 认证与权限

除 `GET /health` 外，所有接口都需要通过 HTTP 头携带身份信息，否则返回 `401 Unauthorized`：

| 请求头 | 必填 | 说明 |
|--------|------|------|
| `X-User` | 是 | 当前操作用户的唯一标识（如邮箱） |
| `X-Role` | 否 | 角色，取值 `user`（默认）、`approver`、`admin` |

权限矩阵：

| 操作 | 允许角色 | 额外约束 |
|------|----------|----------|
| 创建申请 | 任意已认证用户 | body 中 `applicant` 必须与 `X-User` 一致 |
| 提交审批 | 申请人本人 / admin | 只能提交自己的草稿 |
| 批准 / 驳回 | `approver` / `admin` | 审批人取自 `X-User` |
| 激活窗口 | 申请人本人 / admin | 须在时间范围内 |
| 撤销窗口 | `admin` | 撤销人取自 `X-User` |
| 标记过期 | `admin` | — |
| 查询申请 / 历史 / 窗口列表 | 任意已认证用户 | — |

> 操作者身份（approver / activated_by / revoked_by）一律以 `X-User` 头为准，请求体中的同名字段不再生效，防止身份冒充。

## 状态机

申请状态（application status）：

```
draft → submitted → approved → active → expired
                    │           │
                    │           └→ revoked
                    │
                    └→ rejected
```

- `draft`：草稿，已创建但未提交
- `submitted`：已提交，等待审批
- `approved`：审批通过，访问窗口已生成
- `active`：窗口已激活（当前时间落入起止范围）
- `expired`：窗口已过期（当前时间超过结束时间）
- `revoked`：窗口被撤销
- `rejected`：审批被驳回

窗口状态（window status）：`approved` → `active` → `expired` / `revoked`

## API 列表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查（无需认证） |
| POST | `/api/applications` | 创建申请（draft） |
| GET | `/api/applications` | 查询申请列表（可按 status/applicant/resource 过滤） |
| GET | `/api/applications/:id` | 查询单个申请 |
| POST | `/api/applications/:id/submit` | 提交审批 |
| POST | `/api/applications/:id/approve` | 批准申请并生成窗口 |
| POST | `/api/applications/:id/reject` | 驳回申请 |
| POST | `/api/applications/:id/activate` | 激活窗口（需在时间范围内） |
| POST | `/api/applications/:id/revoke` | 撤销窗口 |
| POST | `/api/applications/:id/expire` | 标记过期（当前时间需超过结束时间） |
| GET | `/api/applications/:id/history` | 查询申请完整历史（含审批、激活、撤销记录） |
| GET | `/api/windows?resource=xxx` | 按资源查看当前有效窗口 |

时间格式统一使用 RFC 3339 / ISO 8601 UTC，例如 `2026-08-25T10:00:00Z`。

风险等级：`low`、`medium`、`high`、`critical`。

错误码：`400` 参数校验失败（含非法 status 过滤值）、`401` 未认证、`403` 无权限、`404` 申请/窗口不存在、`409` 非法状态流转或不在时间范围内。

## 完整操作流程示例

以下示例展示从创建申请到撤销窗口的完整生命周期。假设服务运行在 `http://localhost:18123`。

### 1. 创建访问申请（draft）

```bash
curl -s -X POST http://localhost:18123/api/applications \
  -H 'X-User: alice@example.com' \
  -H 'Content-Type: application/json' \
  -d '{
    "applicant": "alice@example.com",
    "target_resource": "test-env-01",
    "reason": "排查支付模块测试环境连接超时问题",
    "start_time": "2026-08-25T10:00:00Z",
    "end_time": "2026-08-25T12:00:00Z",
    "risk_level": "medium"
  }'
```

返回中记录 `"id": 1`，状态为 `draft`。

### 2. 提交审批（submitted）

```bash
curl -s -X POST http://localhost:18123/api/applications/1/submit \
  -H 'X-User: alice@example.com'
```

状态变更为 `submitted`。

### 3. 主管批准申请（approved，生成访问窗口）

```bash
curl -s -X POST http://localhost:18123/api/applications/1/approve \
  -H 'X-User: bob@example.com' \
  -H 'X-Role: approver' \
  -H 'Content-Type: application/json' \
  -d '{
    "comment": "同意，限时两小时"
  }'
```

状态变更为 `approved`，同时在 `access_windows` 表生成一条窗口记录。审批人自动记录为 `bob@example.com`。

### 4. 工程师激活窗口（active）

只有当前时间处于 `start_time` 和 `end_time` 之间时才能激活成功。

```bash
curl -s -X POST http://localhost:18123/api/applications/1/activate \
  -H 'X-User: alice@example.com'
```

状态变更为 `active`。激活人自动记录为 `alice@example.com`。

### 5. 按资源查看当前有效窗口

```bash
curl -s "http://localhost:18123/api/windows?resource=test-env-01" \
  -H 'X-User: alice@example.com'
```

返回所有处于 `active` 且时间范围内的窗口。

### 6. 查询申请完整历史

```bash
curl -s http://localhost:18123/api/applications/1/history \
  -H 'X-User: alice@example.com'
```

返回申请信息、窗口信息，以及全部审批记录、激活记录和撤销记录。

### 7. 撤销窗口（revoked）

安全团队发现异常，可紧急撤销（需要 admin 角色）：

```bash
curl -s -X POST http://localhost:18123/api/applications/1/revoke \
  -H 'X-User: security@example.com' \
  -H 'X-Role: admin' \
  -H 'Content-Type: application/json' \
  -d '{
    "reason": "检测到异常访问行为，紧急撤销"
  }'
```

状态变更为 `revoked`，窗口立即失效。撤销人自动记录为 `security@example.com`。

### 补充：标记过期（expired）

若窗口正常到达结束时间，可由 admin 调用标记过期接口（当前时间需晚于 `end_time`）：

```bash
curl -s -X POST http://localhost:18123/api/applications/1/expire \
  -H 'X-User: security@example.com' \
  -H 'X-Role: admin'
```

状态变更为 `expired`。

### 驳回流程示例

对于不应批准的申请：

```bash
# 创建
APP_ID=$(curl -s -X POST http://localhost:18123/api/applications \
  -H 'X-User: carol@example.com' \
  -H 'Content-Type: application/json' \
  -d '{"applicant":"carol@example.com","target_resource":"prod-db",
       "reason":"直接查生产库","start_time":"2026-08-25T10:00:00Z",
       "end_time":"2026-08-25T18:00:00Z","risk_level":"critical"}' | jq .id)

# 提交
curl -s -X POST http://localhost:18123/api/applications/$APP_ID/submit \
  -H 'X-User: carol@example.com'

# 驳回（需要 approver 角色）
curl -s -X POST http://localhost:18123/api/applications/$APP_ID/reject \
  -H 'X-User: bob@example.com' \
  -H 'X-Role: approver' \
  -H 'Content-Type: application/json' \
  -d '{"comment":"禁止直接访问生产库，请走只读镜像"}'
```

状态变更为 `rejected`，不会生成访问窗口。
