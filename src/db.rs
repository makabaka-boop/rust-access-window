use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;

// ---------- 状态常量 ----------

// 申请单状态：draft -> submitted -> approved -> active -> expired
//                     |            |           \-> revoked
//                     +-> rejected <-----------/
pub const ST_DRAFT: &str = "draft";
pub const ST_SUBMITTED: &str = "submitted";
pub const ST_APPROVED: &str = "approved";
pub const ST_ACTIVE: &str = "active";
pub const ST_EXPIRED: &str = "expired";
pub const ST_REVOKED: &str = "revoked";
pub const ST_REJECTED: &str = "rejected";

// 窗口状态
pub const WIN_APPROVED: &str = "approved";
pub const WIN_ACTIVE: &str = "active";
pub const WIN_EXPIRED: &str = "expired";
pub const WIN_REVOKED: &str = "revoked";

pub const VALID_RISK_LEVELS: [&str; 4] = ["low", "medium", "high", "critical"];

// ---------- 数据模型 ----------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessRequest {
    pub id: i64,
    pub applicant: String,
    pub resource: String,
    pub reason: String,
    pub start_time: String,
    pub end_time: String,
    pub risk_level: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AccessWindow {
    pub id: i64,
    pub request_id: i64,
    pub applicant: String,
    pub resource: String,
    pub start_time: String,
    pub end_time: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApprovalRecord {
    pub id: i64,
    pub request_id: i64,
    pub action: String, // approved | rejected
    pub approver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ActivationRecord {
    pub id: i64,
    pub request_id: i64,
    pub window_id: i64,
    pub activated_by: String,
    pub activated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RevocationRecord {
    pub id: i64,
    pub request_id: i64,
    pub window_id: i64,
    pub revoked_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub revoked_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HistoryEvent {
    pub id: i64,
    pub request_id: i64,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub created_at: String,
}

// ---------- 数据库 ----------

/// 所有状态流转都必须在 `transact` 提供的 IMMEDIATE 事务中完成：
/// 1. 事务一次性提交，中途任何失败都会整体回滚，不会留下半套数据；
/// 2. BEGIN IMMEDIATE 立即获取写锁，配合条件 UPDATE（WHERE status IN ...），
///    并发流转只有一个能成功，其余返回冲突，request 与 window 状态不会分叉；
/// 3. 同一事务内的状态变更与历史事件一起提交，SQLite 写操作天然串行，
///    history_events 自增 id 的顺序即真实提交顺序，不会错乱。
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &str) -> Result<Db, String> {
        let conn = Connection::open(path).map_err(|e| format!("打开数据库失败: {e}"))?;
        // 并发写事务排队等待，而不是立刻报 database is locked
        conn.busy_timeout(Duration::from_secs(10))
            .map_err(|e| format!("设置 busy_timeout 失败: {e}"))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS requests (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                applicant   TEXT    NOT NULL,
                resource    TEXT    NOT NULL,
                reason      TEXT    NOT NULL,
                start_time  TEXT    NOT NULL,   -- RFC3339 UTC
                end_time    TEXT    NOT NULL,   -- RFC3339 UTC
                risk_level  TEXT    NOT NULL,
                status      TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                updated_at  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS windows (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id    INTEGER NOT NULL REFERENCES requests(id),
                applicant     TEXT    NOT NULL,
                resource      TEXT    NOT NULL,
                start_time    TEXT    NOT NULL,
                end_time      TEXT    NOT NULL,
                status        TEXT    NOT NULL,  -- approved | active | expired | revoked
                approved_by   TEXT,
                activated_at  TEXT,
                revoked_at    TEXT,
                revoked_by    TEXT,
                revoke_reason TEXT,
                expired_at    TEXT,
                created_at    TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_records (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id  INTEGER NOT NULL REFERENCES requests(id),
                action      TEXT    NOT NULL,   -- approved | rejected
                approver    TEXT    NOT NULL,
                comment     TEXT,
                created_at  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activation_records (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id   INTEGER NOT NULL REFERENCES requests(id),
                window_id    INTEGER NOT NULL REFERENCES windows(id),
                activated_by TEXT    NOT NULL,
                activated_at TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revocation_records (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id  INTEGER NOT NULL REFERENCES requests(id),
                window_id   INTEGER NOT NULL REFERENCES windows(id),
                revoked_by  TEXT    NOT NULL,
                reason      TEXT,
                revoked_at  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS history_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id  INTEGER NOT NULL REFERENCES requests(id),
                event_type  TEXT    NOT NULL,
                actor       TEXT,
                detail      TEXT,
                created_at  TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_windows_resource ON windows(resource);
            CREATE INDEX IF NOT EXISTS idx_windows_request ON windows(request_id);
            CREATE INDEX IF NOT EXISTS idx_events_request ON history_events(request_id);
            "#,
        )
        .map_err(|e| format!("初始化数据库失败: {e}"))?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    /// 只读操作：加锁后在一个连接上执行。
    pub fn read<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Connection) -> Result<T, E>,
        E: From<String>,
    {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }

    /// 写操作：在一个 IMMEDIATE 事务中执行闭包，全部成功才提交，
    /// 闭包返回 Err 或中途出错则整体回滚。
    pub fn transact<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Connection) -> Result<T, E>,
        E: From<String>,
    {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| E::from(format!("开启事务失败: {e}")))?;
        match f(&tx) {
            Ok(v) => tx
                .commit()
                .map(|_| v)
                .map_err(|e| E::from(format!("提交事务失败: {e}"))),
            Err(e) => {
                let _ = tx.rollback();
                Err(e)
            }
        }
    }
}

// ---------- 申请单 ----------

pub fn create_request(
    conn: &Connection,
    applicant: &str,
    resource: &str,
    reason: &str,
    start: &DateTime<Utc>,
    end: &DateTime<Utc>,
    risk: &str,
    now: &str,
) -> Result<i64, String> {
    conn.execute(
        "INSERT INTO requests (applicant, resource, reason, start_time, end_time, risk_level, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            applicant,
            resource,
            reason,
            start.to_rfc3339(),
            end.to_rfc3339(),
            risk,
            ST_DRAFT,
            now
        ],
    )
    .map_err(|e| format!("插入申请失败: {e}"))?;
    Ok(conn.last_insert_rowid())
}

pub fn get_request(conn: &Connection, id: i64) -> Result<Option<AccessRequest>, String> {
    conn.query_row(
        "SELECT id, applicant, resource, reason, start_time, end_time, risk_level, status, created_at, updated_at
         FROM requests WHERE id = ?1",
        params![id],
        row_to_request,
    )
    .optional()
    .map_err(|e| format!("查询申请失败: {e}"))
}

pub fn list_requests(conn: &Connection) -> Result<Vec<AccessRequest>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, applicant, resource, reason, start_time, end_time, risk_level, status, created_at, updated_at
             FROM requests ORDER BY id DESC",
        )
        .map_err(|e| format!("查询申请列表失败: {e}"))?;
    let rows = stmt
        .query_map([], row_to_request)
        .map_err(|e| format!("查询申请列表失败: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| format!("读取申请行失败: {e}"))?);
    }
    Ok(out)
}

/// 条件更新申请状态：只有当前状态在 allowed 列表中才更新。
/// 返回 false 说明状态已被并发操作改变，调用方应回滚并返回冲突。
pub fn update_request_status(
    conn: &Connection,
    id: i64,
    new_status: &str,
    allowed: &[&str],
    now: &str,
) -> Result<bool, String> {
    let placeholders = allowed.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "UPDATE requests SET status = ?, updated_at = ? WHERE id = ? AND status IN ({placeholders})"
    );
    let mut args: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(3 + allowed.len());
    args.push(&new_status);
    args.push(&now);
    args.push(&id);
    for s in allowed {
        args.push(s);
    }
    let n = conn
        .execute(&sql, args.as_slice())
        .map_err(|e| format!("更新申请状态失败: {e}"))?;
    Ok(n > 0)
}

// ---------- 访问窗口 ----------

pub fn create_window(
    conn: &Connection,
    req: &AccessRequest,
    approver: &str,
    now: &str,
) -> Result<i64, String> {
    conn.execute(
        "INSERT INTO windows (request_id, applicant, resource, start_time, end_time, status, approved_by, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            req.id,
            req.applicant,
            req.resource,
            req.start_time,
            req.end_time,
            WIN_APPROVED,
            approver,
            now
        ],
    )
    .map_err(|e| format!("创建访问窗口失败: {e}"))?;
    Ok(conn.last_insert_rowid())
}

pub fn get_window_by_request(conn: &Connection, request_id: i64) -> Result<Option<AccessWindow>, String> {
    conn.query_row(
        "SELECT id, request_id, applicant, resource, start_time, end_time, status,
                approved_by, activated_at, revoked_at, revoked_by, revoke_reason, expired_at, created_at
         FROM windows WHERE request_id = ?1",
        params![request_id],
        row_to_window,
    )
    .optional()
    .map_err(|e| format!("查询窗口失败: {e}"))
}

pub fn get_window(conn: &Connection, window_id: i64) -> Result<Option<AccessWindow>, String> {
    conn.query_row(
        "SELECT id, request_id, applicant, resource, start_time, end_time, status,
                approved_by, activated_at, revoked_at, revoked_by, revoke_reason, expired_at, created_at
         FROM windows WHERE id = ?1",
        params![window_id],
        row_to_window,
    )
    .optional()
    .map_err(|e| format!("查询窗口失败: {e}"))
}

/// 激活窗口：仅当窗口仍处于 approved 时生效（原子条件更新）。
pub fn activate_window(conn: &Connection, window_id: i64, now: &str) -> Result<bool, String> {
    let n = conn
        .execute(
            "UPDATE windows SET status = ?1, activated_at = ?2
             WHERE id = ?3 AND status = ?4",
            params![WIN_ACTIVE, now, window_id, WIN_APPROVED],
        )
        .map_err(|e| format!("激活窗口失败: {e}"))?;
    Ok(n > 0)
}

/// 撤销窗口：仅当窗口处于 approved/active 时生效（原子条件更新）。
pub fn revoke_window(
    conn: &Connection,
    window_id: i64,
    revoker: &str,
    reason: Option<&str>,
    now: &str,
) -> Result<bool, String> {
    let n = conn
        .execute(
            "UPDATE windows SET status = ?1, revoked_at = ?2, revoked_by = ?3, revoke_reason = ?4
             WHERE id = ?5 AND status IN (?6, ?7)",
            params![WIN_REVOKED, now, revoker, reason, window_id, WIN_APPROVED, WIN_ACTIVE],
        )
        .map_err(|e| format!("撤销窗口失败: {e}"))?;
    Ok(n > 0)
}

/// 标记窗口过期：仅当窗口处于 approved/active 时生效（原子条件更新）。
pub fn expire_window(conn: &Connection, window_id: i64, now: &str) -> Result<bool, String> {
    let n = conn
        .execute(
            "UPDATE windows SET status = ?1, expired_at = ?2
             WHERE id = ?3 AND status IN (?4, ?5)",
            params![WIN_EXPIRED, now, window_id, WIN_APPROVED, WIN_ACTIVE],
        )
        .map_err(|e| format!("标记窗口过期失败: {e}"))?;
    Ok(n > 0)
}

/// 按资源查询当前有效窗口：状态为 active 且当前时间落在起止范围内
pub fn active_windows_for_resource(
    conn: &Connection,
    resource: &str,
    now: &str,
) -> Result<Vec<AccessWindow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, request_id, applicant, resource, start_time, end_time, status,
                    approved_by, activated_at, revoked_at, revoked_by, revoke_reason, expired_at, created_at
             FROM windows
             WHERE resource = ?1 AND status = ?2 AND start_time <= ?3 AND end_time >= ?3
             ORDER BY start_time ASC",
        )
        .map_err(|e| format!("查询有效窗口失败: {e}"))?;
    let rows = stmt
        .query_map(params![resource, WIN_ACTIVE, now], row_to_window)
        .map_err(|e| format!("查询有效窗口失败: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| format!("读取窗口行失败: {e}"))?);
    }
    Ok(out)
}

// ---------- 审批 / 激活 / 撤销记录 ----------

pub fn insert_approval(
    conn: &Connection,
    request_id: i64,
    action: &str,
    approver: &str,
    comment: Option<&str>,
    now: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO approval_records (request_id, action, approver, comment, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![request_id, action, approver, comment, now],
    )
    .map_err(|e| format!("写入审批记录失败: {e}"))?;
    Ok(())
}

pub fn insert_activation(
    conn: &Connection,
    request_id: i64,
    window_id: i64,
    actor: &str,
    now: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO activation_records (request_id, window_id, activated_by, activated_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![request_id, window_id, actor, now],
    )
    .map_err(|e| format!("写入激活记录失败: {e}"))?;
    Ok(())
}

pub fn insert_revocation(
    conn: &Connection,
    request_id: i64,
    window_id: i64,
    revoker: &str,
    reason: Option<&str>,
    now: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO revocation_records (request_id, window_id, revoked_by, reason, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![request_id, window_id, revoker, reason, now],
    )
    .map_err(|e| format!("写入撤销记录失败: {e}"))?;
    Ok(())
}

// ---------- 历史事件 ----------

pub fn insert_event(
    conn: &Connection,
    request_id: i64,
    event_type: &str,
    actor: Option<&str>,
    detail: Option<&str>,
    now: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO history_events (request_id, event_type, actor, detail, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![request_id, event_type, actor, detail, now],
    )
    .map_err(|e| format!("写入历史事件失败: {e}"))?;
    Ok(())
}

pub fn history(conn: &Connection, request_id: i64) -> Result<Vec<HistoryEvent>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, request_id, event_type, actor, detail, created_at
             FROM history_events WHERE request_id = ?1 ORDER BY id ASC",
        )
        .map_err(|e| format!("查询历史失败: {e}"))?;
    let rows = stmt
        .query_map(params![request_id], |row| {
            Ok(HistoryEvent {
                id: row.get(0)?,
                request_id: row.get(1)?,
                event_type: row.get(2)?,
                actor: row.get(3)?,
                detail: row.get(4)?,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| format!("查询历史失败: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| format!("读取历史行失败: {e}"))?);
    }
    Ok(out)
}

pub fn approvals_for_request(conn: &Connection, request_id: i64) -> Result<Vec<ApprovalRecord>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, request_id, action, approver, comment, created_at
             FROM approval_records WHERE request_id = ?1 ORDER BY id ASC",
        )
        .map_err(|e| format!("查询审批记录失败: {e}"))?;
    let rows = stmt
        .query_map(params![request_id], |row| {
            Ok(ApprovalRecord {
                id: row.get(0)?,
                request_id: row.get(1)?,
                action: row.get(2)?,
                approver: row.get(3)?,
                comment: row.get(4)?,
                created_at: row.get(5)?,
            })
        })
        .map_err(|e| format!("查询审批记录失败: {e}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| format!("读取审批记录失败: {e}"))?);
    }
    Ok(out)
}

pub fn activation_for_request(conn: &Connection, request_id: i64) -> Result<Option<ActivationRecord>, String> {
    conn.query_row(
        "SELECT id, request_id, window_id, activated_by, activated_at
         FROM activation_records WHERE request_id = ?1 ORDER BY id DESC LIMIT 1",
        params![request_id],
        |row| {
            Ok(ActivationRecord {
                id: row.get(0)?,
                request_id: row.get(1)?,
                window_id: row.get(2)?,
                activated_by: row.get(3)?,
                activated_at: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(|e| format!("查询激活记录失败: {e}"))
}

pub fn revocation_for_request(conn: &Connection, request_id: i64) -> Result<Option<RevocationRecord>, String> {
    conn.query_row(
        "SELECT id, request_id, window_id, revoked_by, reason, revoked_at
         FROM revocation_records WHERE request_id = ?1 ORDER BY id DESC LIMIT 1",
        params![request_id],
        |row| {
            Ok(RevocationRecord {
                id: row.get(0)?,
                request_id: row.get(1)?,
                window_id: row.get(2)?,
                revoked_by: row.get(3)?,
                reason: row.get(4)?,
                revoked_at: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(|e| format!("查询撤销记录失败: {e}"))
}

fn row_to_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccessRequest> {
    Ok(AccessRequest {
        id: row.get(0)?,
        applicant: row.get(1)?,
        resource: row.get(2)?,
        reason: row.get(3)?,
        start_time: row.get(4)?,
        end_time: row.get(5)?,
        risk_level: row.get(6)?,
        status: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn row_to_window(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccessWindow> {
    Ok(AccessWindow {
        id: row.get(0)?,
        request_id: row.get(1)?,
        applicant: row.get(2)?,
        resource: row.get(3)?,
        start_time: row.get(4)?,
        end_time: row.get(5)?,
        status: row.get(6)?,
        approved_by: row.get(7)?,
        activated_at: row.get(8)?,
        revoked_at: row.get(9)?,
        revoked_by: row.get(10)?,
        revoke_reason: row.get(11)?,
        expired_at: row.get(12)?,
        created_at: row.get(13)?,
    })
}
