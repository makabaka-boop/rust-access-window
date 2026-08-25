mod db;

use chrono::{DateTime, Utc};
use db::{
    Db, ST_ACTIVE, ST_APPROVED, ST_DRAFT, ST_EXPIRED, ST_REJECTED, ST_REVOKED, ST_SUBMITTED,
    VALID_RISK_LEVELS, WIN_APPROVED,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tiny_http::{Header, Method, Request, Response, Server};

const LISTEN_ADDR: &str = "0.0.0.0:18123";

struct ApiErr {
    code: u16,
    msg: String,
}

impl ApiErr {
    fn bad_request(msg: impl Into<String>) -> Self {
        ApiErr {
            code: 400,
            msg: msg.into(),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        ApiErr {
            code: 404,
            msg: msg.into(),
        }
    }
    fn conflict(msg: impl Into<String>) -> Self {
        ApiErr {
            code: 409,
            msg: msg.into(),
        }
    }
    fn internal(msg: impl Into<String>) -> Self {
        ApiErr {
            code: 500,
            msg: msg.into(),
        }
    }
}

impl From<String> for ApiErr {
    fn from(msg: String) -> Self {
        ApiErr::internal(msg)
    }
}

fn now_str() -> String {
    Utc::now().to_rfc3339()
}

fn parse_time(field: &str, raw: &str) -> Result<DateTime<Utc>, ApiErr> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ApiErr::bad_request(format!("{field} 不是合法的 RFC3339 时间: {raw}")))
}

fn required_str<'a>(body: &'a Value, field: &str) -> Result<&'a str, ApiErr> {
    match body.get(field).and_then(Value::as_str) {
        Some(v) if !v.trim().is_empty() => Ok(v),
        _ => Err(ApiErr::bad_request(format!("缺少必填字段: {field}"))),
    }
}

fn optional_str<'a>(body: &'a Value, field: &str) -> Option<&'a str> {
    body.get(field).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn parse_body(req: &mut Request) -> Result<Value, ApiErr> {
    let mut content = String::new();
    req.as_reader()
        .read_to_string(&mut content)
        .map_err(|e| ApiErr::bad_request(format!("读取请求体失败: {e}")))?;
    if content.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&content)
        .map_err(|e| ApiErr::bad_request(format!("请求体不是合法 JSON: {e}")))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn send_response(request: Request, code: u16, value: &Value) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..])
        .expect("合法 header");
    let resp = Response::from_data(body).with_status_code(code).with_header(header);
    if let Err(e) = request.respond(resp) {
        eprintln!("发送响应失败: {e}");
    }
}

fn send_error(request: Request, err: ApiErr) {
    send_response(
        request,
        err.code,
        &json!({ "error": err.msg, "status": err.code }),
    );
}

// ---------- 业务处理 ----------
//
// 所有状态流转都在 db.transact() 的 IMMEDIATE 事务中完成：
//   - 事务内「条件 UPDATE（WHERE status IN ...）+ 写记录 + 写历史事件」一次性提交，
//     中途任何失败整体回滚，不会留下半套数据；
//   - BEGIN IMMEDIATE 立即拿写锁，并发流转串行化，条件 UPDATE 影响 0 行即说明
//     状态已被并发操作改变，返回 409，request 与 window 状态绝不会分叉；
//   - 历史事件与状态变更同一事务提交，按自增 id 排序即真实发生顺序。

fn handle(mut req: Request, db: Arc<Db>) {
    let method = req.method().clone();
    let raw_url = req.url().to_string();
    let path = raw_url.split('?').next().unwrap_or("/").to_string();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let result: Result<(u16, Value), ApiErr> = match (&method, segments.as_slice()) {
        (Method::Get, ["health"]) => Ok((200, json!({ "status": "ok", "service": "rust-access-window" }))),

        // 申请单
        (Method::Post, ["requests"]) => create_request(&mut req, &db),
        (Method::Get, ["requests"]) => list_requests(&db),
        (Method::Get, ["requests", id]) => get_request(id, &db),
        (Method::Post, ["requests", id, "submit"]) => submit_request(id, &mut req, &db),
        (Method::Post, ["requests", id, "approve"]) => approve_request(id, &mut req, &db),
        (Method::Post, ["requests", id, "reject"]) => reject_request(id, &mut req, &db),
        (Method::Post, ["requests", id, "activate"]) => activate_window(id, &mut req, &db),
        (Method::Post, ["requests", id, "revoke"]) => revoke_window(id, &mut req, &db),
        (Method::Post, ["requests", id, "expire"]) => expire_window(id, &mut req, &db),
        (Method::Get, ["requests", id, "history"]) => request_history(id, &db),

        // 按资源查询当前有效窗口
        (Method::Get, ["resources", resource, "active-windows"]) => {
            active_windows(&percent_decode(resource), &db)
        }

        _ => Err(ApiErr::not_found(format!(
            "未找到路由: {} {}",
            method.as_str(),
            path
        ))),
    };

    match result {
        Ok((code, value)) => send_response(req, code, &value),
        Err(err) => send_error(req, err),
    }
}

fn parse_id(id: &str) -> Result<i64, ApiErr> {
    id.parse::<i64>()
        .map_err(|_| ApiErr::bad_request(format!("非法 ID: {id}")))
}

/// 并发冲突时的统一提示
fn conflict_changed() -> ApiErr {
    ApiErr::conflict("申请/窗口状态已被并发操作改变，请刷新后重试")
}

fn create_request(req: &mut Request, db: &Db) -> Result<(u16, Value), ApiErr> {
    let body = parse_body(req)?;
    let applicant = required_str(&body, "applicant")?;
    let resource = required_str(&body, "resource")?;
    let reason = required_str(&body, "reason")?;
    let start_raw = required_str(&body, "start_time")?;
    let end_raw = required_str(&body, "end_time")?;
    let risk = required_str(&body, "risk_level")?.to_lowercase();

    let start = parse_time("start_time", start_raw)?;
    let end = parse_time("end_time", end_raw)?;
    if end <= start {
        return Err(ApiErr::bad_request("end_time 必须晚于 start_time"));
    }
    if !VALID_RISK_LEVELS.contains(&risk.as_str()) {
        return Err(ApiErr::bad_request(format!(
            "risk_level 必须是: {}",
            VALID_RISK_LEVELS.join(", ")
        )));
    }

    db.transact(|conn| {
        let now = now_str();
        let id = db::create_request(conn, applicant, resource, reason, &start, &end, &risk, &now)?;
        db::insert_event(conn, id, "created", Some(applicant), Some("创建访问申请"), &now)?;
        let created = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::internal("申请创建后查询失败"))?;
        Ok((201, json!({ "message": "申请已创建(draft)", "request": created })))
    })
}

fn list_requests(db: &Db) -> Result<(u16, Value), ApiErr> {
    let items = db.read(|conn| db::list_requests(conn))?;
    Ok((200, json!({ "count": items.len(), "requests": items })))
}

fn get_request(id: &str, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    db.read(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        let window = db::get_window_by_request(conn, id)?;
        let approvals = db::approvals_for_request(conn, id)?;
        let activation = db::activation_for_request(conn, id)?;
        let revocation = db::revocation_for_request(conn, id)?;
        Ok((
            200,
            json!({
                "request": request,
                "window": window,
                "approval_records": approvals,
                "activation_record": activation,
                "revocation_record": revocation,
            }),
        ))
    })
}

fn submit_request(id: &str, req: &mut Request, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    let body = parse_body(req)?;
    db.transact(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        if request.status != ST_DRAFT {
            return Err(ApiErr::conflict(format!(
                "只有 draft 状态的申请可以提交审批，当前状态: {}",
                request.status
            )));
        }
        let actor = optional_str(&body, "actor").unwrap_or(&request.applicant);
        let now = now_str();
        if !db::update_request_status(conn, id, ST_SUBMITTED, &[ST_DRAFT], &now)? {
            return Err(conflict_changed());
        }
        db::insert_event(conn, id, "submitted", Some(actor), Some("提交审批"), &now)?;

        let updated = db::get_request(conn, id)?.unwrap();
        Ok((200, json!({ "message": "申请已提交审批(submitted)", "request": updated })))
    })
}

fn approve_request(id: &str, req: &mut Request, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    let body = parse_body(req)?;
    let approver = required_str(&body, "approver")?.to_string();
    let comment = optional_str(&body, "comment").map(str::to_string);
    db.transact(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        if request.status != ST_SUBMITTED {
            return Err(ApiErr::conflict(format!(
                "只有 submitted 状态的申请可以批准，当前状态: {}",
                request.status
            )));
        }
        let now = now_str();
        if !db::update_request_status(conn, id, ST_APPROVED, &[ST_SUBMITTED], &now)? {
            return Err(conflict_changed());
        }
        let window_id = db::create_window(conn, &request, &approver, &now)?;
        db::insert_approval(conn, id, "approved", &approver, comment.as_deref(), &now)?;
        db::insert_event(
            conn,
            id,
            "approved",
            Some(&approver),
            comment.as_deref().or(Some("审批通过，已生成访问窗口")),
            &now,
        )?;

        let updated = db::get_request(conn, id)?.unwrap();
        let window = db::get_window(conn, window_id)?;
        Ok((
            200,
            json!({
                "message": "审批通过(approved)，访问窗口已生成",
                "request": updated,
                "window": window,
                "window_id": window_id,
            }),
        ))
    })
}

fn reject_request(id: &str, req: &mut Request, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    let body = parse_body(req)?;
    let approver = required_str(&body, "approver")?.to_string();
    let comment = optional_str(&body, "comment").map(str::to_string);
    db.transact(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        if request.status != ST_SUBMITTED {
            return Err(ApiErr::conflict(format!(
                "只有 submitted 状态的申请可以驳回，当前状态: {}",
                request.status
            )));
        }
        let now = now_str();
        if !db::update_request_status(conn, id, ST_REJECTED, &[ST_SUBMITTED], &now)? {
            return Err(conflict_changed());
        }
        db::insert_approval(conn, id, "rejected", &approver, comment.as_deref(), &now)?;
        db::insert_event(
            conn,
            id,
            "rejected",
            Some(&approver),
            comment.as_deref().or(Some("审批驳回")),
            &now,
        )?;

        let updated = db::get_request(conn, id)?.unwrap();
        Ok((200, json!({ "message": "申请已驳回(rejected)", "request": updated })))
    })
}

fn activate_window(id: &str, req: &mut Request, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    let body = parse_body(req)?;
    db.transact(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        if request.status != ST_APPROVED {
            return Err(ApiErr::conflict(format!(
                "只有 approved 状态的申请可以激活窗口，当前状态: {}",
                request.status
            )));
        }
        let window = db::get_window_by_request(conn, id)?
            .ok_or_else(|| ApiErr::internal("申请已批准但未找到访问窗口"))?;
        if window.status != WIN_APPROVED {
            return Err(ApiErr::conflict(format!(
                "窗口当前状态为 {}，无法激活",
                window.status
            )));
        }

        // 时间窗口校验：只有当前时间落入 [start, end] 才能激活
        let now = Utc::now();
        let start = parse_time("start_time", &window.start_time)?;
        let end = parse_time("end_time", &window.end_time)?;
        if now < start {
            return Err(ApiErr::conflict(format!(
                "尚未进入访问窗口起止时间（开始于 {}），不能激活",
                window.start_time
            )));
        }
        if now > end {
            return Err(ApiErr::conflict(format!(
                "访问窗口已于 {} 到期，不能激活，请调用 expire 标记过期",
                window.end_time
            )));
        }

        let actor = optional_str(&body, "actor").unwrap_or(&request.applicant);
        let now_s = now.to_rfc3339();
        // 条件更新：窗口仍为 approved 才激活，否则说明并发撤销/过期已抢先
        if !db::activate_window(conn, window.id, &now_s)? {
            return Err(conflict_changed());
        }
        if !db::update_request_status(conn, id, ST_ACTIVE, &[ST_APPROVED], &now_s)? {
            return Err(conflict_changed());
        }
        db::insert_activation(conn, id, window.id, actor, &now_s)?;
        db::insert_event(conn, id, "activated", Some(actor), Some("窗口已激活，访问生效"), &now_s)?;

        let updated = db::get_request(conn, id)?.unwrap();
        let window = db::get_window(conn, window.id)?;
        Ok((200, json!({ "message": "访问窗口已激活(active)", "request": updated, "window": window })))
    })
}

fn revoke_window(id: &str, req: &mut Request, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    let body = parse_body(req)?;
    let revoker = required_str(&body, "revoker")?.to_string();
    let reason = optional_str(&body, "reason").map(str::to_string);
    db.transact(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        if request.status != ST_APPROVED && request.status != ST_ACTIVE {
            return Err(ApiErr::conflict(format!(
                "只有 approved/active 状态的窗口可以撤销，当前状态: {}",
                request.status
            )));
        }
        let window = db::get_window_by_request(conn, id)?
            .ok_or_else(|| ApiErr::internal("未找到访问窗口"))?;
        let now = now_str();
        // 条件更新：窗口仍为 approved/active 才撤销，与激活/过期并发时只有一方成功
        if !db::revoke_window(conn, window.id, &revoker, reason.as_deref(), &now)? {
            return Err(conflict_changed());
        }
        if !db::update_request_status(
            conn,
            id,
            ST_REVOKED,
            &[ST_APPROVED, ST_ACTIVE],
            &now,
        )? {
            return Err(conflict_changed());
        }
        db::insert_revocation(conn, id, window.id, &revoker, reason.as_deref(), &now)?;
        db::insert_event(
            conn,
            id,
            "revoked",
            Some(&revoker),
            reason.as_deref().or(Some("窗口被撤销")),
            &now,
        )?;

        let updated = db::get_request(conn, id)?.unwrap();
        let window = db::get_window(conn, window.id)?;
        Ok((200, json!({ "message": "访问窗口已撤销(revoked)", "request": updated, "window": window })))
    })
}

fn expire_window(id: &str, req: &mut Request, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    let body = parse_body(req)?;
    db.transact(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        if request.status != ST_APPROVED && request.status != ST_ACTIVE {
            return Err(ApiErr::conflict(format!(
                "只有 approved/active 状态的窗口可以标记过期，当前状态: {}",
                request.status
            )));
        }
        let window = db::get_window_by_request(conn, id)?
            .ok_or_else(|| ApiErr::internal("未找到访问窗口"))?;

        let now = Utc::now();
        let end = parse_time("end_time", &window.end_time)?;
        if now <= end {
            return Err(ApiErr::conflict(format!(
                "窗口尚未到结束时间（结束于 {}），不能标记过期",
                window.end_time
            )));
        }

        let actor = optional_str(&body, "actor").unwrap_or("system");
        let now_s = now.to_rfc3339();
        if !db::expire_window(conn, window.id, &now_s)? {
            return Err(conflict_changed());
        }
        if !db::update_request_status(
            conn,
            id,
            ST_EXPIRED,
            &[ST_APPROVED, ST_ACTIVE],
            &now_s,
        )? {
            return Err(conflict_changed());
        }
        db::insert_event(
            conn,
            id,
            "expired",
            Some(actor),
            Some("窗口到达结束时间，标记过期"),
            &now_s,
        )?;

        let updated = db::get_request(conn, id)?.unwrap();
        let window = db::get_window(conn, window.id)?;
        Ok((200, json!({ "message": "访问窗口已过期(expired)", "request": updated, "window": window })))
    })
}

fn request_history(id: &str, db: &Db) -> Result<(u16, Value), ApiErr> {
    let id = parse_id(id)?;
    db.read(|conn| {
        let request = db::get_request(conn, id)?
            .ok_or_else(|| ApiErr::not_found(format!("申请 {id} 不存在")))?;
        let events = db::history(conn, id)?;
        let window = db::get_window_by_request(conn, id)?;
        Ok((
            200,
            json!({
                "request": request,
                "window": window,
                "event_count": events.len(),
                "events": events,
            }),
        ))
    })
}

fn active_windows(resource: &str, db: &Db) -> Result<(u16, Value), ApiErr> {
    let now = now_str();
    let windows = db.read(|conn| db::active_windows_for_resource(conn, resource, &now))?;
    Ok((200, json!({
        "resource": resource,
        "now": now,
        "count": windows.len(),
        "windows": windows,
    })))
}

fn main() {
    let db_path =
        std::env::var("ACCESS_DB_PATH").unwrap_or_else(|_| "data/access_window.db".to_string());
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).expect("创建数据库目录失败");
        }
    }
    let db = Arc::new(Db::open(&db_path).expect("初始化数据库失败"));

    let server = Server::http(LISTEN_ADDR).expect("监听 18123 端口失败");
    println!("rust-access-window 服务已启动: http://{LISTEN_ADDR}");
    println!("SQLite 数据库文件: {db_path}");

    for request in server.incoming_requests() {
        let db = Arc::clone(&db);
        std::thread::spawn(move || handle(request, db));
    }
}
