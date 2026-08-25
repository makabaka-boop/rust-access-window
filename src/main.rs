use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

type Db = Arc<Mutex<Connection>>;

#[derive(Serialize, Clone)]
struct AccessRequest {
    id: i64,
    applicant: String,
    resource: String,
    reason: String,
    start_time: String,
    end_time: String,
    risk_level: String,
    status: String,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct Window {
    id: i64,
    request_id: i64,
    resource: String,
    start_time: String,
    end_time: String,
    status: String,
    created_at: String,
}

#[derive(Serialize)]
struct Approval {
    id: i64,
    request_id: i64,
    action: String,
    approver: String,
    comment: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct Activation {
    id: i64,
    request_id: i64,
    window_id: i64,
    activated_at: String,
}

#[derive(Serialize)]
struct Submission {
    id: i64,
    request_id: i64,
    submitted_at: String,
}

#[derive(Serialize)]
struct Expiration {
    id: i64,
    request_id: i64,
    window_id: i64,
    expired_at: String,
}

#[derive(Serialize)]
struct Revocation {
    id: i64,
    request_id: i64,
    window_id: i64,
    revoked_by: String,
    reason: Option<String>,
    revoked_at: String,
}

#[derive(Serialize)]
struct History {
    request: AccessRequest,
    window: Option<Window>,
    submissions: Vec<Submission>,
    approvals: Vec<Approval>,
    activations: Vec<Activation>,
    expirations: Vec<Expiration>,
    revocations: Vec<Revocation>,
}

#[derive(Deserialize)]
struct CreateRequest {
    applicant: String,
    resource: String,
    reason: String,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    risk_level: String,
}

#[derive(Deserialize)]
struct ApproveBody {
    approver: String,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct RejectBody {
    approver: String,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct RevokeBody {
    revoked_by: String,
    reason: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn err(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorBody>) {
    (status, Json(ErrorBody { error: msg.to_string() }))
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn init_db(conn: &Connection) {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            applicant TEXT NOT NULL,
            resource TEXT NOT NULL,
            reason TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL UNIQUE,
            resource TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            submitted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS expirations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            window_id INTEGER NOT NULL,
            expired_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            approver TEXT NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            window_id INTEGER NOT NULL,
            activated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS revocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            window_id INTEGER NOT NULL,
            revoked_by TEXT NOT NULL,
            reason TEXT,
            revoked_at TEXT NOT NULL
        );
        ",
    )
    .expect("failed to initialize database");
}

fn get_request(conn: &Connection, id: i64) -> Option<AccessRequest> {
    conn.query_row(
        "SELECT id, applicant, resource, reason, start_time, end_time, risk_level, status, created_at, updated_at FROM requests WHERE id = ?1",
        params![id],
        |r| {
            Ok(AccessRequest {
                id: r.get(0)?,
                applicant: r.get(1)?,
                resource: r.get(2)?,
                reason: r.get(3)?,
                start_time: r.get(4)?,
                end_time: r.get(5)?,
                risk_level: r.get(6)?,
                status: r.get(7)?,
                created_at: r.get(8)?,
                updated_at: r.get(9)?,
            })
        },
    )
    .ok()
}

fn get_window(conn: &Connection, request_id: i64) -> Option<Window> {
    conn.query_row(
        "SELECT id, request_id, resource, start_time, end_time, status, created_at FROM windows WHERE request_id = ?1",
        params![request_id],
        |r| {
            Ok(Window {
                id: r.get(0)?,
                request_id: r.get(1)?,
                resource: r.get(2)?,
                start_time: r.get(3)?,
                end_time: r.get(4)?,
                status: r.get(5)?,
                created_at: r.get(6)?,
            })
        },
    )
    .ok()
}

fn require_non_empty(value: &str, field: &str) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if value.trim().is_empty() {
        Err(err(StatusCode::BAD_REQUEST, &format!("{} must not be empty", field)))
    } else {
        Ok(())
    }
}

async fn create_request(
    State(db): State<Db>,
    Json(body): Json<CreateRequest>,
) -> Result<(StatusCode, Json<AccessRequest>), (StatusCode, Json<ErrorBody>)> {
    require_non_empty(&body.applicant, "applicant")?;
    require_non_empty(&body.resource, "resource")?;
    require_non_empty(&body.reason, "reason")?;
    require_non_empty(&body.risk_level, "risk_level")?;
    if body.end_time <= body.start_time {
        return Err(err(StatusCode::BAD_REQUEST, "end_time must be after start_time"));
    }
    let conn = db.lock().unwrap();
    let ts = now();
    conn.execute(
        "INSERT INTO requests (applicant, resource, reason, start_time, end_time, risk_level, status, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,'draft',?7,?7)",
        params![
            body.applicant,
            body.resource,
            body.reason,
            body.start_time.to_rfc3339(),
            body.end_time.to_rfc3339(),
            body.risk_level,
            ts
        ],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to create request"))?;
    let id = conn.last_insert_rowid();
    Ok((StatusCode::CREATED, Json(get_request(&conn, id).unwrap())))
}

async fn submit_request(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<AccessRequest>, (StatusCode, Json<ErrorBody>)> {
    let mut conn = db.lock().unwrap();
    let req = get_request(&conn, id).ok_or_else(|| err(StatusCode::NOT_FOUND, "request not found"))?;
    if req.status != "draft" {
        return Err(err(StatusCode::CONFLICT, "only draft requests can be submitted"));
    }
    let ts = now();
    let tx = conn.transaction().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "transaction failed"))?;
    tx.execute(
        "INSERT INTO submissions (request_id, submitted_at) VALUES (?1,?2)",
        params![id, ts],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to record submission"))?;
    tx.execute(
        "UPDATE requests SET status = 'submitted', updated_at = ?1 WHERE id = ?2",
        params![ts, id],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update request status"))?;
    tx.commit().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "commit failed"))?;
    Ok(Json(get_request(&conn, id).unwrap()))
}

async fn approve_request(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<AccessRequest>, (StatusCode, Json<ErrorBody>)> {
    require_non_empty(&body.approver, "approver")?;
    let mut conn = db.lock().unwrap();
    let req = get_request(&conn, id).ok_or_else(|| err(StatusCode::NOT_FOUND, "request not found"))?;
    if req.status != "submitted" {
        return Err(err(StatusCode::CONFLICT, "only submitted requests can be approved"));
    }
    let ts = now();
    let tx = conn.transaction().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "transaction failed"))?;
    tx.execute(
        "INSERT INTO approvals (request_id, action, approver, comment, created_at) VALUES (?1,'approved',?2,?3,?4)",
        params![id, body.approver, body.comment, ts],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to record approval"))?;
    tx.execute(
        "INSERT INTO windows (request_id, resource, start_time, end_time, status, created_at) VALUES (?1,?2,?3,?4,'approved',?5)",
        params![id, req.resource, req.start_time, req.end_time, ts],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to create window"))?;
    tx.execute(
        "UPDATE requests SET status = 'approved', updated_at = ?1 WHERE id = ?2",
        params![ts, id],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update request status"))?;
    tx.commit().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "commit failed"))?;
    Ok(Json(get_request(&conn, id).unwrap()))
}

async fn reject_request(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<RejectBody>,
) -> Result<Json<AccessRequest>, (StatusCode, Json<ErrorBody>)> {
    require_non_empty(&body.approver, "approver")?;
    let mut conn = db.lock().unwrap();
    let req = get_request(&conn, id).ok_or_else(|| err(StatusCode::NOT_FOUND, "request not found"))?;
    if req.status != "submitted" {
        return Err(err(StatusCode::CONFLICT, "only submitted requests can be rejected"));
    }
    let ts = now();
    let tx = conn.transaction().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "transaction failed"))?;
    tx.execute(
        "INSERT INTO approvals (request_id, action, approver, comment, created_at) VALUES (?1,'rejected',?2,?3,?4)",
        params![id, body.approver, body.comment, ts],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to record rejection"))?;
    tx.execute(
        "UPDATE requests SET status = 'rejected', updated_at = ?1 WHERE id = ?2",
        params![ts, id],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update request status"))?;
    tx.commit().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "commit failed"))?;
    Ok(Json(get_request(&conn, id).unwrap()))
}

async fn activate_request(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<AccessRequest>, (StatusCode, Json<ErrorBody>)> {
    let mut conn = db.lock().unwrap();
    let req = get_request(&conn, id).ok_or_else(|| err(StatusCode::NOT_FOUND, "request not found"))?;
    if req.status != "approved" {
        return Err(err(StatusCode::CONFLICT, "only approved requests can be activated"));
    }
    let now_utc = Utc::now();
    let start = DateTime::parse_from_rfc3339(&req.start_time).unwrap().with_timezone(&Utc);
    let end = DateTime::parse_from_rfc3339(&req.end_time).unwrap().with_timezone(&Utc);
    if now_utc < start || now_utc > end {
        return Err(err(
            StatusCode::CONFLICT,
            "current time is outside the window range; cannot activate",
        ));
    }
    let window = get_window(&conn, id).unwrap();
    let ts = now();
    let tx = conn.transaction().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "transaction failed"))?;
    tx.execute(
        "INSERT INTO activations (request_id, window_id, activated_at) VALUES (?1,?2,?3)",
        params![id, window.id, ts],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to record activation"))?;
    tx.execute("UPDATE windows SET status = 'active' WHERE request_id = ?1", params![id])
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update window status"))?;
    tx.execute(
        "UPDATE requests SET status = 'active', updated_at = ?1 WHERE id = ?2",
        params![ts, id],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update request status"))?;
    tx.commit().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "commit failed"))?;
    Ok(Json(get_request(&conn, id).unwrap()))
}

async fn revoke_request(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<AccessRequest>, (StatusCode, Json<ErrorBody>)> {
    require_non_empty(&body.revoked_by, "revoked_by")?;
    let mut conn = db.lock().unwrap();
    let req = get_request(&conn, id).ok_or_else(|| err(StatusCode::NOT_FOUND, "request not found"))?;
    if req.status != "active" && req.status != "approved" {
        return Err(err(StatusCode::CONFLICT, "only approved or active windows can be revoked"));
    }
    let window = get_window(&conn, id).unwrap();
    let ts = now();
    let tx = conn.transaction().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "transaction failed"))?;
    tx.execute(
        "INSERT INTO revocations (request_id, window_id, revoked_by, reason, revoked_at) VALUES (?1,?2,?3,?4,?5)",
        params![id, window.id, body.revoked_by, body.reason, ts],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to record revocation"))?;
    tx.execute("UPDATE windows SET status = 'revoked' WHERE request_id = ?1", params![id])
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update window status"))?;
    tx.execute(
        "UPDATE requests SET status = 'revoked', updated_at = ?1 WHERE id = ?2",
        params![ts, id],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update request status"))?;
    tx.commit().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "commit failed"))?;
    Ok(Json(get_request(&conn, id).unwrap()))
}

async fn expire_request(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<AccessRequest>, (StatusCode, Json<ErrorBody>)> {
    let mut conn = db.lock().unwrap();
    let req = get_request(&conn, id).ok_or_else(|| err(StatusCode::NOT_FOUND, "request not found"))?;
    if req.status != "active" && req.status != "approved" {
        return Err(err(StatusCode::CONFLICT, "only approved or active windows can be expired"));
    }
    let end = DateTime::parse_from_rfc3339(&req.end_time).unwrap().with_timezone(&Utc);
    if Utc::now() <= end {
        return Err(err(StatusCode::CONFLICT, "window end_time has not passed yet"));
    }
    let window = get_window(&conn, id).unwrap();
    let ts = now();
    let tx = conn.transaction().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "transaction failed"))?;
    tx.execute(
        "INSERT INTO expirations (request_id, window_id, expired_at) VALUES (?1,?2,?3)",
        params![id, window.id, ts],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to record expiration"))?;
    tx.execute("UPDATE windows SET status = 'expired' WHERE request_id = ?1", params![id])
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update window status"))?;
    tx.execute(
        "UPDATE requests SET status = 'expired', updated_at = ?1 WHERE id = ?2",
        params![ts, id],
    )
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "failed to update request status"))?;
    tx.commit().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "commit failed"))?;
    Ok(Json(get_request(&conn, id).unwrap()))
}

async fn request_history(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<History>, (StatusCode, Json<ErrorBody>)> {
    let conn = db.lock().unwrap();
    let req = get_request(&conn, id).ok_or_else(|| err(StatusCode::NOT_FOUND, "request not found"))?;
    let window = get_window(&conn, id);

    let mut stmt = conn
        .prepare("SELECT id, request_id, submitted_at FROM submissions WHERE request_id = ?1 ORDER BY id")
        .unwrap();
    let submissions = stmt
        .query_map(params![id], |r| {
            Ok(Submission {
                id: r.get(0)?,
                request_id: r.get(1)?,
                submitted_at: r.get(2)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut stmt = conn
        .prepare("SELECT id, request_id, action, approver, comment, created_at FROM approvals WHERE request_id = ?1 ORDER BY id")
        .unwrap();
    let approvals = stmt
        .query_map(params![id], |r| {
            Ok(Approval {
                id: r.get(0)?,
                request_id: r.get(1)?,
                action: r.get(2)?,
                approver: r.get(3)?,
                comment: r.get(4)?,
                created_at: r.get(5)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut stmt = conn
        .prepare("SELECT id, request_id, window_id, activated_at FROM activations WHERE request_id = ?1 ORDER BY id")
        .unwrap();
    let activations = stmt
        .query_map(params![id], |r| {
            Ok(Activation {
                id: r.get(0)?,
                request_id: r.get(1)?,
                window_id: r.get(2)?,
                activated_at: r.get(3)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut stmt = conn
        .prepare("SELECT id, request_id, window_id, expired_at FROM expirations WHERE request_id = ?1 ORDER BY id")
        .unwrap();
    let expirations = stmt
        .query_map(params![id], |r| {
            Ok(Expiration {
                id: r.get(0)?,
                request_id: r.get(1)?,
                window_id: r.get(2)?,
                expired_at: r.get(3)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut stmt = conn
        .prepare("SELECT id, request_id, window_id, revoked_by, reason, revoked_at FROM revocations WHERE request_id = ?1 ORDER BY id")
        .unwrap();
    let revocations = stmt
        .query_map(params![id], |r| {
            Ok(Revocation {
                id: r.get(0)?,
                request_id: r.get(1)?,
                window_id: r.get(2)?,
                revoked_by: r.get(3)?,
                reason: r.get(4)?,
                revoked_at: r.get(5)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    Ok(Json(History { request: req, window, submissions, approvals, activations, expirations, revocations }))
}

async fn active_windows(
    State(db): State<Db>,
    Path(resource): Path<String>,
) -> Result<Json<Vec<Window>>, (StatusCode, Json<ErrorBody>)> {
    let conn = db.lock().unwrap();
    let ts = now();
    let mut stmt = conn
        .prepare(
            "SELECT id, request_id, resource, start_time, end_time, status, created_at FROM windows
             WHERE resource = ?1 AND status = 'active' AND start_time <= ?2 AND end_time >= ?2",
        )
        .unwrap();
    let windows = stmt
        .query_map(params![resource, ts], |r| {
            Ok(Window {
                id: r.get(0)?,
                request_id: r.get(1)?,
                resource: r.get(2)?,
                start_time: r.get(3)?,
                end_time: r.get(4)?,
                status: r.get(5)?,
                created_at: r.get(6)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    Ok(Json(windows))
}

#[tokio::main]
async fn main() {
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "access_window.db".to_string());
    let conn = Connection::open(&db_path).expect("failed to open database");
    init_db(&conn);
    let db: Db = Arc::new(Mutex::new(conn));

    let app = Router::new()
        .route("/requests", post(create_request))
        .route("/requests/:id/submit", post(submit_request))
        .route("/requests/:id/approve", post(approve_request))
        .route("/requests/:id/reject", post(reject_request))
        .route("/requests/:id/activate", post(activate_request))
        .route("/requests/:id/revoke", post(revoke_request))
        .route("/requests/:id/expire", post(expire_request))
        .route("/requests/:id/history", get(request_history))
        .route("/resources/:resource/active-windows", get(active_windows))
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:18123")
        .await
        .expect("failed to bind port 18123");
    println!("listening on http://0.0.0.0:18123, db: {}", db_path);
    axum::serve(listener, app).await.unwrap();
}
