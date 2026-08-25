mod auth;
mod db;
mod models;

use std::sync::{Arc, Mutex, MutexGuard};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;

use auth::{Principal, Role, TokenRegistry};
use models::*;

/// Shared application state: the SQLite connection plus the token registry.
#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    tokens: TokenRegistry,
}

const DB_PATH: &str = "access_window.db";
const LISTEN_ADDR: &str = "0.0.0.0:18123";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_access_window=info,tower_http=info".into()),
        )
        .init();

    // Fail closed: without a valid credential set we refuse to start rather than
    // accept anonymous callers.
    let tokens = match auth::load_tokens_from_env() {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "startup aborted: {e}\n\
                 set ACCESS_WINDOW_TOKENS='token:username:role[,...]' \
                 (roles: operator, approver, admin)"
            );
            std::process::exit(1);
        }
    };

    let conn = db::open(DB_PATH).expect("failed to open SQLite database");
    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        tokens,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/applications", post(create_application))
        .route("/applications/{id}", get(get_application))
        .route("/applications/{id}/submit", post(submit_application))
        .route("/applications/{id}/approve", post(approve_application))
        .route("/applications/{id}/reject", post(reject_application))
        .route("/applications/{id}/history", get(application_history))
        .route("/windows/{id}/activate", post(activate_window))
        .route("/windows/{id}/revoke", post(revoke_window))
        .route("/windows/{id}/expire", post(expire_window))
        .route("/resources/{resource}/active-windows", get(active_windows_by_resource))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR)
        .await
        .expect("failed to bind listener");
    tracing::info!("access-window service listening on {LISTEN_ADDR}, db at {DB_PATH}");
    axum::serve(listener, app).await.unwrap();
}

// ----- Error handling -----

/// API error carrying an HTTP status and a message.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        ApiError {
            status,
            message: msg.into(),
        }
    }
    fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, msg)
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}"))
    }
}

impl From<(StatusCode, String)> for ApiError {
    fn from((status, message): (StatusCode, String)) -> Self {
        ApiError { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// Lock the shared connection, recovering from a poisoned mutex instead of
/// panicking. A prior panic while holding the lock would otherwise poison it and
/// make every subsequent request abort with an empty response.
fn lock_db(db: &Arc<Mutex<Connection>>) -> MutexGuard<'_, Connection> {
    db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Parse a stored application status, mapping an unexpected value to a 500 with
/// a clear message rather than panicking (which resets the connection).
fn parse_app_status(raw: &str) -> ApiResult<AppStatus> {
    AppStatus::parse(raw).ok_or_else(|| {
        ApiError::internal(format!("stored application status '{raw}' is not recognized"))
    })
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn parse_time(s: &str, field: &str) -> ApiResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ApiError::bad_request(format!("{field} must be RFC3339 datetime, got '{s}'")))
}

// ----- Handlers -----

/// Authenticate the caller from request headers using the token registry.
fn authenticate(state: &AppState, headers: &HeaderMap) -> ApiResult<Principal> {
    auth::authenticate(headers, &state.tokens).map_err(ApiError::from)
}

/// Authenticate and require one of the given roles.
fn authorize(state: &AppState, headers: &HeaderMap, allowed: &[Role]) -> ApiResult<Principal> {
    let principal = authenticate(state, headers)?;
    auth::require_role(&principal, allowed).map_err(ApiError::from)?;
    Ok(principal)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn create_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateApplicationReq>,
) -> ApiResult<impl IntoResponse> {
    // Any authenticated user may file a request; the applicant is the caller.
    let principal = authenticate(&state, &headers)?;

    // Validate inputs.
    if req.target_resource.trim().is_empty() {
        return Err(ApiError::bad_request("target_resource is required"));
    }
    if req.reason.trim().is_empty() {
        return Err(ApiError::bad_request("reason is required"));
    }
    let risk = req.risk_level.to_lowercase();
    if !matches!(risk.as_str(), "low" | "medium" | "high") {
        return Err(ApiError::bad_request("risk_level must be one of: low, medium, high"));
    }
    let start = parse_time(&req.start_time, "start_time")?;
    let end = parse_time(&req.end_time, "end_time")?;
    if end <= start {
        return Err(ApiError::bad_request("end_time must be after start_time"));
    }

    let now = now_rfc3339();
    let conn = lock_db(&state.db);
    conn.execute(
        "INSERT INTO applications
         (applicant, target_resource, reason, start_time, end_time, risk_level, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'draft', ?7, ?7)",
        rusqlite::params![
            principal.username,
            req.target_resource.trim(),
            req.reason.trim(),
            start.to_rfc3339(),
            end.to_rfc3339(),
            risk,
            now,
        ],
    )?;
    let id = conn.last_insert_rowid();
    let app = load_application(&conn, id)?;
    Ok((StatusCode::CREATED, Json(app)))
}

async fn get_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
    authenticate(&state, &headers)?;
    let conn = lock_db(&state.db);
    let app = load_application(&conn, id)?;
    Ok(Json(app))
}

async fn submit_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
    let principal = authenticate(&state, &headers)?;
    let conn = lock_db(&state.db);
    let app = load_application(&conn, id)?;
    // Only the applicant (or an admin) may submit their own draft.
    if principal.role != Role::Admin && app.applicant != principal.username {
        return Err(ApiError::from((
            StatusCode::FORBIDDEN,
            "only the applicant may submit this application".to_string(),
        )));
    }
    let status = parse_app_status(&app.status)?;
    if status != AppStatus::Draft {
        return Err(ApiError::conflict(format!(
            "only draft applications can be submitted (current: {})",
            app.status
        )));
    }
    let now = now_rfc3339();
    conn.execute(
        "UPDATE applications SET status = 'submitted', updated_at = ?2 WHERE id = ?1",
        rusqlite::params![id, now],
    )?;
    let app = load_application(&conn, id)?;
    Ok(Json(app))
}

async fn approve_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<ApproveReq>,
) -> ApiResult<impl IntoResponse> {
    let principal = authorize(&state, &headers, &[Role::Approver])?;
    let mut conn = lock_db(&state.db);
    let app = load_application(&conn, id)?;
    let status = parse_app_status(&app.status)?;
    if status != AppStatus::Submitted {
        return Err(ApiError::conflict(format!(
            "only submitted applications can be approved (current: {})",
            app.status
        )));
    }
    let now = now_rfc3339();

    // Approval must be atomic: the approval record, the status change and the
    // generated window either all persist together or not at all.
    let tx = conn.transaction()?;
    // Record the approval decision.
    tx.execute(
        "INSERT INTO approval_records (application_id, decision, approver, comment, created_at)
         VALUES (?1, 'approved', ?2, ?3, ?4)",
        rusqlite::params![id, principal.username, req.comment, now],
    )?;
    // Move application to approved.
    tx.execute(
        "UPDATE applications SET status = 'approved', updated_at = ?2 WHERE id = ?1",
        rusqlite::params![id, now],
    )?;
    // Generate the access window mirroring the application's time range.
    tx.execute(
        "INSERT INTO access_windows
         (application_id, target_resource, start_time, end_time, status, created_at)
         VALUES (?1, ?2, ?3, ?4, 'approved', ?5)",
        rusqlite::params![id, app.target_resource, app.start_time, app.end_time, now],
    )?;
    let window_id = tx.last_insert_rowid();
    tx.commit()?;

    let app = load_application(&conn, id)?;
    let window = load_window(&conn, window_id)?;
    Ok((StatusCode::CREATED, Json(json!({ "application": app, "window": window }))))
}

async fn reject_application(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<RejectReq>,
) -> ApiResult<impl IntoResponse> {
    let principal = authorize(&state, &headers, &[Role::Approver])?;
    let mut conn = lock_db(&state.db);
    let app = load_application(&conn, id)?;
    let status = parse_app_status(&app.status)?;
    if status != AppStatus::Submitted {
        return Err(ApiError::conflict(format!(
            "only submitted applications can be rejected (current: {})",
            app.status
        )));
    }
    let now = now_rfc3339();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO approval_records (application_id, decision, approver, comment, created_at)
         VALUES (?1, 'rejected', ?2, ?3, ?4)",
        rusqlite::params![id, principal.username, req.comment, now],
    )?;
    tx.execute(
        "UPDATE applications SET status = 'rejected', updated_at = ?2 WHERE id = ?1",
        rusqlite::params![id, now],
    )?;
    tx.commit()?;
    let app = load_application(&conn, id)?;
    Ok(Json(app))
}

async fn activate_window(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
    // Activation is performed by the applicant (operator) or an admin.
    let principal = authorize(&state, &headers, &[Role::Operator])?;
    let mut conn = lock_db(&state.db);
    let window = load_window(&conn, id)?;
    // Only the window's own applicant (or an admin) may activate it.
    let app = load_application(&conn, window.application_id)?;
    if principal.role != Role::Admin && app.applicant != principal.username {
        return Err(ApiError::from((
            StatusCode::FORBIDDEN,
            "only the applicant may activate this window".to_string(),
        )));
    }
    if window.status != WindowStatus::Approved.as_str() {
        return Err(ApiError::conflict(format!(
            "only approved windows can be activated (current: {})",
            window.status
        )));
    }
    // Time-window check: current time must fall within [start, end].
    let start = parse_time(&window.start_time, "start_time")?;
    let end = parse_time(&window.end_time, "end_time")?;
    let now = Utc::now();
    if now < start {
        return Err(ApiError::conflict(format!(
            "window not yet open; starts at {}",
            window.start_time
        )));
    }
    if now > end {
        return Err(ApiError::conflict(format!(
            "window already ended at {}; mark it expired instead",
            window.end_time
        )));
    }

    let now_s = now.to_rfc3339();
    // Activation touches three tables; keep them consistent via a transaction.
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE access_windows SET status = 'active', activated_at = ?2 WHERE id = ?1",
        rusqlite::params![id, now_s],
    )?;
    tx.execute(
        "UPDATE applications SET status = 'active', updated_at = ?2 WHERE id = ?1",
        rusqlite::params![window.application_id, now_s],
    )?;
    tx.execute(
        "INSERT INTO activation_records (window_id, application_id, activated_by, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, window.application_id, principal.username, now_s],
    )?;
    tx.commit()?;
    let window = load_window(&conn, id)?;
    Ok(Json(window))
}

async fn revoke_window(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<RevokeReq>,
) -> ApiResult<impl IntoResponse> {
    // Revocation is an approver/admin action.
    let principal = authorize(&state, &headers, &[Role::Approver])?;
    let mut conn = lock_db(&state.db);
    let window = load_window(&conn, id)?;
    // Only approved or active windows can be revoked.
    if !matches!(
        window.status.as_str(),
        s if s == WindowStatus::Approved.as_str() || s == WindowStatus::Active.as_str()
    ) {
        return Err(ApiError::conflict(format!(
            "only approved or active windows can be revoked (current: {})",
            window.status
        )));
    }
    let now = now_rfc3339();
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE access_windows SET status = 'revoked', revoked_at = ?2 WHERE id = ?1",
        rusqlite::params![id, now],
    )?;
    tx.execute(
        "UPDATE applications SET status = 'revoked', updated_at = ?2 WHERE id = ?1",
        rusqlite::params![window.application_id, now],
    )?;
    tx.execute(
        "INSERT INTO revocation_records (window_id, application_id, revoked_by, reason, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, window.application_id, principal.username, req.reason, now],
    )?;
    tx.commit()?;
    let window = load_window(&conn, id)?;
    Ok(Json(window))
}

async fn expire_window(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
    // Marking expired is an approver/admin operation.
    authorize(&state, &headers, &[Role::Approver])?;
    let mut conn = lock_db(&state.db);
    let window = load_window(&conn, id)?;
    if !matches!(
        window.status.as_str(),
        s if s == WindowStatus::Approved.as_str() || s == WindowStatus::Active.as_str()
    ) {
        return Err(ApiError::conflict(format!(
            "only approved or active windows can be expired (current: {})",
            window.status
        )));
    }
    let end = parse_time(&window.end_time, "end_time")?;
    if Utc::now() <= end {
        return Err(ApiError::conflict(format!(
            "window is still within its validity period (ends at {})",
            window.end_time
        )));
    }
    let now = now_rfc3339();
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE access_windows SET status = 'expired', expired_at = ?2 WHERE id = ?1",
        rusqlite::params![id, now],
    )?;
    tx.execute(
        "UPDATE applications SET status = 'expired', updated_at = ?2 WHERE id = ?1",
        rusqlite::params![window.application_id, now],
    )?;
    tx.commit()?;
    let window = load_window(&conn, id)?;
    Ok(Json(window))
}

async fn application_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
    authenticate(&state, &headers)?;
    let conn = lock_db(&state.db);
    let app = load_application(&conn, id)?;
    let windows = load_windows_for_application(&conn, id)?;
    let approvals = load_approvals(&conn, id)?;
    let activations = load_activations(&conn, id)?;
    let revocations = load_revocations(&conn, id)?;
    Ok(Json(json!({
        "application": app,
        "windows": windows,
        "approval_records": approvals,
        "activation_records": activations,
        "revocation_records": revocations,
    })))
}

#[derive(Debug, Deserialize)]
struct ActiveWindowsQuery {
    /// Optional reference time (RFC3339). Defaults to now.
    at: Option<String>,
}

async fn active_windows_by_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource): Path<String>,
    Query(q): Query<ActiveWindowsQuery>,
) -> ApiResult<impl IntoResponse> {
    authenticate(&state, &headers)?;
    let at = match q.at {
        Some(ref s) => parse_time(s, "at")?,
        None => Utc::now(),
    };
    let conn = lock_db(&state.db);
    // "Currently valid" = window is active AND now falls within [start, end].
    let mut stmt = conn.prepare(
        "SELECT id, application_id, target_resource, start_time, end_time, status,
                created_at, activated_at, revoked_at, expired_at
         FROM access_windows
         WHERE target_resource = ?1 AND status = 'active'
           AND start_time <= ?2 AND end_time >= ?2
         ORDER BY start_time ASC",
    )?;
    let at_s = at.to_rfc3339();
    let rows = stmt
        .query_map(rusqlite::params![resource, at_s], row_to_window)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "resource": resource, "as_of": at_s, "windows": rows })))
}

// ----- DB row loaders -----

fn load_application(conn: &Connection, id: i64) -> ApiResult<Application> {
    conn.query_row(
        "SELECT id, applicant, target_resource, reason, start_time, end_time,
                risk_level, status, created_at, updated_at
         FROM applications WHERE id = ?1",
        rusqlite::params![id],
        |r| {
            Ok(Application {
                id: r.get(0)?,
                applicant: r.get(1)?,
                target_resource: r.get(2)?,
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
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            ApiError::not_found(format!("application {id} not found"))
        }
        other => other.into(),
    })
}

fn row_to_window(r: &rusqlite::Row) -> rusqlite::Result<AccessWindow> {
    Ok(AccessWindow {
        id: r.get(0)?,
        application_id: r.get(1)?,
        target_resource: r.get(2)?,
        start_time: r.get(3)?,
        end_time: r.get(4)?,
        status: r.get(5)?,
        created_at: r.get(6)?,
        activated_at: r.get(7)?,
        revoked_at: r.get(8)?,
        expired_at: r.get(9)?,
    })
}

fn load_window(conn: &Connection, id: i64) -> ApiResult<AccessWindow> {
    conn.query_row(
        "SELECT id, application_id, target_resource, start_time, end_time, status,
                created_at, activated_at, revoked_at, expired_at
         FROM access_windows WHERE id = ?1",
        rusqlite::params![id],
        row_to_window,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            ApiError::not_found(format!("window {id} not found"))
        }
        other => other.into(),
    })
}

fn load_windows_for_application(conn: &Connection, app_id: i64) -> ApiResult<Vec<AccessWindow>> {
    let mut stmt = conn.prepare(
        "SELECT id, application_id, target_resource, start_time, end_time, status,
                created_at, activated_at, revoked_at, expired_at
         FROM access_windows WHERE application_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![app_id], row_to_window)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_approvals(conn: &Connection, app_id: i64) -> ApiResult<Vec<ApprovalRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, application_id, decision, approver, comment, created_at
         FROM approval_records WHERE application_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![app_id], |r| {
            Ok(ApprovalRecord {
                id: r.get(0)?,
                application_id: r.get(1)?,
                decision: r.get(2)?,
                approver: r.get(3)?,
                comment: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_activations(conn: &Connection, app_id: i64) -> ApiResult<Vec<ActivationRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, window_id, application_id, activated_by, created_at
         FROM activation_records WHERE application_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![app_id], |r| {
            Ok(ActivationRecord {
                id: r.get(0)?,
                window_id: r.get(1)?,
                application_id: r.get(2)?,
                activated_by: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_revocations(conn: &Connection, app_id: i64) -> ApiResult<Vec<RevocationRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, window_id, application_id, revoked_by, reason, created_at
         FROM revocation_records WHERE application_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![app_id], |r| {
            Ok(RevocationRecord {
                id: r.get(0)?,
                window_id: r.get(1)?,
                application_id: r.get(2)?,
                revoked_by: r.get(3)?,
                reason: r.get(4)?,
                created_at: r.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
