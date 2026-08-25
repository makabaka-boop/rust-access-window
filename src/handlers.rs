use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;
use std::sync::Arc;

use crate::auth::AuthUser;
use crate::db::Db;
use crate::error::AppError;
use crate::models::*;

pub type AppState = Arc<Db>;

pub async fn create_application(
    auth: AuthUser,
    State(db): State<AppState>,
    Json(mut req): Json<CreateApplicationRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !req.applicant.eq_ignore_ascii_case(&auth.user) {
        return Err(AppError::Forbidden(format!(
            "applicant in body '{}' does not match authenticated user '{}'",
            req.applicant, auth.user
        )));
    }
    req.applicant = auth.user.clone();
    let app = db.create_application(&req)?;
    Ok((StatusCode::CREATED, Json(app)))
}

pub async fn get_application(
    _auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    let app = db.get_application(id)?;
    Ok(Json(app))
}

pub async fn list_applications(
    _auth: AuthUser,
    State(db): State<AppState>,
    Query(query): Query<ListApplicationsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let apps = db.list_applications(&query)?;
    Ok(Json(apps))
}

pub async fn submit_application(
    auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    let app = db.submit_application(id, &auth.user, auth.role.is_admin())?;
    Ok(Json(json!({
        "application": app,
        "message": "application submitted for approval",
    })))
}

pub async fn approve_application(
    auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<ApproveRequest>,
) -> Result<impl IntoResponse, AppError> {
    auth.require_approver()?;
    let (app, window) =
        db.approve_application(id, &auth.user, req.comment.as_deref())?;
    Ok(Json(json!({
        "application": app,
        "window": window,
        "message": "application approved and access window created",
    })))
}

pub async fn reject_application(
    auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<RejectRequest>,
) -> Result<impl IntoResponse, AppError> {
    auth.require_approver()?;
    let app = db.reject_application(id, &auth.user, req.comment.as_deref())?;
    Ok(Json(json!({
        "application": app,
        "message": "application rejected",
    })))
}

pub async fn activate_window(
    auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
    body: Option<Json<ActivateRequest>>,
) -> Result<impl IntoResponse, AppError> {
    let _ = body;
    let (app, window) =
        db.activate_window(id, &auth.user, auth.role.is_admin())?;
    Ok(Json(json!({
        "application": app,
        "window": window,
        "message": "access window activated",
    })))
}

pub async fn revoke_window(
    auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<RevokeRequest>,
) -> Result<impl IntoResponse, AppError> {
    auth.require_admin()?;
    let (app, window) =
        db.revoke_window(id, &auth.user, req.reason.as_deref())?;
    Ok(Json(json!({
        "application": app,
        "window": window,
        "message": "access window revoked",
    })))
}

pub async fn expire_window(
    auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    auth.require_admin()?;
    let (app, window) = db.expire_window(id)?;
    Ok(Json(json!({
        "application": app,
        "window": window,
        "message": "access window marked as expired",
    })))
}

pub async fn get_history(
    _auth: AuthUser,
    State(db): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    let history = db.get_application_history(id)?;
    Ok(Json(history))
}

pub async fn list_active_windows(
    _auth: AuthUser,
    State(db): State<AppState>,
    Query(query): Query<ListWindowsQuery>,
) -> Result<impl IntoResponse, AppError> {
    let windows = db.list_active_windows(query.resource.as_deref())?;
    Ok(Json(json!({
        "windows": windows,
        "count": windows.len(),
    })))
}

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "rust-access-window",
    }))
}
