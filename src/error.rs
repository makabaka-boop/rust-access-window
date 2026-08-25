use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("time parse error: {0}")]
    TimeParse(#[from] chrono::ParseError),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    #[error("window has not yet reached start time: {0}")]
    NotStarted(String),

    #[error("window has already expired: {0}")]
    AlreadyExpired(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Db(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("database error: {}", e),
            ),
            AppError::TimeParse(e) => (
                StatusCode::BAD_REQUEST,
                format!("invalid time format: {}", e),
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::InvalidTransition { from, to } => (
                StatusCode::CONFLICT,
                format!("invalid state transition: {} -> {}", from, to),
            ),
            AppError::NotStarted(t) => (
                StatusCode::CONFLICT,
                format!("window has not yet reached start time: {}", t),
            ),
            AppError::AlreadyExpired(t) => (
                StatusCode::CONFLICT,
                format!("window has already expired: {}", t),
            ),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
        };

        let body = Json(json!({
            "error": status.to_string(),
            "message": message,
        }));

        (status, body).into_response()
    }
}
