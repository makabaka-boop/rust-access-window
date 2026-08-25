use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Approver,
    Admin,
}

impl Role {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "user" => Some(Role::User),
            "approver" => Some(Role::Approver),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn can_approve(&self) -> bool {
        matches!(self, Role::Approver | Role::Admin)
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user: String,
    pub role: Role,
}

impl AuthUser {
    pub fn require_approver(&self) -> Result<(), AuthError> {
        if self.role.can_approve() {
            Ok(())
        } else {
            Err(AuthError::forbidden(
                "approver or admin role is required",
            ))
        }
    }

    pub fn require_admin(&self) -> Result<(), AuthError> {
        if self.role.is_admin() {
            Ok(())
        } else {
            Err(AuthError::forbidden("admin role is required"))
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    Unauthorized(String),
    Forbidden(String),
}

impl AuthError {
    pub fn unauthorized(msg: &str) -> Self {
        AuthError::Unauthorized(msg.to_string())
    }

    pub fn forbidden(msg: &str) -> Self {
        AuthError::Forbidden(msg.to_string())
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            AuthError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
        };
        let body = Json(json!({
            "error": status.to_string(),
            "message": message,
        }));
        (status, body).into_response()
    }
}

impl From<AuthError> for AppError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Unauthorized(m) => AppError::Unauthorized(m),
            AuthError::Forbidden(m) => AppError::Forbidden(m),
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let user = parts
            .headers
            .get("x-user")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AuthError::unauthorized("missing or empty X-User header")
            })?;

        let role = parts
            .headers
            .get("x-role")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
            .unwrap_or("user");

        let role = Role::from_str(role).ok_or_else(|| {
            AuthError::unauthorized(&format!(
                "invalid X-Role '{}': must be one of user, approver, admin",
                role
            ))
        })?;

        Ok(AuthUser { user, role })
    }
}
