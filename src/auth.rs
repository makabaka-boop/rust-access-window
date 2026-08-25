use std::collections::HashMap;
use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};

/// Roles a principal can hold. `Admin` is allowed to perform any action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Requests, submits and activates windows (e.g. the engineer).
    Operator,
    /// Approves / rejects applications and revokes windows.
    Approver,
    /// May perform any action.
    Admin,
}

impl Role {
    fn parse(s: &str) -> Option<Role> {
        Some(match s.trim() {
            "operator" => Role::Operator,
            "approver" => Role::Approver,
            "admin" => Role::Admin,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Operator => "operator",
            Role::Approver => "approver",
            Role::Admin => "admin",
        }
    }
}

/// An authenticated caller resolved from an API token.
#[derive(Debug, Clone)]
pub struct Principal {
    pub username: String,
    pub role: Role,
}

/// Immutable token -> principal registry, shared across requests.
pub type TokenRegistry = Arc<HashMap<String, Principal>>;

/// Parse the `ACCESS_WINDOW_TOKENS` env value into a token registry.
///
/// Format: comma-separated `token:username:role` triples, e.g.
/// `s3cr3t-alice:alice:approver,s3cr3t-bob:bob:operator`.
/// Returns an error (fail closed) if the value is missing or malformed, so the
/// service never starts up silently accepting anonymous callers.
pub fn load_tokens_from_env() -> Result<TokenRegistry, String> {
    let raw = std::env::var("ACCESS_WINDOW_TOKENS")
        .map_err(|_| "ACCESS_WINDOW_TOKENS is not set; refusing to start without credentials".to_string())?;

    let mut map = HashMap::new();
    for (idx, entry) in raw.split(',').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() != 3 {
            return Err(format!(
                "token entry #{} malformed; expected 'token:username:role'",
                idx + 1
            ));
        }
        let token = parts[0].trim();
        let username = parts[1].trim();
        let role = Role::parse(parts[2])
            .ok_or_else(|| format!("token entry #{} has unknown role '{}'", idx + 1, parts[2]))?;
        if token.is_empty() || username.is_empty() {
            return Err(format!("token entry #{} has empty token or username", idx + 1));
        }
        map.insert(
            token.to_string(),
            Principal {
                username: username.to_string(),
                role,
            },
        );
    }
    if map.is_empty() {
        return Err("ACCESS_WINDOW_TOKENS did not contain any valid credentials".to_string());
    }
    Ok(Arc::new(map))
}

/// Extract the bearer/api-key token from request headers.
fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(rest) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
            let t = rest.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

/// Resolve the caller's identity from the request, or a `(status, message)`
/// auth error. Identity is never taken from the request body.
pub fn authenticate(
    headers: &HeaderMap,
    registry: &TokenRegistry,
) -> Result<Principal, (StatusCode, String)> {
    let token = extract_token(headers).ok_or((
        StatusCode::UNAUTHORIZED,
        "missing credentials; provide 'Authorization: Bearer <token>' or 'X-Api-Key'".to_string(),
    ))?;
    registry
        .get(&token)
        .cloned()
        .ok_or((StatusCode::UNAUTHORIZED, "invalid token".to_string()))
}

/// Ensure the principal holds one of `allowed` roles (Admin always passes).
pub fn require_role(
    principal: &Principal,
    allowed: &[Role],
) -> Result<(), (StatusCode, String)> {
    if principal.role == Role::Admin || allowed.contains(&principal.role) {
        Ok(())
    } else {
        let names: Vec<&str> = allowed.iter().map(|r| r.as_str()).collect();
        Err((
            StatusCode::FORBIDDEN,
            format!(
                "role '{}' is not permitted; requires one of: {}",
                principal.role.as_str(),
                names.join(", ")
            ),
        ))
    }
}
