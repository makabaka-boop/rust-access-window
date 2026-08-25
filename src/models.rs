use serde::{Deserialize, Serialize};

/// Lifecycle state of an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppStatus {
    Draft,
    Submitted,
    Approved,
    Active,
    Expired,
    Revoked,
    Rejected,
}

impl AppStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AppStatus::Draft => "draft",
            AppStatus::Submitted => "submitted",
            AppStatus::Approved => "approved",
            AppStatus::Active => "active",
            AppStatus::Expired => "expired",
            AppStatus::Revoked => "revoked",
            AppStatus::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "draft" => AppStatus::Draft,
            "submitted" => AppStatus::Submitted,
            "approved" => AppStatus::Approved,
            "active" => AppStatus::Active,
            "expired" => AppStatus::Expired,
            "revoked" => AppStatus::Revoked,
            "rejected" => AppStatus::Rejected,
            _ => return None,
        })
    }
}

/// Lifecycle state of an access window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowStatus {
    Approved,
    Active,
    Expired,
    Revoked,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WindowStatus::Approved => "approved",
            WindowStatus::Active => "active",
            WindowStatus::Expired => "expired",
            WindowStatus::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Application {
    pub id: i64,
    pub applicant: String,
    pub target_resource: String,
    pub reason: String,
    pub start_time: String,
    pub end_time: String,
    pub risk_level: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct AccessWindow {
    pub id: i64,
    pub application_id: i64,
    pub target_resource: String,
    pub start_time: String,
    pub end_time: String,
    pub status: String,
    pub created_at: String,
    pub activated_at: Option<String>,
    pub revoked_at: Option<String>,
    pub expired_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApprovalRecord {
    pub id: i64,
    pub application_id: i64,
    pub decision: String,
    pub approver: String,
    pub comment: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ActivationRecord {
    pub id: i64,
    pub window_id: i64,
    pub application_id: i64,
    pub activated_by: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct RevocationRecord {
    pub id: i64,
    pub window_id: i64,
    pub application_id: i64,
    pub revoked_by: String,
    pub reason: Option<String>,
    pub created_at: String,
}

// ---- Request payloads ----

#[derive(Debug, Deserialize)]
pub struct CreateApplicationReq {
    // applicant is derived from the authenticated caller, not the request body.
    pub target_resource: String,
    pub reason: String,
    pub start_time: String, // RFC3339
    pub end_time: String,   // RFC3339
    pub risk_level: String, // low | medium | high
}

// Note: approver / activated_by / revoked_by are intentionally NOT part of any
// request body. The acting identity is always derived from the authenticated
// principal (see auth.rs) so callers cannot impersonate one another.

#[derive(Debug, Default, Deserialize)]
pub struct ApproveReq {
    pub comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RejectReq {
    pub comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RevokeReq {
    pub reason: Option<String>,
}
