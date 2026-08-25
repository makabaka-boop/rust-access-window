use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationStatus {
    Draft,
    Submitted,
    Approved,
    Active,
    Expired,
    Revoked,
    Rejected,
}

impl ApplicationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApplicationStatus::Draft => "draft",
            ApplicationStatus::Submitted => "submitted",
            ApplicationStatus::Approved => "approved",
            ApplicationStatus::Active => "active",
            ApplicationStatus::Expired => "expired",
            ApplicationStatus::Revoked => "revoked",
            ApplicationStatus::Rejected => "rejected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(ApplicationStatus::Draft),
            "submitted" => Some(ApplicationStatus::Submitted),
            "approved" => Some(ApplicationStatus::Approved),
            "active" => Some(ApplicationStatus::Active),
            "expired" => Some(ApplicationStatus::Expired),
            "revoked" => Some(ApplicationStatus::Revoked),
            "rejected" => Some(ApplicationStatus::Rejected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowStatus {
    Approved,
    Active,
    Expired,
    Revoked,
}

impl WindowStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "approved" => Some(WindowStatus::Approved),
            "active" => Some(WindowStatus::Active),
            "expired" => Some(WindowStatus::Expired),
            "revoked" => Some(WindowStatus::Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: i64,
    pub applicant: String,
    pub target_resource: String,
    pub reason: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub risk_level: RiskLevel,
    pub status: ApplicationStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessWindow {
    pub id: i64,
    pub application_id: i64,
    pub target_resource: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: WindowStatus,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub expired_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: i64,
    pub application_id: i64,
    pub action: String,
    pub approver: String,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationRecord {
    pub id: i64,
    pub application_id: i64,
    pub window_id: i64,
    pub activated_by: String,
    pub activated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub id: i64,
    pub application_id: i64,
    pub window_id: i64,
    pub revoked_by: String,
    pub reason: Option<String>,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationHistory {
    pub application: Application,
    pub window: Option<AccessWindow>,
    pub approval_records: Vec<ApprovalRecord>,
    pub activation_records: Vec<ActivationRecord>,
    pub revocation_records: Vec<RevocationRecord>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApplicationRequest {
    pub applicant: String,
    pub target_resource: String,
    pub reason: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RejectRequest {
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ActivateRequest {}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListWindowsQuery {
    pub resource: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListApplicationsQuery {
    pub status: Option<String>,
    pub applicant: Option<String>,
    pub resource: Option<String>,
}
