use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

use crate::error::AppError;
use crate::models::*;

#[derive(Debug)]
pub struct Db {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    applicant TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    reason TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL UNIQUE,
    target_resource TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved',
    created_at TEXT NOT NULL,
    activated_at TEXT,
    expired_at TEXT,
    revoked_at TEXT,
    FOREIGN KEY (application_id) REFERENCES applications(id)
);

CREATE TABLE IF NOT EXISTS approval_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    approver TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id)
);

CREATE TABLE IF NOT EXISTS activation_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    window_id INTEGER NOT NULL,
    activated_by TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id),
    FOREIGN KEY (window_id) REFERENCES access_windows(id)
);

CREATE TABLE IF NOT EXISTS revocation_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    window_id INTEGER NOT NULL,
    revoked_by TEXT NOT NULL,
    reason TEXT,
    revoked_at TEXT NOT NULL,
    FOREIGN KEY (application_id) REFERENCES applications(id),
    FOREIGN KEY (window_id) REFERENCES access_windows(id)
);

CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_applications_applicant ON applications(applicant);
CREATE INDEX IF NOT EXISTS idx_applications_resource ON applications(target_resource);
CREATE INDEX IF NOT EXISTS idx_windows_resource ON access_windows(target_resource);
CREATE INDEX IF NOT EXISTS idx_windows_status ON access_windows(status);
CREATE INDEX IF NOT EXISTS idx_approval_app_id ON approval_records(application_id);
CREATE INDEX IF NOT EXISTS idx_activation_app_id ON activation_records(application_id);
CREATE INDEX IF NOT EXISTS idx_revocation_app_id ON revocation_records(application_id);
"#;

impl Db {
    pub fn open(path: &str) -> Result<Self, AppError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    fn row_to_application(row: &rusqlite::Row) -> rusqlite::Result<Application> {
        let start_str: String = row.get(4)?;
        let end_str: String = row.get(5)?;
        let risk_str: String = row.get(6)?;
        let status_str: String = row.get(7)?;
        let created_str: String = row.get(8)?;
        let updated_str: String = row.get(9)?;

        Ok(Application {
            id: row.get(0)?,
            applicant: row.get(1)?,
            target_resource: row.get(2)?,
            reason: row.get(3)?,
            start_time: DateTime::parse_from_rfc3339(&start_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))?
                .with_timezone(&Utc),
            end_time: DateTime::parse_from_rfc3339(&end_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))?
                .with_timezone(&Utc),
            risk_level: RiskLevel::from_str(&risk_str).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid risk level: {}", risk_str),
                    )),
                )
            })?,
            status: ApplicationStatus::from_str(&status_str).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid status: {}", status_str),
                    )),
                )
            })?,
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))?
                .with_timezone(&Utc),
        })
    }

    fn row_to_window(row: &rusqlite::Row) -> rusqlite::Result<AccessWindow> {
        let start_str: String = row.get(3)?;
        let end_str: String = row.get(4)?;
        let status_str: String = row.get(5)?;
        let created_str: String = row.get(6)?;
        let activated_str: Option<String> = row.get(7)?;
        let expired_str: Option<String> = row.get(8)?;
        let revoked_str: Option<String> = row.get(9)?;

        let parse_dt = |s: &str| -> rusqlite::Result<DateTime<Utc>> {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))
        };

        let parse_opt_dt = |s: &Option<String>| -> rusqlite::Result<Option<DateTime<Utc>>> {
            match s {
                Some(v) => Ok(Some(parse_dt(v)?)),
                None => Ok(None),
            }
        };

        Ok(AccessWindow {
            id: row.get(0)?,
            application_id: row.get(1)?,
            target_resource: row.get(2)?,
            start_time: parse_dt(&start_str)?,
            end_time: parse_dt(&end_str)?,
            status: WindowStatus::from_str(&status_str).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid window status: {}", status_str),
                    )),
                )
            })?,
            created_at: parse_dt(&created_str)?,
            activated_at: parse_opt_dt(&activated_str)?,
            expired_at: parse_opt_dt(&expired_str)?,
            revoked_at: parse_opt_dt(&revoked_str)?,
        })
    }

    fn row_to_approval(row: &rusqlite::Row) -> rusqlite::Result<ApprovalRecord> {
        let created_str: String = row.get(5)?;
        Ok(ApprovalRecord {
            id: row.get(0)?,
            application_id: row.get(1)?,
            action: row.get(2)?,
            approver: row.get(3)?,
            comment: row.get(4)?,
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))?
                .with_timezone(&Utc),
        })
    }

    fn row_to_activation(row: &rusqlite::Row) -> rusqlite::Result<ActivationRecord> {
        let at_str: String = row.get(4)?;
        Ok(ActivationRecord {
            id: row.get(0)?,
            application_id: row.get(1)?,
            window_id: row.get(2)?,
            activated_by: row.get(3)?,
            activated_at: DateTime::parse_from_rfc3339(&at_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))?
                .with_timezone(&Utc),
        })
    }

    fn row_to_revocation(row: &rusqlite::Row) -> rusqlite::Result<RevocationRecord> {
        let at_str: String = row.get(5)?;
        Ok(RevocationRecord {
            id: row.get(0)?,
            application_id: row.get(1)?,
            window_id: row.get(2)?,
            revoked_by: row.get(3)?,
            reason: row.get(4)?,
            revoked_at: DateTime::parse_from_rfc3339(&at_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))?
                .with_timezone(&Utc),
        })
    }

    pub fn create_application(
        &self,
        req: &CreateApplicationRequest,
    ) -> Result<Application, AppError> {
        if req.start_time >= req.end_time {
            return Err(AppError::Validation(
                "start_time must be before end_time".to_string(),
            ));
        }
        if req.applicant.trim().is_empty() {
            return Err(AppError::Validation("applicant is required".to_string()));
        }
        if req.target_resource.trim().is_empty() {
            return Err(AppError::Validation(
                "target_resource is required".to_string(),
            ));
        }
        if req.reason.trim().is_empty() {
            return Err(AppError::Validation("reason is required".to_string()));
        }

        let now = Utc::now();
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO applications (applicant, target_resource, reason, start_time, end_time, risk_level, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                req.applicant,
                req.target_resource,
                req.reason,
                req.start_time.to_rfc3339(),
                req.end_time.to_rfc3339(),
                req.risk_level.as_str(),
                ApplicationStatus::Draft.as_str(),
                now.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )?;

        let id = conn.last_insert_rowid();
        self.get_application_conn(&conn, id)
    }

    fn get_application_conn(
        &self,
        conn: &Connection,
        id: i64,
    ) -> Result<Application, AppError> {
        let mut stmt = conn.prepare(
            "SELECT id, applicant, target_resource, reason, start_time, end_time, risk_level, status, created_at, updated_at
             FROM applications WHERE id = ?1",
        )?;

        let app = stmt
            .query_row(params![id], Self::row_to_application)
            .optional()?
            .ok_or_else(|| {
                AppError::NotFound(format!("application {} not found", id))
            })?;
        Ok(app)
    }

    pub fn get_application(&self, id: i64) -> Result<Application, AppError> {
        let conn = self.conn.lock().unwrap();
        self.get_application_conn(&conn, id)
    }

    pub fn list_applications(
        &self,
        query: &ListApplicationsQuery,
    ) -> Result<Vec<Application>, AppError> {
        if let Some(s) = &query.status {
            if ApplicationStatus::from_str(s).is_none() {
                return Err(AppError::Validation(format!(
                    "invalid status '{}': must be one of draft, submitted, approved, active, expired, revoked, rejected",
                    s
                )));
            }
        }

        let conn = self.conn.lock().unwrap();
        let mut sql = String::from(
            "SELECT id, applicant, target_resource, reason, start_time, end_time, risk_level, status, created_at, updated_at
             FROM applications WHERE 1=1",
        );
        let mut param_values: Vec<String> = Vec::new();

        if let Some(s) = &query.status {
            sql.push_str(" AND status = ?");
            param_values.push(s.clone());
        }
        if let Some(a) = &query.applicant {
            sql.push_str(" AND applicant = ?");
            param_values.push(a.clone());
        }
        if let Some(r) = &query.resource {
            sql.push_str(" AND target_resource = ?");
            param_values.push(r.clone());
        }
        sql.push_str(" ORDER BY id DESC");

        let mut stmt = conn.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::ToSql> =
            param_values.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let apps = stmt.query_map(params_ref.as_slice(), Self::row_to_application)?;
        let mut result = Vec::new();
        for app in apps {
            result.push(app?);
        }
        Ok(result)
    }

    pub fn submit_application(
        &self,
        id: i64,
        operator: &str,
        is_admin: bool,
    ) -> Result<Application, AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let app = self.get_application_conn(&tx, id)?;
        if app.status != ApplicationStatus::Draft {
            return Err(AppError::InvalidTransition {
                from: app.status.as_str().to_string(),
                to: "submitted".to_string(),
            });
        }
        if !is_admin && app.applicant != operator {
            return Err(AppError::Forbidden(format!(
                "only the applicant '{}' or an admin can submit this application",
                app.applicant
            )));
        }

        let now = Utc::now();
        tx.execute(
            "UPDATE applications SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![
                ApplicationStatus::Submitted.as_str(),
                now.to_rfc3339(),
                id
            ],
        )?;

        let app = self.get_application_conn(&tx, id)?;
        tx.commit()?;
        Ok(app)
    }

    pub fn approve_application(
        &self,
        id: i64,
        approver: &str,
        comment: Option<&str>,
    ) -> Result<(Application, AccessWindow), AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let app = self.get_application_conn(&tx, id)?;
        if app.status != ApplicationStatus::Submitted {
            return Err(AppError::InvalidTransition {
                from: app.status.as_str().to_string(),
                to: "approved".to_string(),
            });
        }

        let now = Utc::now();

        tx.execute(
            "INSERT INTO approval_records (application_id, action, approver, comment, created_at)
             VALUES (?1, 'approve', ?2, ?3, ?4)",
            params![id, approver, comment, now.to_rfc3339()],
        )?;

        tx.execute(
            "UPDATE applications SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![
                ApplicationStatus::Approved.as_str(),
                now.to_rfc3339(),
                id
            ],
        )?;

        tx.execute(
            "INSERT INTO access_windows (application_id, target_resource, start_time, end_time, status, created_at)
             VALUES (?1, ?2, ?3, ?4, 'approved', ?5)",
            params![
                id,
                app.target_resource,
                app.start_time.to_rfc3339(),
                app.end_time.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )?;

        let window_id = tx.last_insert_rowid();
        let window = self.get_window_conn(&tx, window_id)?;
        let app = self.get_application_conn(&tx, id)?;

        tx.commit()?;
        Ok((app, window))
    }

    pub fn reject_application(
        &self,
        id: i64,
        approver: &str,
        comment: Option<&str>,
    ) -> Result<Application, AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let app = self.get_application_conn(&tx, id)?;
        if app.status != ApplicationStatus::Submitted {
            return Err(AppError::InvalidTransition {
                from: app.status.as_str().to_string(),
                to: "rejected".to_string(),
            });
        }

        let now = Utc::now();

        tx.execute(
            "INSERT INTO approval_records (application_id, action, approver, comment, created_at)
             VALUES (?1, 'reject', ?2, ?3, ?4)",
            params![id, approver, comment, now.to_rfc3339()],
        )?;

        tx.execute(
            "UPDATE applications SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![
                ApplicationStatus::Rejected.as_str(),
                now.to_rfc3339(),
                id
            ],
        )?;

        let app = self.get_application_conn(&tx, id)?;
        tx.commit()?;
        Ok(app)
    }

    pub fn activate_window(
        &self,
        id: i64,
        activated_by: &str,
        is_admin: bool,
    ) -> Result<(Application, AccessWindow), AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let app = self.get_application_conn(&tx, id)?;
        if app.status != ApplicationStatus::Approved {
            return Err(AppError::InvalidTransition {
                from: app.status.as_str().to_string(),
                to: "active".to_string(),
            });
        }
        if !is_admin && app.applicant != activated_by {
            return Err(AppError::Forbidden(format!(
                "only the applicant '{}' or an admin can activate this window",
                app.applicant
            )));
        }

        let window = self.get_window_by_application_conn(&tx, id)?;
        let now = Utc::now();

        if now < window.start_time {
            return Err(AppError::NotStarted(window.start_time.to_rfc3339()));
        }
        if now > window.end_time {
            return Err(AppError::AlreadyExpired(window.end_time.to_rfc3339()));
        }

        tx.execute(
            "INSERT INTO activation_records (application_id, window_id, activated_by, activated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, window.id, activated_by, now.to_rfc3339()],
        )?;

        tx.execute(
            "UPDATE access_windows SET status = 'active', activated_at = ?1 WHERE id = ?2",
            params![now.to_rfc3339(), window.id],
        )?;

        tx.execute(
            "UPDATE applications SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![
                ApplicationStatus::Active.as_str(),
                now.to_rfc3339(),
                id
            ],
        )?;

        let window = self.get_window_conn(&tx, window.id)?;
        let app = self.get_application_conn(&tx, id)?;

        tx.commit()?;
        Ok((app, window))
    }

    pub fn revoke_window(
        &self,
        id: i64,
        revoked_by: &str,
        reason: Option<&str>,
    ) -> Result<(Application, AccessWindow), AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let app = self.get_application_conn(&tx, id)?;
        if app.status != ApplicationStatus::Approved && app.status != ApplicationStatus::Active {
            return Err(AppError::InvalidTransition {
                from: app.status.as_str().to_string(),
                to: "revoked".to_string(),
            });
        }

        let window = self.get_window_by_application_conn(&tx, id)?;
        let now = Utc::now();

        tx.execute(
            "INSERT INTO revocation_records (application_id, window_id, revoked_by, reason, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, window.id, revoked_by, reason, now.to_rfc3339()],
        )?;

        tx.execute(
            "UPDATE access_windows SET status = 'revoked', revoked_at = ?1 WHERE id = ?2",
            params![now.to_rfc3339(), window.id],
        )?;

        tx.execute(
            "UPDATE applications SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![
                ApplicationStatus::Revoked.as_str(),
                now.to_rfc3339(),
                id
            ],
        )?;

        let window = self.get_window_conn(&tx, window.id)?;
        let app = self.get_application_conn(&tx, id)?;

        tx.commit()?;
        Ok((app, window))
    }

    pub fn expire_window(&self, id: i64) -> Result<(Application, AccessWindow), AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let app = self.get_application_conn(&tx, id)?;
        if app.status != ApplicationStatus::Approved && app.status != ApplicationStatus::Active {
            return Err(AppError::InvalidTransition {
                from: app.status.as_str().to_string(),
                to: "expired".to_string(),
            });
        }

        let window = self.get_window_by_application_conn(&tx, id)?;
        let now = Utc::now();

        if now <= window.end_time {
            return Err(AppError::Validation(format!(
                "window has not yet expired; end_time is {}",
                window.end_time.to_rfc3339()
            )));
        }

        tx.execute(
            "UPDATE access_windows SET status = 'expired', expired_at = ?1 WHERE id = ?2",
            params![now.to_rfc3339(), window.id],
        )?;

        tx.execute(
            "UPDATE applications SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![
                ApplicationStatus::Expired.as_str(),
                now.to_rfc3339(),
                id
            ],
        )?;

        let window = self.get_window_conn(&tx, window.id)?;
        let app = self.get_application_conn(&tx, id)?;

        tx.commit()?;
        Ok((app, window))
    }

    pub fn get_application_history(
        &self,
        id: i64,
    ) -> Result<ApplicationHistory, AppError> {
        let conn = self.conn.lock().unwrap();

        let application = self.get_application_conn(&conn, id)?;
        let window = self.get_window_by_application_optional_conn(&conn, id)?;

        let approval_records = {
            let mut stmt = conn.prepare(
                "SELECT id, application_id, action, approver, comment, created_at
                 FROM approval_records WHERE application_id = ?1 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![id], Self::row_to_approval)?;
            let mut result = Vec::new();
            for r in rows {
                result.push(r?);
            }
            result
        };

        let activation_records = {
            let mut stmt = conn.prepare(
                "SELECT id, application_id, window_id, activated_by, activated_at
                 FROM activation_records WHERE application_id = ?1 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![id], Self::row_to_activation)?;
            let mut result = Vec::new();
            for r in rows {
                result.push(r?);
            }
            result
        };

        let revocation_records = {
            let mut stmt = conn.prepare(
                "SELECT id, application_id, window_id, revoked_by, reason, revoked_at
                 FROM revocation_records WHERE application_id = ?1 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![id], Self::row_to_revocation)?;
            let mut result = Vec::new();
            for r in rows {
                result.push(r?);
            }
            result
        };

        Ok(ApplicationHistory {
            application,
            window,
            approval_records,
            activation_records,
            revocation_records,
        })
    }

    pub fn list_active_windows(
        &self,
        resource: Option<&str>,
    ) -> Result<Vec<AccessWindow>, AppError> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        let resource_owned = resource.map(|s| s.to_string());

        let base_sql = "SELECT id, application_id, target_resource, start_time, end_time, status, created_at, activated_at, expired_at, revoked_at
                 FROM access_windows
                 WHERE status = 'active'";

        let (sql, params_vec): (String, Vec<&dyn rusqlite::ToSql>) = match &resource_owned {
            Some(r) => {
                let sql = format!(
                    "{} AND target_resource = ?1 AND start_time <= ?2 AND end_time >= ?3 ORDER BY id DESC",
                    base_sql
                );
                let params: Vec<&dyn rusqlite::ToSql> =
                    vec![r as &dyn rusqlite::ToSql, &now_str as &dyn rusqlite::ToSql, &now_str as &dyn rusqlite::ToSql];
                (sql, params)
            }
            None => {
                let sql = format!(
                    "{} AND start_time <= ?1 AND end_time >= ?2 ORDER BY id DESC",
                    base_sql
                );
                let params: Vec<&dyn rusqlite::ToSql> =
                    vec![&now_str as &dyn rusqlite::ToSql, &now_str as &dyn rusqlite::ToSql];
                (sql, params)
            }
        };

        let mut stmt = conn.prepare(&sql)?;
        let windows = stmt.query_map(params_vec.as_slice(), Self::row_to_window)?;
        let mut result = Vec::new();
        for w in windows {
            result.push(w?);
        }
        Ok(result)
    }

    fn get_window_conn(
        &self,
        conn: &Connection,
        id: i64,
    ) -> Result<AccessWindow, AppError> {
        let mut stmt = conn.prepare(
            "SELECT id, application_id, target_resource, start_time, end_time, status, created_at, activated_at, expired_at, revoked_at
             FROM access_windows WHERE id = ?1",
        )?;
        let w = stmt
            .query_row(params![id], Self::row_to_window)
            .optional()?
            .ok_or_else(|| AppError::NotFound(format!("window {} not found", id)))?;
        Ok(w)
    }

    fn get_window_by_application_conn(
        &self,
        conn: &Connection,
        application_id: i64,
    ) -> Result<AccessWindow, AppError> {
        match self.get_window_by_application_optional_conn(conn, application_id)? {
            Some(w) => Ok(w),
            None => Err(AppError::NotFound(format!(
                "access window for application {} not found",
                application_id
            ))),
        }
    }

    fn get_window_by_application_optional_conn(
        &self,
        conn: &Connection,
        application_id: i64,
    ) -> Result<Option<AccessWindow>, AppError> {
        let mut stmt = conn.prepare(
            "SELECT id, application_id, target_resource, start_time, end_time, status, created_at, activated_at, expired_at, revoked_at
             FROM access_windows WHERE application_id = ?1",
        )?;
        let mut windows = stmt.query(params![application_id])?;
        match windows.next()? {
            Some(row) => Ok(Some(Self::row_to_window(row)?)),
            None => Ok(None),
        }
    }
}
