use rusqlite::Connection;

/// Open the SQLite database at `path` and ensure the schema exists.
pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;",
    )?;
    init_schema(&conn)?;
    Ok(conn)
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS applications (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            applicant       TEXT NOT NULL,
            target_resource TEXT NOT NULL,
            reason          TEXT NOT NULL,
            start_time      TEXT NOT NULL,   -- RFC3339 UTC
            end_time        TEXT NOT NULL,   -- RFC3339 UTC
            risk_level      TEXT NOT NULL,   -- low | medium | high
            status          TEXT NOT NULL,   -- draft|submitted|approved|active|expired|revoked|rejected
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS access_windows (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id  INTEGER NOT NULL REFERENCES applications(id),
            target_resource TEXT NOT NULL,
            start_time      TEXT NOT NULL,
            end_time        TEXT NOT NULL,
            status          TEXT NOT NULL,   -- approved|active|expired|revoked
            created_at      TEXT NOT NULL,
            activated_at    TEXT,
            revoked_at      TEXT,
            expired_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS approval_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id  INTEGER NOT NULL REFERENCES applications(id),
            decision        TEXT NOT NULL,   -- approved | rejected
            approver        TEXT NOT NULL,
            comment         TEXT,
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activation_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            window_id       INTEGER NOT NULL REFERENCES access_windows(id),
            application_id  INTEGER NOT NULL REFERENCES applications(id),
            activated_by    TEXT NOT NULL,
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS revocation_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            window_id       INTEGER NOT NULL REFERENCES access_windows(id),
            application_id  INTEGER NOT NULL REFERENCES applications(id),
            revoked_by      TEXT NOT NULL,
            reason          TEXT,
            created_at      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_windows_resource ON access_windows(target_resource, status);
        CREATE INDEX IF NOT EXISTS idx_windows_application ON access_windows(application_id);
        "#,
    )
}
