mod auth;
mod db;
mod error;
mod handlers;
mod models;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use db::Db;

const DB_PATH: &str = "access_window.db";
const PORT: u16 = 18123;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let db = Db::open(DB_PATH)?;
    let state = Arc::new(db);

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/api/applications", post(handlers::create_application).get(handlers::list_applications))
        .route("/api/applications/:id", get(handlers::get_application))
        .route("/api/applications/:id/submit", post(handlers::submit_application))
        .route("/api/applications/:id/approve", post(handlers::approve_application))
        .route("/api/applications/:id/reject", post(handlers::reject_application))
        .route("/api/applications/:id/activate", post(handlers::activate_window))
        .route("/api/applications/:id/revoke", post(handlers::revoke_window))
        .route("/api/applications/:id/expire", post(handlers::expire_window))
        .route("/api/applications/:id/history", get(handlers::get_history))
        .route("/api/windows", get(handlers::list_active_windows))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", PORT);
    tracing::info!("server listening on http://{}", addr);
    tracing::info!("SQLite database file: {}", DB_PATH);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
