use crate::error::ApiResult;
use crate::extract::Admin;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Serialize, sqlx::FromRow)]
pub struct FeedRow {
    source: String,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    consecutive_failures: i32,
    /// Nur "gesund", wenn der letzte Abruf erfolgreich war; sonst "veraltet seit" `last_success_at`.
    healthy: bool,
}

pub async fn list(_: Admin, State(st): State<AppState>) -> ApiResult<Json<Vec<FeedRow>>> {
    let rows = sqlx::query_as::<_, FeedRow>(
        "SELECT source, last_attempt_at, last_success_at, last_error, last_error_at, consecutive_failures, \
                (last_success_at IS NOT NULL AND consecutive_failures = 0) AS healthy \
         FROM feed_state ORDER BY source",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows))
}
