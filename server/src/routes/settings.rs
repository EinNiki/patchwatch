//! Einstellungen, die zur Laufzeit in der UI änderbar sind (Tabelle `settings`).

use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;

pub const RETENTION_KEY: &str = "report_retention_days";
pub const RETENTION_RANGE: std::ops::RangeInclusive<i64> = 7..=3650;

/// Aufbewahrung der Report-Historie in Tagen: UI-Wert vor Konfiguration.
pub async fn retention_days(pool: &PgPool, fallback: i64) -> i64 {
    sqlx::query_scalar::<_, Value>("SELECT value FROM settings WHERE key = $1")
        .bind(RETENTION_KEY)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.as_i64())
        .filter(|d| RETENTION_RANGE.contains(d))
        .unwrap_or(fallback)
}

pub async fn get(_: Admin, State(st): State<AppState>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "report_retention_days": retention_days(&st.pool, st.cfg.report_retention_days).await,
        "report_retention_default_days": st.cfg.report_retention_days,
        "report_retention_min_days": RETENTION_RANGE.start(),
        "report_retention_max_days": RETENTION_RANGE.end(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    report_retention_days: i64,
}

pub async fn put(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Json(body): Json<Body>,
) -> ApiResult<Json<Value>> {
    if !RETENTION_RANGE.contains(&body.report_retention_days) {
        return Err(ApiError::BadRequest(format!(
            "Aufbewahrung: {} bis {} Tage",
            RETENTION_RANGE.start(),
            RETENTION_RANGE.end()
        )));
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(RETENTION_KEY)
    .bind(json!(body.report_retention_days))
    .execute(&st.pool)
    .await?;
    Ok(Json(
        json!({ "report_retention_days": body.report_retention_days }),
    ))
}
