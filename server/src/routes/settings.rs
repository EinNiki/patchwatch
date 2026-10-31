//! Einstellungen, die zur Laufzeit in der UI änderbar sind (Tabelle `settings`).

use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::schedule::{self, ReportSchedule};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;

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
    let now = Utc::now();
    let mut feeds = Vec::new();
    for src in crate::cve::sources::list(&st).await? {
        let source = &src.id;
        let default = st.cfg.cve.interval_minutes as i64;
        feeds.push(json!({
            "source": source,
            "label": src.label,
            "interval_minutes": schedule::feed_interval_minutes(&st.pool, source, default).await,
            "default_minutes": default,
        }));
    }
    let sched = schedule::report_schedule(&st.pool).await;
    let last_run = schedule::reports_last_run(&st.pool).await;
    Ok(Json(json!({
        "report_retention_days": retention_days(&st.pool, st.cfg.report_retention_days).await,
        "report_retention_default_days": st.cfg.report_retention_days,
        "report_retention_min_days": RETENTION_RANGE.start(),
        "report_retention_max_days": RETENTION_RANGE.end(),
        "stale_after_hours": schedule::stale_after_hours(&st.pool, st.cfg.stale_after_hours).await,
        "stale_after_default_hours": st.cfg.stale_after_hours,
        "stale_after_min_hours": schedule::STALE_HOURS_RANGE.start(),
        "stale_after_max_hours": schedule::STALE_HOURS_RANGE.end(),
        "feeds": feeds,
        "feed_interval_min_minutes": schedule::FEED_INTERVAL_RANGE.start(),
        "feed_interval_max_minutes": schedule::FEED_INTERVAL_RANGE.end(),
        "report_schedule": schedule::report_schedule_json(&sched, last_run, now),
        "report_every_hours_min": schedule::REPORT_EVERY_HOURS_RANGE.start(),
        "report_every_hours_max": schedule::REPORT_EVERY_HOURS_RANGE.end(),
        // Das Check-in-Intervall steht in der agent.toml und wird dort geändert; hier nur zur Anzeige.
        "checkin_interval_hint": "Das Check-in-Intervall der Agents steht in deren agent.toml (Standard: alle 15 Minuten).",
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    report_retention_days: Option<i64>,
    stale_after_hours: Option<i64>,
    /// Quelle -> Minuten.
    feed_intervals: Option<BTreeMap<String, i64>>,
    report_schedule: Option<ReportSchedule>,
}

pub async fn put(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Json(body): Json<Body>,
) -> ApiResult<Json<Value>> {
    // Erst alles prüfen, dann in einer Transaktion schreiben: ein ungültiger Wert ändert nichts.
    if let Some(d) = body.report_retention_days {
        if !RETENTION_RANGE.contains(&d) {
            return Err(ApiError::BadRequest(format!(
                "Aufbewahrung: {} bis {} Tage",
                RETENTION_RANGE.start(),
                RETENTION_RANGE.end()
            )));
        }
    }
    if let Some(h) = body.stale_after_hours {
        schedule::validate_stale_hours(h).map_err(ApiError::BadRequest)?;
    }
    if let Some(map) = &body.feed_intervals {
        for (source, minutes) in map {
            // Nur bekannte Quellen: der Schlüssel landet in einem Settings-Key.
            let known: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM cve_sources WHERE id = $1 AND deleted_at IS NULL)",
            )
            .bind(source)
            .fetch_one(&st.pool)
            .await?;
            if !known {
                return Err(ApiError::BadRequest("Unbekannte Feed-Quelle".into()));
            }
            schedule::validate_feed_interval(*minutes).map_err(ApiError::BadRequest)?;
        }
    }
    if let Some(r) = &body.report_schedule {
        r.validate().map_err(ApiError::BadRequest)?;
    }

    let mut tx = st.pool.begin().await?;
    if let Some(d) = body.report_retention_days {
        schedule::set(&mut *tx, RETENTION_KEY, &json!(d)).await?;
    }
    if let Some(h) = body.stale_after_hours {
        schedule::set(&mut *tx, schedule::STALE_KEY, &json!(h)).await?;
    }
    for (source, minutes) in body.feed_intervals.iter().flatten() {
        schedule::set(&mut *tx, &schedule::feed_key(source), &json!(minutes)).await?;
    }
    if let Some(r) = &body.report_schedule {
        schedule::set(
            &mut *tx,
            schedule::REPORTS_KEY,
            &serde_json::to_value(r).unwrap_or(Value::Null),
        )
        .await?;
        // Die Zählung beginnt mit dem Speichern: ein neuer Plan löst nicht rückwirkend sofort aus.
        schedule::set(
            &mut *tx,
            schedule::REPORTS_LAST_RUN_KEY,
            &json!(Utc::now().to_rfc3339()),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "ok": true })))
}
