use crate::cve::refresh;
use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(sqlx::FromRow)]
struct FeedDb {
    source: String,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    consecutive_failures: i32,
}

#[derive(Serialize)]
pub struct FeedRow {
    source: String,
    configured: bool,
    /// `ok`, `stale` (Fehler oder zu lange kein Erfolg) oder `never` (noch nie erfolgreich abgerufen).
    state: &'static str,
    healthy: bool,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    /// Seit wann die Daten dieser Quelle veraltet sind (= letzter erfolgreicher Abruf).
    stale_since: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    consecutive_failures: i32,
}

/// Zustand eines Feeds; ein Feed ist nie "ok", solange der letzte Abruf fehlschlug oder zu lange her ist.
fn classify(
    f: &FeedDb,
    now: DateTime<Utc>,
    max_age: Duration,
) -> (&'static str, Option<DateTime<Utc>>) {
    match f.last_success_at {
        None => ("never", None),
        Some(t) if f.consecutive_failures > 0 || now - t > max_age => ("stale", Some(t)),
        Some(_) => ("ok", None),
    }
}

pub async fn list(_: Admin, State(st): State<AppState>) -> ApiResult<Json<Vec<FeedRow>>> {
    let rows: Vec<FeedDb> = sqlx::query_as(
        "SELECT source, last_attempt_at, last_success_at, last_error, last_error_at, consecutive_failures FROM feed_state ORDER BY source",
    )
    .fetch_all(&st.pool)
    .await?;
    let now = Utc::now();
    // Ohne Erfolg seit 3 Intervallen gilt ein Feed auch dann als veraltet, wenn kein Fehler gespeichert wurde.
    let max_age = Duration::minutes(3 * st.cfg.cve.interval_minutes as i64);
    let configured = &st.cfg.cve.sources;
    let mut out: Vec<FeedRow> = rows
        .into_iter()
        .map(|f| {
            let (state, stale_since) = classify(&f, now, max_age);
            FeedRow {
                configured: configured.contains(&f.source),
                healthy: state == "ok",
                state,
                stale_since,
                source: f.source,
                last_attempt_at: f.last_attempt_at,
                last_success_at: f.last_success_at,
                last_error: f.last_error,
                last_error_at: f.last_error_at,
                consecutive_failures: f.consecutive_failures,
            }
        })
        .collect();
    // Konfigurierte, aber noch nie gelaufene Quellen sichtbar machen (nie stillschweigend "grün").
    for s in configured {
        if !out.iter().any(|r| &r.source == s) {
            out.push(FeedRow {
                source: s.clone(),
                configured: true,
                state: "never",
                healthy: false,
                last_attempt_at: None,
                last_success_at: None,
                stale_since: None,
                last_error: None,
                last_error_at: None,
                consecutive_failures: 0,
            });
        }
    }
    out.sort_by(|a, b| a.source.cmp(&b.source));
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct RefreshQuery {
    wait: Option<bool>,
}

/// Feeds sofort abrufen. Mit `?wait=true` wird auf das Ergebnis gewartet, sonst im Hintergrund (202).
pub async fn refresh(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Query(q): Query<RefreshQuery>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let guard = st
        .refresh_lock
        .clone()
        .try_lock_owned()
        .map_err(|_| ApiError::Conflict("Ein Feed-Abruf läuft bereits".into()))?;
    if q.wait.unwrap_or(false) {
        let results = refresh::refresh_all(&st).await;
        drop(guard);
        let body: Vec<Value> = results
            .into_iter()
            .map(|(source, o)| match o {
                refresh::Outcome::NotModified => json!({ "source": source, "result": "not_modified" }),
                refresh::Outcome::Updated { changed_rows, events } => json!({ "source": source, "result": "updated", "changed_rows": changed_rows, "events": events }),
                refresh::Outcome::Failed(e) => json!({ "source": source, "result": "failed", "error": e }),
            })
            .collect();
        return Ok((StatusCode::OK, Json(json!({ "results": body }))));
    }
    tokio::spawn(async move {
        refresh::refresh_all(&st).await;
        drop(guard);
    });
    Ok((StatusCode::ACCEPTED, Json(json!({ "status": "gestartet" }))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(success_h: Option<i64>, failures: i32) -> (FeedDb, DateTime<Utc>) {
        let now = Utc::now();
        (
            FeedDb {
                source: "ubuntu".into(),
                last_attempt_at: None,
                last_success_at: success_h.map(|h| now - Duration::hours(h)),
                last_error: None,
                last_error_at: None,
                consecutive_failures: failures,
            },
            now,
        )
    }

    #[test]
    fn feed_is_never_silently_green() {
        let max = Duration::hours(3);
        let (f, now) = feed(None, 0);
        assert_eq!(classify(&f, now, max).0, "never");
        let (f, now) = feed(Some(1), 0);
        assert_eq!(classify(&f, now, max).0, "ok");
        // Letzter Abruf fehlgeschlagen: stale seit dem letzten Erfolg.
        let (f, now) = feed(Some(1), 1);
        let (state, since) = classify(&f, now, max);
        assert_eq!(state, "stale");
        assert_eq!(since, f.last_success_at);
        // Kein Fehler gespeichert, aber seit Stunden kein Erfolg (z. B. Scheduler hängt).
        let (f, now) = feed(Some(5), 0);
        assert_eq!(classify(&f, now, max).0, "stale");
    }
}
