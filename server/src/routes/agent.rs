//! Agent-seitige Endpunkte: Token-Authentifizierung und Check-in.
//!
//! Der Check-in beantwortet ausschließlich die Frage "Report jetzt senden?". Der Server schickt dem
//! Agent bewusst nie Befehle, Pfade oder Skripte.

use crate::error::{ApiError, ApiResult};
use crate::extract::ClientIp;
use crate::security;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap};
use axum::Json;
use serde_json::{json, Value};
use std::time::Duration;

/// Eine Anfrage gilt als verloren, wenn der Agent nach "ja" 10 Minuten keinen Report liefert.
pub const DISPATCH_RETRY_MINUTES: i32 = 10;

/// Findet den Host zum Bearer-Token (nur der Hash liegt in der DB). `scope` trennt die Rate-Limits
/// je Endpunkt, `per_minute` ist das Limit je Client-IP; Fehlversuche werden zusätzlich begrenzt.
pub(crate) async fn authenticate_host(
    st: &AppState,
    ip: &str,
    headers: &HeaderMap,
    scope: &str,
    per_minute: u32,
) -> ApiResult<i64> {
    st.limiter
        .check(
            &format!("{scope}:{ip}"),
            per_minute,
            Duration::from_secs(60),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| !t.is_empty() && t.len() <= 200);
    let host: Option<(i64,)> = match token {
        Some(t) => {
            sqlx::query_as("SELECT id FROM hosts WHERE token_hash = $1")
                .bind(security::sha256(t))
                .fetch_optional(&st.pool)
                .await?
        }
        None => None,
    };
    match host {
        Some((id,)) => Ok(id),
        None => {
            st.limiter
                .check(&format!("{scope}-bad:{ip}"), 20, Duration::from_secs(600))
                .map_err(|w| ApiError::TooManyRequests {
                    retry_after_secs: w.as_secs().max(1),
                })?;
            Err(ApiError::Unauthorized)
        }
    }
}

/// Längste Wartezeit eines Check-ins (Long-Poll); der Agent fragt danach sofort erneut.
const MAX_WAIT_SECS: u64 = 55;

#[derive(serde::Deserialize)]
pub struct CheckinQuery {
    /// Sekunden, die der Server auf eine Anforderung wartet, bevor er „nein“ antwortet (0 = sofort).
    wait: Option<u64>,
}

/// Atomar: meldet, ob ein Report gewünscht ist, und markiert ihn als ausgeliefert.
/// Aktualisiert `last_checkin_at`.
async fn dispatch(st: &AppState, host_id: i64) -> ApiResult<bool> {
    let mut tx = st.pool.begin().await?;
    let requested: (bool,) = sqlx::query_as(
        "WITH old AS ( \
            SELECT id, (report_requested_at IS NOT NULL AND ( \
                report_dispatched_at IS NULL OR report_dispatched_at < report_requested_at \
                OR report_dispatched_at < now() - make_interval(mins => $2))) AS want \
            FROM hosts WHERE id = $1 FOR UPDATE) \
         UPDATE hosts h SET last_checkin_at = now(), \
            report_dispatched_at = CASE WHEN old.want THEN now() ELSE h.report_dispatched_at END \
         FROM old WHERE h.id = old.id RETURNING old.want",
    )
    .bind(host_id)
    .bind(DISPATCH_RETRY_MINUTES)
    .fetch_one(&mut *tx)
    .await?;
    crate::live::notify(&mut tx, "checkin", Some(host_id), None).await;
    tx.commit().await?;
    Ok(requested.0)
}

/// Leichte Abfrage ohne Schreibzugriff: liegt eine auslieferbare Anforderung vor?
async fn wanted(st: &AppState, host_id: i64) -> ApiResult<bool> {
    let w: Option<bool> = sqlx::query_scalar(
        "SELECT report_requested_at IS NOT NULL AND (report_dispatched_at IS NULL \
            OR report_dispatched_at < report_requested_at \
            OR report_dispatched_at < now() - make_interval(mins => $2)) FROM hosts WHERE id = $1",
    )
    .bind(host_id)
    .bind(DISPATCH_RETRY_MINUTES)
    .fetch_optional(&st.pool)
    .await?
    .flatten();
    Ok(w.unwrap_or(false))
}

/// POST /api/v1/agent/checkin[?wait=N]: aktualisiert `last_checkin_at` und meldet, ob ein Report gewünscht ist.
/// "Ja" gibt es genau einmal je Anfrage (atomar), danach erst wieder nach `DISPATCH_RETRY_MINUTES`,
/// falls der Report ausbleibt. Mit `wait` hält der Server die Anfrage bis zu N Sekunden offen und antwortet sofort,
/// sobald in der UI „Jetzt aktualisieren“ gedrückt wird (Long-Poll). Der Request-Body wird nicht gelesen.
pub async fn checkin(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(q): Query<CheckinQuery>,
) -> ApiResult<Json<Value>> {
    let host_id = authenticate_host(&st, &ip, &headers, "checkin", 600).await?;
    // Zuerst abonnieren: eine Anforderung zwischen Prüfung und Warten geht so nicht verloren.
    let mut events = st.live.subscribe();
    let mut requested = dispatch(&st, host_id).await?;
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(q.wait.unwrap_or(0).min(MAX_WAIT_SECS));
    while !requested && tokio::time::Instant::now() < deadline {
        // Auf ein Live-Ereignis warten, spätestens nach 2 s erneut nachsehen (falls kein Listener läuft).
        let nap = std::time::Duration::from_secs(2).min(deadline - tokio::time::Instant::now());
        let _ = tokio::time::timeout(nap, events.recv()).await;
        if wanted(&st, host_id).await? {
            requested = dispatch(&st, host_id).await?;
        }
    }
    Ok(Json(json!({ "report_requested": requested })))
}
