use crate::cve::{refresh, sources};
use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
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
    /// `builtin` (Debian, Ubuntu) oder `managed` (über die UI hinzugefügt).
    kind: &'static str,
    enabled: bool,
    /// Alt-Feld: eingeschaltet.
    configured: bool,
    /// Reichert nur bereits bekannte CVEs an (OSV, NVD, CISA KEV).
    enrich_only: bool,
    takes_secret: bool,
    takes_base_url: bool,
    /// Nie das Geheimnis selbst.
    secret_set: bool,
    base_url: Option<String>,
    interval_minutes: i64,
    /// `ok`, `stale` (Fehler oder zu lange kein Erfolg), `never` (noch nie erfolgreich) oder `disabled` (abgeschaltet).
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

/// Zustand eines Feeds; ein Feed ist nie "ok", solange der letzte Abruf fehlschlug, er zu lange her ist oder er abgeschaltet ist.
fn classify(
    f: &FeedDb,
    enabled: bool,
    now: DateTime<Utc>,
    max_age: Duration,
) -> (&'static str, Option<DateTime<Utc>>) {
    if !enabled {
        return ("disabled", f.last_success_at);
    }
    match f.last_success_at {
        None => ("never", None),
        Some(t) if f.consecutive_failures > 0 || now - t > max_age => ("stale", Some(t)),
        Some(_) => ("ok", None),
    }
}

pub async fn list(_: Admin, State(st): State<AppState>) -> ApiResult<Json<Vec<FeedRow>>> {
    let sources = sources::list(&st).await?;
    let rows: Vec<FeedDb> = sqlx::query_as(
        "SELECT source, last_attempt_at, last_success_at, last_error, last_error_at, consecutive_failures FROM feed_state",
    )
    .fetch_all(&st.pool)
    .await?;
    let now = Utc::now();
    let default = st.cfg.cve.interval_minutes as i64;
    let mut out = Vec::new();
    for src in sources {
        let f = rows.iter().find(|r| r.source == src.name);
        let empty = FeedDb {
            source: src.name.clone(),
            last_attempt_at: None,
            last_success_at: None,
            last_error: None,
            last_error_at: None,
            consecutive_failures: 0,
        };
        let f = f.unwrap_or(&empty);
        let interval = crate::schedule::feed_interval_minutes(&st.pool, &src.name, default).await;
        // Ohne Erfolg seit 3 Intervallen gilt ein Feed auch dann als veraltet, wenn kein Fehler gespeichert wurde.
        let (state, stale_since) = classify(f, src.enabled, now, Duration::minutes(3 * interval));
        out.push(FeedRow {
            kind: if sources::is_builtin(&src.name) {
                "builtin"
            } else {
                "managed"
            },
            enabled: src.enabled,
            configured: src.enabled,
            enrich_only: sources::enrich_only(&src.name),
            takes_secret: sources::takes_secret(&src.name),
            takes_base_url: sources::takes_base_url(&src.name),
            secret_set: src.secret_set,
            base_url: src.base_url.clone(),
            interval_minutes: interval,
            healthy: state == "ok",
            state,
            stale_since,
            last_attempt_at: f.last_attempt_at,
            last_success_at: f.last_success_at,
            last_error: f.last_error.clone(),
            last_error_at: f.last_error_at,
            consecutive_failures: f.consecutive_failures,
            source: src.name,
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBody {
    name: String,
    base_url: Option<String>,
    secret: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateBody {
    enabled: Option<bool>,
    base_url: Option<String>,
    clear_base_url: Option<bool>,
    secret: Option<String>,
    clear_secret: Option<bool>,
}

const MAX_SECRET_LEN: usize = 512;

fn check_secret(name: &str, secret: &str) -> ApiResult<()> {
    if !sources::takes_secret(name) {
        return Err(ApiError::BadRequest(
            "Diese Quelle nimmt keinen Schlüssel an".into(),
        ));
    }
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN || secret.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "Schlüssel ist leer, zu lang oder enthält Steuerzeichen".into(),
        ));
    }
    Ok(())
}

async fn check_url(st: &AppState, name: &str, url: &str) -> ApiResult<()> {
    if !sources::takes_base_url(name) {
        return Err(ApiError::BadRequest(
            "Für diese Quelle ist keine eigene URL möglich".into(),
        ));
    }
    sources::check_base_url(st, url)
        .await
        .map(|_| ())
        .map_err(ApiError::BadRequest)
}

/// Nach Änderungen, die die Bewertung betreffen (Quelle an/aus/entfernt), alle Hosts im Hintergrund neu bewerten.
fn reevaluate_in_background(st: &AppState) {
    let st = st.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::cve::reeval::reevaluate_all(&st).await {
            tracing::error!(error = %e, "Neubewertung nach Quellenänderung fehlgeschlagen");
        }
    });
}

/// Quelle hinzufügen (nur bekannte Typen, keine freien URLs).
pub async fn create(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Json(b): Json<CreateBody>,
) -> ApiResult<StatusCode> {
    if !sources::is_known(&b.name) {
        return Err(ApiError::BadRequest(
            "Unbekannter Quellentyp (erlaubt: osv, nvd, cisa_kev)".into(),
        ));
    }
    if let Some(u) = &b.base_url {
        check_url(&st, &b.name, u).await?;
    }
    let secret = match &b.secret {
        Some(sec) => {
            check_secret(&b.name, sec)?;
            Some(
                sources::encrypt_secret(&st, &b.name, sec)
                    .await
                    .map_err(ApiError::BadRequest)?,
            )
        }
        None => None,
    };
    let done = sqlx::query("INSERT INTO cve_sources (name, base_url, secret) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(&b.name)
        .bind(&b.base_url)
        .bind(secret)
        .execute(&st.pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::Conflict("Die Quelle gibt es schon".into()));
    }
    Ok(StatusCode::CREATED)
}

pub async fn update(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(name): Path<String>,
    Json(b): Json<UpdateBody>,
) -> ApiResult<StatusCode> {
    if !sources::is_known(&name) {
        return Err(ApiError::NotFound);
    }
    if let Some(u) = &b.base_url {
        check_url(&st, &name, u).await?;
    }
    let secret = match &b.secret {
        Some(sec) => {
            check_secret(&name, sec)?;
            Some(
                sources::encrypt_secret(&st, &name, sec)
                    .await
                    .map_err(ApiError::BadRequest)?,
            )
        }
        None => None,
    };
    let mut tx = st.pool.begin().await?;
    let exists: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM cve_sources WHERE name = $1 FOR UPDATE")
            .bind(&name)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(was_enabled) = exists else {
        return Err(ApiError::NotFound);
    };
    if let Some(en) = b.enabled {
        sqlx::query("UPDATE cve_sources SET enabled = $2, updated_at = now() WHERE name = $1")
            .bind(&name)
            .bind(en)
            .execute(&mut *tx)
            .await?;
    }
    if b.clear_base_url == Some(true) {
        sqlx::query("UPDATE cve_sources SET base_url = NULL, updated_at = now() WHERE name = $1")
            .bind(&name)
            .execute(&mut *tx)
            .await?;
    } else if let Some(u) = &b.base_url {
        sqlx::query("UPDATE cve_sources SET base_url = $2, updated_at = now() WHERE name = $1")
            .bind(&name)
            .bind(u)
            .execute(&mut *tx)
            .await?;
    }
    if b.clear_secret == Some(true) {
        sqlx::query("UPDATE cve_sources SET secret = NULL, updated_at = now() WHERE name = $1")
            .bind(&name)
            .execute(&mut *tx)
            .await?;
    } else if let Some(blob) = secret {
        sqlx::query("UPDATE cve_sources SET secret = $2, updated_at = now() WHERE name = $1")
            .bind(&name)
            .bind(blob)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    if b.enabled.is_some_and(|en| en != was_enabled) {
        reevaluate_in_background(&st);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Entfernt eine hinzugefügte Quelle samt ihrer Daten (sie zählen sonst weiter in der Bewertung). Eingebaute lassen sich nur abschalten.
pub async fn delete(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    if sources::is_builtin(&name) {
        return Err(ApiError::BadRequest(
            "Eingebaute Quellen lassen sich nur abschalten".into(),
        ));
    }
    let mut tx = st.pool.begin().await?;
    let gone = sqlx::query("DELETE FROM cve_sources WHERE name = $1")
        .bind(&name)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 0 {
        return Err(ApiError::NotFound);
    }
    sqlx::query("DELETE FROM cve_source_status WHERE source = $1")
        .bind(&name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM feed_state WHERE source = $1")
        .bind(&name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    reevaluate_in_background(&st);
    Ok(StatusCode::NO_CONTENT)
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
        assert_eq!(classify(&f, true, now, max).0, "never");
        let (f, now) = feed(Some(1), 0);
        assert_eq!(classify(&f, true, now, max).0, "ok");
        // Letzter Abruf fehlgeschlagen: stale seit dem letzten Erfolg.
        let (f, now) = feed(Some(1), 1);
        let (state, since) = classify(&f, true, now, max);
        assert_eq!(state, "stale");
        assert_eq!(since, f.last_success_at);
        // Kein Fehler gespeichert, aber seit Stunden kein Erfolg (z. B. Scheduler hängt).
        let (f, now) = feed(Some(5), 0);
        assert_eq!(classify(&f, true, now, max).0, "stale");
        assert_eq!(
            classify(&f, false, now, max).0,
            "disabled",
            "abgeschaltet ist nie ok"
        );
    }
}
