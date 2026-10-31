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
    /// Stabile ID der Quelle (nicht der Anzeigename).
    source: String,
    /// Typ der Quelle: debian, ubuntu, osv, nvd, cisa_kev.
    #[serde(rename = "type")]
    kind_type: String,
    /// Anzeigename (frei wählbar, eindeutig).
    label: String,
    ecosystem: Option<String>,
    takes_ecosystem: bool,
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
        let f = rows.iter().find(|r| r.source == src.id);
        let empty = FeedDb {
            source: src.id.clone(),
            last_attempt_at: None,
            last_success_at: None,
            last_error: None,
            last_error_at: None,
            consecutive_failures: 0,
        };
        let f = f.unwrap_or(&empty);
        let interval = crate::schedule::feed_interval_minutes(&st.pool, &src.id, default).await;
        // Ohne Erfolg seit 3 Intervallen gilt ein Feed auch dann als veraltet, wenn kein Fehler gespeichert wurde.
        let (state, stale_since) = classify(f, src.enabled, now, Duration::minutes(3 * interval));
        out.push(FeedRow {
            kind_type: src.kind.clone(),
            label: src.label.clone(),
            ecosystem: src.ecosystem.clone(),
            takes_ecosystem: sources::takes_ecosystem(&src.kind),
            kind: if sources::is_builtin(&src.kind) {
                "builtin"
            } else {
                "managed"
            },
            enabled: src.enabled,
            configured: src.enabled,
            enrich_only: sources::enrich_only(&src.kind),
            takes_secret: sources::takes_secret(&src.kind),
            takes_base_url: sources::takes_base_url(&src.kind),
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
            source: src.id,
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBody {
    #[serde(rename = "type")]
    kind: String,
    /// Anzeigename; ohne Angabe der Name des Typs.
    label: Option<String>,
    base_url: Option<String>,
    ecosystem: Option<String>,
    secret: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateBody {
    enabled: Option<bool>,
    label: Option<String>,
    base_url: Option<String>,
    clear_base_url: Option<bool>,
    ecosystem: Option<String>,
    clear_ecosystem: Option<bool>,
    secret: Option<String>,
    clear_secret: Option<bool>,
}

const MAX_SECRET_LEN: usize = 512;
const MAX_LABEL_CHARS: usize = 40;

fn check_secret(kind: &str, secret: &str) -> ApiResult<()> {
    if !sources::takes_secret(kind) {
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

/// Anzeigename: 1 bis 40 Zeichen, keine Steuerzeichen. Die Anzeige im UI escaped den Text (React), der Server speichert ihn unverändert.
fn check_label(raw: &str) -> ApiResult<String> {
    let label = raw.trim();
    let n = label.chars().count();
    if n == 0 || n > MAX_LABEL_CHARS {
        return Err(ApiError::BadRequest(format!(
            "Name: 1 bis {MAX_LABEL_CHARS} Zeichen"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "Name: keine Steuerzeichen oder Zeilenumbrüche".into(),
        ));
    }
    Ok(label.to_owned())
}

fn check_ecosystem(kind: &str, eco: &str) -> ApiResult<String> {
    if !sources::takes_ecosystem(kind) {
        return Err(ApiError::BadRequest("Nur OSV kennt ein Ökosystem".into()));
    }
    let eco = eco.trim();
    if eco.is_empty()
        || eco.len() > 40
        || !eco
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".:_-".contains(c))
    {
        return Err(ApiError::BadRequest(
            "Ökosystem: z. B. Debian:13 oder Ubuntu:24.04".into(),
        ));
    }
    Ok(eco.to_owned())
}

async fn check_url(st: &AppState, kind: &str, url: &str) -> ApiResult<()> {
    if let Some(problem) = sources::url_problem(kind, url) {
        return Err(ApiError::BadRequest(problem));
    }
    if !sources::takes_base_url(kind) {
        return Err(ApiError::BadRequest(format!(
            "Für den Typ {} ist keine eigene Adresse möglich",
            sources::kind_title(kind)
        )));
    }
    sources::check_base_url(st, url)
        .await
        .map(|_| ())
        .map_err(ApiError::BadRequest)
}

/// Eindeutigkeitsverletzungen der Tabelle in verständliche Fehler übersetzen (auch bei gleichzeitigem Doppelklick).
fn map_unique(e: sqlx::Error) -> ApiError {
    let constraint = e
        .as_database_error()
        .and_then(|d| d.constraint())
        .map(str::to_owned);
    match constraint.as_deref() {
        Some("cve_sources_label_uq") => ApiError::Conflict("Name bereits vergeben".into()),
        Some("cve_sources_config_uq") => ApiError::Conflict(
            "Eine Quelle dieses Typs mit gleicher Konfiguration gibt es schon".into(),
        ),
        _ => e.into(),
    }
}

/// Nach Änderungen, die die Bewertung betreffen (Quelle an/aus/gelöscht/neu), alle Hosts im Hintergrund neu bewerten.
fn reevaluate_in_background(st: &AppState) {
    let st = st.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::cve::reeval::reevaluate_all(&st).await {
            tracing::error!(error = %e, "Neubewertung nach Quellenänderung fehlgeschlagen");
        }
    });
}

/// Quelle hinzufügen (nur bekannte Typen). Alles wird vor dem Speichern geprüft, gespeichert wird mit einem einzigen
/// INSERT: bei einem Fehler entsteht nichts, ein gleichzeitiger Doppelversand scheitert am Unique-Index.
pub async fn create(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Json(b): Json<CreateBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if !sources::is_known(&b.kind) {
        return Err(ApiError::BadRequest(
            "Unbekannter Quellentyp (erlaubt: debian, ubuntu, osv, nvd, cisa_kev)".into(),
        ));
    }
    sources::ensure_seeded(&st).await?;
    let label = check_label(b.label.as_deref().unwrap_or(sources::kind_title(&b.kind)))?;
    let base_url = b
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());
    if let Some(u) = base_url {
        check_url(&st, &b.kind, u).await?;
    }
    let ecosystem = match b
        .ecosystem
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        Some(e) => Some(check_ecosystem(&b.kind, e)?),
        None => None,
    };
    let id = sources::new_id(&b.kind);
    let secret = match &b.secret {
        Some(sec) => {
            check_secret(&b.kind, sec)?;
            Some(
                sources::encrypt_secret(&st, &id, sec)
                    .await
                    .map_err(ApiError::BadRequest)?,
            )
        }
        None => None,
    };
    sqlx::query("INSERT INTO cve_sources (id, kind, label, base_url, ecosystem, secret) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(&id)
        .bind(&b.kind)
        .bind(&label)
        .bind(base_url)
        .bind(&ecosystem)
        .bind(secret)
        .execute(&st.pool)
        .await
        .map_err(map_unique)?;
    // Ein Debian-/Ubuntu-Host ohne Quelle war "CVE-Lage unbekannt": mit der neuen Quelle neu bewerten.
    reevaluate_in_background(&st);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "label": label })),
    ))
}

pub async fn update(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<UpdateBody>,
) -> ApiResult<StatusCode> {
    let kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM cve_sources WHERE id = $1 AND deleted_at IS NULL")
            .bind(&id)
            .fetch_optional(&st.pool)
            .await?;
    let Some(kind) = kind else {
        return Err(ApiError::NotFound);
    };
    let label = match &b.label {
        Some(l) => Some(check_label(l)?),
        None => None,
    };
    if let Some(u) = &b.base_url {
        check_url(&st, &kind, u.trim()).await?;
    }
    let ecosystem = match &b.ecosystem {
        Some(e) => Some(check_ecosystem(&kind, e)?),
        None => None,
    };
    let secret = match &b.secret {
        Some(sec) => {
            check_secret(&kind, sec)?;
            Some(
                sources::encrypt_secret(&st, &id, sec)
                    .await
                    .map_err(ApiError::BadRequest)?,
            )
        }
        None => None,
    };
    let mut tx = st.pool.begin().await?;
    let exists: Option<bool> = sqlx::query_scalar(
        "SELECT enabled FROM cve_sources WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(was_enabled) = exists else {
        return Err(ApiError::NotFound);
    };
    if let Some(en) = b.enabled {
        sqlx::query("UPDATE cve_sources SET enabled = $2, updated_at = now() WHERE id = $1")
            .bind(&id)
            .bind(en)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(l) = &label {
        sqlx::query("UPDATE cve_sources SET label = $2, updated_at = now() WHERE id = $1")
            .bind(&id)
            .bind(l)
            .execute(&mut *tx)
            .await
            .map_err(map_unique)?;
    }
    if b.clear_base_url == Some(true) {
        sqlx::query("UPDATE cve_sources SET base_url = NULL, updated_at = now() WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(map_unique)?;
    } else if let Some(u) = &b.base_url {
        sqlx::query("UPDATE cve_sources SET base_url = $2, updated_at = now() WHERE id = $1")
            .bind(&id)
            .bind(u.trim())
            .execute(&mut *tx)
            .await
            .map_err(map_unique)?;
    }
    if b.clear_ecosystem == Some(true) {
        sqlx::query("UPDATE cve_sources SET ecosystem = NULL, updated_at = now() WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(map_unique)?;
    } else if let Some(e) = &ecosystem {
        sqlx::query("UPDATE cve_sources SET ecosystem = $2, updated_at = now() WHERE id = $1")
            .bind(&id)
            .bind(e)
            .execute(&mut *tx)
            .await
            .map_err(map_unique)?;
    }
    if b.clear_secret == Some(true) {
        sqlx::query("UPDATE cve_sources SET secret = NULL, updated_at = now() WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    } else if let Some(blob) = secret {
        sqlx::query("UPDATE cve_sources SET secret = $2, updated_at = now() WHERE id = $1")
            .bind(&id)
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

/// Löscht eine Quelle (auch Debian/Ubuntu). Ihre Daten bleiben 30 Tage liegen, zählen aber nicht mehr als aktuell
/// (Hosts ohne aktive Quelle für ihre Distribution werden "CVE-Lage unbekannt"); danach räumt der Cleanup-Job auf.
/// Das Geheimnis wird sofort verworfen. Wieder hinzufügen geht jederzeit.
pub async fn delete(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let gone = sqlx::query(
        "UPDATE cve_sources SET deleted_at = now(), secret = NULL, updated_at = now() WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(&id)
    .execute(&st.pool)
    .await?
    .rows_affected();
    if gone == 0 {
        return Err(ApiError::NotFound);
    }
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
