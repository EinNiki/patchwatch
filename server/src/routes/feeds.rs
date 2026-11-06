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
    /// Offener Rückstandsabbau (siehe `cve::Backfill`).
    backfill: Option<Value>,
    /// Fehlläufe in Folge (Wiederholungsleiter) und frühester nächster Versuch danach.
    retry_step: i32,
    next_attempt_at: Option<DateTime<Utc>>,
    /// Hybridquelle (Ubuntu): Massendaten je Release und stündlicher Abruf (siehe `cve::Bulk`).
    bulk: Option<Value>,
}

/// Fortschritt eines Rückstandsabbaus oder Erstabrufs für die Feed-Tabelle.
#[derive(Serialize)]
pub struct BackfillView {
    /// Erstabruf (noch nie vollständig) statt Aufholen nach einem bestätigten Cursor.
    initial: bool,
    pages_done: u32,
    runs: u32,
    next_offset: u32,
    /// Position in der Liste in Seiten (ohne Überlappung) und geschätzte Gesamtzahl bis zum Ziel.
    position_pages: u32,
    est_pages: Option<u32>,
    /// Seitenlimit je Lauf (nur Quellen mit Cursor-Paginierung).
    pages_per_run: Option<u32>,
    /// Horizont des Erstabrufs bzw. der alte Cursor, bis zu dem noch gelesen werden muss.
    target: String,
    since: DateTime<Utc>,
    /// Fertiger Text für die Anzeige.
    progress: String,
}

fn backfill_view(raw: &Value, pages_per_run: Option<u32>) -> Option<BackfillView> {
    let b: crate::cve::Backfill = serde_json::from_value(raw.clone()).ok()?;
    let per = pages_per_run.map_or(String::new(), |n| format!(", bis zu {n} Seiten pro Lauf"));
    let position = b.next_offset / crate::cve::ubuntu::PAGE as u32;
    let runs = format!("{} {}", b.runs, if b.runs == 1 { "Lauf" } else { "Läufe" });
    let progress = if b.initial {
        // Die Gesamtzahl ist nur eine Schätzung (die Liste ändert sich laufend) und so gekennzeichnet.
        let of = b
            .est_pages
            .map_or(format!("Seite {position} (Gesamtzahl unbekannt)"), |m| {
                format!("Seite {position} von etwa {m} (Schätzung)")
            });
        let horizon = if b.target.starts_with("1970") {
            "gesamte Liste".to_owned()
        } else {
            format!("Horizont ab {}", b.target.get(..10).unwrap_or(&b.target))
        };
        format!("Erstabruf läuft: {of}; {horizon}; {runs} seit Beginn{per}")
    } else {
        format!(
            "Rückstand wird abgebaut: {} Seiten in {} geladen{per}",
            b.pages_done, runs
        )
    };
    Some(BackfillView {
        initial: b.initial,
        pages_done: b.pages_done,
        runs: b.runs,
        next_offset: b.next_offset,
        position_pages: position,
        est_pages: b.est_pages,
        pages_per_run,
        target: b.target,
        since: b.started_at,
        progress,
    })
}

/// Eine Massendatei (ein Release) für die Feed-Tabelle.
#[derive(Serialize)]
pub struct BulkReleaseView {
    release: String,
    /// `ok` (gültig und frisch), `error` (letzter Import fehlgeschlagen), `stale` (Frist überschritten) oder `pending`.
    state: &'static str,
    /// Fertiger Text: "importiert", "unverändert (304)" oder der Fehler.
    result_text: String,
    imported_at: Option<DateTime<Utc>>,
    verified_at: Option<DateTime<Utc>>,
    bytes: Option<u64>,
    records: Option<u32>,
    status: Option<u16>,
    retry_after_secs: Option<u64>,
    next_attempt_at: Option<DateTime<Utc>>,
    fresh_until: Option<DateTime<Utc>>,
}

/// Der stündliche Abruf der ersten Seiten von `cves.json`.
#[derive(Serialize)]
pub struct HourlyView {
    last_run_at: Option<DateTime<Utc>>,
    last_ok_at: Option<DateTime<Utc>>,
    page_size: u32,
    max_page: Option<u32>,
    pages_last: u32,
    failures: u32,
    status: Option<u16>,
    retry_after_secs: Option<u64>,
    error_text: Option<String>,
    next_attempt_at: Option<DateTime<Utc>>,
    /// Hinweis bei dauerhaftem 503/504.
    hint: Option<String>,
}

/// Anzeige der Hybridquelle: Massendaten je Release und stündlicher Abruf.
#[derive(Serialize)]
pub struct BulkView {
    /// Alle relevanten Releases haben einen gültigen, frischen Import (Voraussetzung für "ok").
    complete: bool,
    bulk_interval_minutes: i64,
    releases: Vec<BulkReleaseView>,
    hourly: HourlyView,
}

fn bulk_view(
    raw: &Value,
    label: &str,
    now: DateTime<Utc>,
    hourly_next: Option<DateTime<Utc>>,
    bulk_interval_minutes: i64,
) -> Option<BulkView> {
    let b: crate::cve::Bulk = serde_json::from_value(raw.clone()).ok()?;
    let releases = b
        .relevant
        .iter()
        .map(|r| {
            let e = b.releases.get(r).cloned().unwrap_or_default();
            let fresh_until = b.ok.get(r).copied();
            let (state, result_text) = match (e.last_result.as_str(), fresh_until) {
                ("error", _) => (
                    "error",
                    plain_error(
                        e.last_error.as_deref().unwrap_or("Fehler"),
                        label,
                        e.next_attempt_at.map(|n| n - now),
                    ),
                ),
                (_, Some(_)) if e.last_result == "not_modified" => {
                    ("ok", "unverändert (304)".to_owned())
                }
                (_, Some(_)) => ("ok", "importiert".to_owned()),
                ("", None) => ("pending", "noch nicht importiert".to_owned()),
                (_, None) => ("stale", "Frist überschritten, Daten veraltet".to_owned()),
            };
            BulkReleaseView {
                release: r.clone(),
                state,
                result_text,
                imported_at: e.imported_at,
                verified_at: e.verified_at,
                bytes: e.bytes,
                records: e.records,
                status: e.last_status,
                retry_after_secs: e.retry_after_secs,
                next_attempt_at: e.next_attempt_at,
                fresh_until,
            }
        })
        .collect();
    let i = &b.incr;
    let persistent = i.failures >= 3 && matches!(i.last_status, Some(503 | 504));
    let hourly = HourlyView {
        last_run_at: i.last_run_at,
        last_ok_at: i.last_ok_at,
        page_size: i.page_size,
        max_page: i.max_page,
        pages_last: i.pages_last,
        failures: i.failures,
        status: i.last_status,
        retry_after_secs: i.retry_after_secs,
        error_text: i
            .last_error
            .as_deref()
            .map(|e| plain_error(e, label, hourly_next.map(|n| n - now))),
        next_attempt_at: hourly_next,
        hint: persistent.then(|| {
            format!(
                "Die Ubuntu-API antwortet seit {} Läufen mit 503/504 (überlastet). Behoben-Daten kommen weiter aus den Massendateien; offene Fälle werden verzögert nachgeführt.",
                i.failures
            )
        }),
    };
    Some(BulkView {
        complete: b.complete,
        bulk_interval_minutes,
        releases,
        hourly,
    })
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
    /// `ok`, `stale` (Fehler oder zu lange kein Erfolg), `incomplete` (Rückstand wird abgebaut, Daten noch
    /// lückenhaft), `never` (noch nie erfolgreich) oder `disabled` (abgeschaltet).
    state: &'static str,
    healthy: bool,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    /// Seit wann die Daten dieser Quelle veraltet sind (= letzter erfolgreicher Abruf).
    stale_since: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
    consecutive_failures: i32,
    /// Fehlläufe in Folge (setzt sich mit dem nächsten erfolgreichen Lauf zurück).
    failed_runs: i32,
    /// Wann der nächste Abruf frühestens stattfindet (nach Fehllauf: Wiederholungsleiter).
    next_attempt_at: Option<DateTime<Utc>>,
    /// Letzter Fehler in verständlichem Text, bei Bedarf mit dem nächsten Versuch.
    error_text: Option<String>,
    /// Fortschritt, solange der Feed unvollständig ist.
    backfill: Option<BackfillView>,
    /// Nur Ubuntu im Hybridmodus: Massendaten je Release und stündlicher Abruf.
    bulk: Option<BulkView>,
}

/// Fehlertext für Menschen: was die Quelle gemeldet hat und wann es weitergeht.
fn plain_error(raw: &str, label: &str, next_in: Option<Duration>) -> String {
    let m = raw.strip_prefix("Lauf unterbrochen: ").unwrap_or(raw);
    let what = if m == "HTTP 429" {
        format!("{label} drosselt (429, zu viele Anfragen)")
    } else if let Some(code) = m.strip_prefix("HTTP ") {
        format!("{label} meldet {code}")
    } else if m.starts_with("Netzwerkfehler") {
        format!("Verbindung zu {label} fehlgeschlagen")
    } else if m.starts_with("Lauf ohne Fortschritt") {
        format!("Abruf von {label} hing und wurde abgebrochen")
    } else {
        m.to_owned()
    };
    let interrupted = if raw.starts_with("Lauf unterbrochen: ") {
        ", Lauf unterbrochen (bisherige Seiten bleiben gespeichert)"
    } else {
        ""
    };
    match next_in {
        Some(d) if d >= Duration::minutes(1) => {
            let n = (d.num_seconds() + 59) / 60;
            format!(
                "{what}{interrupted}, nächster Versuch in {n} {}",
                if n == 1 { "Minute" } else { "Minuten" }
            )
        }
        Some(_) => format!("{what}{interrupted}, nächster Versuch gleich"),
        None => format!("{what}{interrupted}"),
    }
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
    // Offene Lücke: die Daten sind lückenhaft, auch wenn der letzte Lauf Fortschritt brachte. Nie "ok".
    if f.backfill.is_some() {
        return ("incomplete", f.last_success_at);
    }
    // Hybridquelle: "ok" nur, wenn alle relevanten Releases gültige, frische Massendaten haben und die offenen Fälle
    // (stündlicher Abruf) nicht dauerhaft ausbleiben.
    if let Some(b) = f
        .bulk
        .as_ref()
        .and_then(|v| serde_json::from_value::<crate::cve::Bulk>(v.clone()).ok())
    {
        let hourly_broken = b.incr.failures >= 3;
        if !b.complete || b.ok.values().any(|u| *u <= now) || hourly_broken {
            return ("incomplete", f.last_success_at);
        }
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
        "SELECT source, last_attempt_at, last_success_at, last_error, last_error_at, consecutive_failures, backfill, retry_step, next_attempt_at, bulk FROM feed_state",
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
            backfill: None,
            retry_step: 0,
            next_attempt_at: None,
            bulk: None,
        };
        let f = f.unwrap_or(&empty);
        let interval = crate::schedule::feed_interval_minutes(&st.pool, &src.id, default).await;
        // Ohne Erfolg seit 3 Intervallen gilt ein Feed auch dann als veraltet, wenn kein Fehler gespeichert wurde.
        let (state, stale_since) = classify(f, src.enabled, now, Duration::minutes(3 * interval));
        // Nächster Versuch: nach einem Fehllauf die Leiter, sonst letzter Versuch + Intervall (höchstens so lange).
        let by_interval = f.last_attempt_at.map(|t| t + Duration::minutes(interval));
        let next_attempt_at = if src.enabled {
            match (f.next_attempt_at, by_interval) {
                (Some(n), Some(i)) => Some(n.min(i)),
                (n, i) => n.or(i),
            }
        } else {
            None
        };
        let bulk_every = crate::schedule::bulk_interval_minutes(
            &st.pool,
            &src.id,
            st.cfg.cve.ubuntu_bulk_interval_minutes as i64,
        )
        .await;
        let error_text = f
            .last_error
            .as_deref()
            .map(|e| plain_error(e, &src.label, next_attempt_at.map(|n| n - now)));
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
            failed_runs: f.retry_step,
            next_attempt_at,
            error_text,
            backfill: f.backfill.as_ref().and_then(|b| {
                backfill_view(
                    b,
                    (src.kind == "ubuntu").then_some(st.cfg.cve.ubuntu_max_pages),
                )
            }),
            bulk: f
                .bulk
                .as_ref()
                .and_then(|b| bulk_view(b, &src.label, now, by_interval, bulk_every)),
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
                refresh::Outcome::Incomplete { changed_rows, events } => json!({ "source": source, "result": "incomplete", "changed_rows": changed_rows, "events": events }),
                refresh::Outcome::Failed(e) => json!({ "source": source, "result": "failed", "error": e }),
                refresh::Outcome::Skipped => json!({ "source": source, "result": "skipped" }),
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
                backfill: None,
                retry_step: 0,
                next_attempt_at: None,
                bulk: None,
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
        // Offene Lücke (Rückstandsabbau): nie "ok" -- auch nicht, wenn der letzte Lauf Fortschritt brachte,
        // kein Fehler gespeichert ist und der letzte Erfolg erst eine Stunde zurückliegt, oder es noch gar keinen gab.
        let marker = Some(json!({}));
        let (mut f, now) = feed(Some(1), 0);
        f.backfill = marker.clone();
        let (state, since) = classify(&f, true, now, max);
        assert_eq!(state, "incomplete");
        assert_eq!(since, f.last_success_at);
        let (mut f, now) = feed(None, 0);
        f.backfill = marker;
        assert_eq!(classify(&f, true, now, max).0, "incomplete");
        assert_eq!(classify(&f, false, now, max).0, "disabled");
    }

    #[test]
    fn plain_error_text_names_source_status_and_next_attempt() {
        let m =
            |raw: &str, mins: Option<i64>| plain_error(raw, "Ubuntu", mins.map(Duration::minutes));
        assert_eq!(
            m("HTTP 503", Some(12)),
            "Ubuntu meldet 503, nächster Versuch in 12 Minuten"
        );
        assert_eq!(
            m("HTTP 429", Some(1)),
            "Ubuntu drosselt (429, zu viele Anfragen), nächster Versuch in 1 Minute"
        );
        assert!(m("Lauf unterbrochen: HTTP 503", Some(2)).contains("Lauf unterbrochen"));
        assert!(
            m("Netzwerkfehler: timeout", None).starts_with("Verbindung zu Ubuntu fehlgeschlagen")
        );
        assert!(m("HTTP 503", Some(0)).ends_with("nächster Versuch gleich"));
        assert!(m("Lauf ohne Fortschritt seit 30 Minuten abgebrochen", None).contains("hing"));
    }
}
