use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::security;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const HOST_SELECT: &str = "SELECT h.id, h.name, h.hostname, h.os_id, h.os_version, h.os_codename, h.pretty_name, \
    h.running_kernel, h.kernel_package, h.kernel_package_version, h.newest_kernel, h.newest_kernel_version, \
    h.reboot_needed_kernel, h.reboot_required_file, \
    (COALESCE(h.reboot_required_file, false) OR COALESCE(h.reboot_needed_kernel, false)) AS reboot_needed, \
    h.updates_pending, h.updates_security, h.uptime_seconds, h.is_proxmox, h.proxmox_version, \
    h.status, h.status_changed_at, h.last_report_at, h.created_at, \
    h.agent_version, h.last_checkin_at, h.report_requested_at, \
    COALESCE(c.vulnerable, 0) AS cve_vulnerable, COALESCE(c.fix_pending, 0) AS cve_fix_pending, \
    COALESCE(c.unknown, 0) AS cve_unknown \
    FROM hosts h LEFT JOIN LATERAL ( \
        SELECT count(*) FILTER (WHERE status = 'vulnerable') AS vulnerable, \
               count(*) FILTER (WHERE status = 'fix_pending') AS fix_pending, \
               count(*) FILTER (WHERE status = 'unknown') AS unknown \
        FROM host_cve_status WHERE host_id = h.id) c ON true";

/// Offene Paket-Updates laut letztem Report; `{"items": null}`, wenn der Agent noch keine Liste mitschickt.
pub async fn updates(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let row: Option<(Option<Value>,)> =
        sqlx::query_as("SELECT updates_list FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let (list,) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "items": list })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct HostRow {
    id: i64,
    name: String,
    hostname: Option<String>,
    os_id: Option<String>,
    os_version: Option<String>,
    os_codename: Option<String>,
    pretty_name: Option<String>,
    running_kernel: Option<String>,
    kernel_package: Option<String>,
    kernel_package_version: Option<String>,
    newest_kernel: Option<String>,
    newest_kernel_version: Option<String>,
    reboot_needed_kernel: Option<bool>,
    reboot_required_file: Option<bool>,
    reboot_needed: bool,
    updates_pending: Option<i32>,
    updates_security: Option<i32>,
    uptime_seconds: Option<i64>,
    is_proxmox: bool,
    proxmox_version: Option<String>,
    status: String,
    status_changed_at: Option<DateTime<Utc>>,
    last_report_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    agent_version: Option<String>,
    last_checkin_at: Option<DateTime<Utc>>,
    report_requested_at: Option<DateTime<Utc>>,
    cve_vulnerable: i64,
    cve_fix_pending: i64,
    cve_unknown: i64,
}

pub async fn list(_: Admin, State(st): State<AppState>) -> ApiResult<Json<Vec<HostRow>>> {
    let rows = sqlx::query_as::<_, HostRow>(&format!("{HOST_SELECT} ORDER BY h.name"))
        .fetch_all(&st.pool)
        .await?;
    Ok(Json(rows))
}

pub async fn detail(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<HostRow>> {
    sqlx::query_as::<_, HostRow>(&format!("{HOST_SELECT} WHERE h.id = $1"))
        .bind(id)
        .fetch_optional(&st.pool)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct HistoryRow {
    id: i64,
    received_at: DateTime<Utc>,
    running_kernel: Option<String>,
    updates_pending: Option<i32>,
    updates_security: Option<i32>,
    reboot_needed: bool,
    status: String,
}

pub async fn history(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult<Json<Vec<HistoryRow>>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let rows = sqlx::query_as::<_, HistoryRow>(
        "SELECT id, received_at, running_kernel, updates_pending, updates_security, reboot_needed, status \
         FROM reports WHERE host_id = $1 ORDER BY received_at DESC LIMIT $2",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct HostCveRow {
    cve_id: String,
    status: String,
    reason: String,
    computed_at: DateTime<Utc>,
    sources: Value,
    description: Option<String>,
    priority: Option<String>,
    watched: bool,
    /// Manuelle Prüfung (z. B. Proxmox); gilt nur für den Kernel, bei dem sie gesetzt wurde.
    reviewed_at: Option<DateTime<Utc>>,
    reviewed_by: Option<String>,
    /// Priorität als Stufe 0–10 (0 = unbekannt).
    #[sqlx(skip)]
    level: u8,
}

#[derive(Deserialize)]
pub struct CvesQuery {
    limit: Option<i64>,
}

/// CVE-Bewertungen eines Hosts, dringlichste zuerst (verwundbar, Neustart nötig, Fix angekündigt, unbekannt …).
/// Die Sortierung erfolgt vor dem Limit, damit bei sehr vielen Zeilen nie kritische abgeschnitten werden.
pub async fn cves(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<CvesQuery>,
) -> ApiResult<Json<Vec<HostCveRow>>> {
    let limit = q.limit.unwrap_or(500).clamp(1, 5000);
    let rows = sqlx::query_as::<_, HostCveRow>(
        "SELECT s.cve_id, s.status, s.reason, s.computed_at, s.sources, c.description, c.priority, \
                (w.cve_id IS NOT NULL) AS watched, m.reviewed_at, m.reviewed_by \
         FROM host_cve_status s JOIN cves c ON c.id = s.cve_id JOIN hosts h ON h.id = s.host_id \
         LEFT JOIN cve_watchlist w ON w.cve_id = s.cve_id \
         LEFT JOIN manual_reviews m ON m.host_id = s.host_id AND m.cve_id = s.cve_id AND m.kernel_version = h.running_kernel \
         WHERE s.host_id = $1 \
         ORDER BY CASE s.status WHEN 'vulnerable' THEN 0 WHEN 'fixed_installed_reboot_required' THEN 1 \
                                WHEN 'fix_pending' THEN 2 WHEN 'unknown' THEN 3 ELSE 4 END, \
                  (w.cve_id IS NOT NULL) DESC, s.cve_id DESC \
         LIMIT $2",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(&st.pool)
    .await?;
    let rows = rows
        .into_iter()
        .map(|mut r| {
            r.level = super::cves::priority_level(r.priority.as_deref());
            r
        })
        .collect();
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct NewHost {
    name: String,
}

fn valid_host_name(n: &str) -> bool {
    (1..=63).contains(&n.len())
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// Legt einen Host an; der Token wird nur hier einmalig im Klartext zurückgegeben.
pub async fn create(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Json(body): Json<NewHost>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if !valid_host_name(&body.name) {
        return Err(ApiError::BadRequest(
            "Name: 1–63 Zeichen aus A–Z, a–z, 0–9, '.', '_', '-'".into(),
        ));
    }
    let token = security::new_agent_token();
    let row: Result<(i64,), sqlx::Error> =
        sqlx::query_as("INSERT INTO hosts (name, token_hash) VALUES ($1, $2) RETURNING id")
            .bind(&body.name)
            .bind(security::sha256(&token))
            .fetch_one(&st.pool)
            .await;
    match row {
        Ok((id,)) => Ok((
            StatusCode::CREATED,
            Json(json!({ "id": id, "name": body.name, "token": token })),
        )),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(ApiError::Conflict(
            "Ein Host mit diesem Namen existiert bereits".into(),
        )),
        Err(e) => Err(e.into()),
    }
}

pub async fn rotate_token(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let token = security::new_agent_token();
    let n = sqlx::query("UPDATE hosts SET token_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(security::sha256(&token))
        .execute(&st.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "id": id, "token": token })))
}

pub async fn remove(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let n = sqlx::query("DELETE FROM hosts WHERE id = $1")
        .bind(id)
        .execute(&st.pool)
        .await?
        .rows_affected();
    if n == 0 {
        Err(ApiError::NotFound)
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

/// "Geprüft am …": Admin hat die CVE für diesen Host manuell geprüft. Der Status bleibt unverändert
/// (UNKNOWN); die Markierung verfällt, sobald sich der laufende Kernel ändert.
pub async fn review(
    CsrfAdmin(admin): CsrfAdmin,
    State(st): State<AppState>,
    Path((id, cve)): Path<(i64, String)>,
) -> ApiResult<StatusCode> {
    if !crate::routes::valid_cve_id(&cve) {
        return Err(ApiError::BadRequest("ungültige CVE-ID".into()));
    }
    let kernel: Option<Option<String>> =
        sqlx::query_scalar("SELECT running_kernel FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let Some(Some(kernel)) = kernel else {
        return Err(ApiError::Conflict(
            "Host hat noch keinen Kernel gemeldet".into(),
        ));
    };
    sqlx::query(
        "INSERT INTO manual_reviews (host_id, cve_id, reviewed_by, kernel_version) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (host_id, cve_id) DO UPDATE SET reviewed_at = now(), reviewed_by = EXCLUDED.reviewed_by, \
           kernel_version = EXCLUDED.kernel_version",
    )
    .bind(id)
    .bind(&cve)
    .bind(&admin.username)
    .bind(kernel)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unreview(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path((id, cve)): Path<(i64, String)>,
) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM manual_reviews WHERE host_id = $1 AND cve_id = $2")
        .bind(id)
        .bind(&cve)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Mindestabstand zwischen zwei Report-Anfragen für denselben Host.
const REQUEST_COOLDOWN_SECS: i32 = 60;

/// "Jetzt aktualisieren": merkt den Wunsch beim Host vor; der Agent holt ihn beim nächsten Check-in ab.
/// Höchstens eine Anfrage je Host und Minute (in der DB, übersteht Neustarts).
pub async fn request_report(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let mut tx = st.pool.begin().await?;
    let updated: Option<(i64,)> = sqlx::query_as(
        "UPDATE hosts SET report_requested_at = now(), report_dispatched_at = NULL, last_report_request_at = now() \
         WHERE id = $1 AND (last_report_request_at IS NULL \
            OR last_report_request_at < now() - make_interval(secs => $2)) RETURNING id",
    )
    .bind(id)
    .bind(REQUEST_COOLDOWN_SECS)
    .fetch_optional(&mut *tx)
    .await?;
    if updated.is_none() {
        let wait: Option<(Option<f64>,)> = sqlx::query_as(
            "SELECT extract(epoch FROM last_report_request_at + make_interval(secs => $2) - now())::float8 \
             FROM hosts WHERE id = $1",
        )
        .bind(id)
        .bind(REQUEST_COOLDOWN_SECS)
        .fetch_optional(&mut *tx)
        .await?;
        return match wait {
            None => Err(ApiError::NotFound),
            Some((w,)) => Err(ApiError::TooManyRequests {
                retry_after_secs: w.unwrap_or(1.0).ceil().max(1.0) as u64,
            }),
        };
    }
    crate::live::notify(&mut tx, "report_requested", Some(id), None).await;
    tx.commit().await?;
    Ok(Json(json!({ "requested": 1 })))
}

/// Fordert bei allen Hosts einen Report an (Cooldown je Host); liefert (angefordert, gesamt).
/// Der Server sagt dem Agent weiterhin nur "jetzt melden"; genutzt von der Route und vom Zeitplan.
pub async fn request_all(pool: &sqlx::PgPool) -> sqlx::Result<(i64, i64)> {
    let mut tx = pool.begin().await?;
    let requested = sqlx::query(
        "UPDATE hosts SET report_requested_at = now(), report_dispatched_at = NULL, last_report_request_at = now() \
         WHERE last_report_request_at IS NULL OR last_report_request_at < now() - make_interval(secs => $1)",
    )
    .bind(REQUEST_COOLDOWN_SECS)
    .execute(&mut *tx)
    .await?
    .rows_affected() as i64;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM hosts")
        .fetch_one(&mut *tx)
        .await?;
    if requested > 0 {
        crate::live::notify(&mut tx, "report_requested", None, None).await;
    }
    tx.commit().await?;
    Ok((requested, total))
}

/// "Alle aktualisieren": gleiche Regel je Host; Hosts im Cooldown werden übersprungen.
pub async fn request_report_all(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
) -> ApiResult<Json<Value>> {
    let (requested, total) = request_all(&st.pool).await?;
    Ok(Json(
        json!({ "requested": requested, "skipped": total - requested }),
    ))
}
