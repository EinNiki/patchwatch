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
    COALESCE(c.vulnerable, 0) AS cve_vulnerable, COALESCE(c.fix_pending, 0) AS cve_fix_pending, \
    COALESCE(c.unknown, 0) AS cve_unknown \
    FROM hosts h LEFT JOIN LATERAL ( \
        SELECT count(*) FILTER (WHERE status = 'vulnerable') AS vulnerable, \
               count(*) FILTER (WHERE status = 'fix_pending') AS fix_pending, \
               count(*) FILTER (WHERE status = 'unknown') AS unknown \
        FROM host_cve_status WHERE host_id = h.id) c ON true";

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
}

pub async fn cves(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<HostCveRow>>> {
    let rows = sqlx::query_as::<_, HostCveRow>(
        "SELECT s.cve_id, s.status, s.reason, s.computed_at, s.sources, c.description, c.priority, \
                (w.cve_id IS NOT NULL) AS watched \
         FROM host_cve_status s JOIN cves c ON c.id = s.cve_id LEFT JOIN cve_watchlist w ON w.cve_id = s.cve_id \
         WHERE s.host_id = $1 ORDER BY (w.cve_id IS NOT NULL) DESC, s.cve_id DESC LIMIT 2000",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
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
