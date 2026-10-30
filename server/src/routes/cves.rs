use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// CVE-ID wie `CVE-2024-1086`.
pub fn valid_cve_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, num)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && (4..=7).contains(&num.len())
        && num.chars().all(|c| c.is_ascii_digit())
}

#[derive(Deserialize)]
pub struct ListQuery {
    watchlist: Option<bool>,
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CveRow {
    id: String,
    description: Option<String>,
    priority: Option<String>,
    published_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    watched: bool,
    note: Option<String>,
    hosts_vulnerable: i64,
    hosts_fix_pending: i64,
    hosts_unknown: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SourceRow {
    source: String,
    release: String,
    package: String,
    status: String,
    fix_version: Option<String>,
    updated_at: DateTime<Utc>,
}

const CVE_SELECT: &str = "SELECT c.id, c.description, c.priority, c.published_at, c.updated_at, \
    (w.cve_id IS NOT NULL) AS watched, w.note, \
    count(h.*) FILTER (WHERE h.status = 'vulnerable') AS hosts_vulnerable, \
    count(h.*) FILTER (WHERE h.status = 'fix_pending') AS hosts_fix_pending, \
    count(h.*) FILTER (WHERE h.status = 'unknown') AS hosts_unknown \
    FROM cves c LEFT JOIN cve_watchlist w ON w.cve_id = c.id LEFT JOIN host_cve_status h ON h.cve_id = c.id";

pub async fn list(
    _: Admin,
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<CveRow>>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    // LIKE-Metazeichen im Suchtext entschärfen.
    let pattern = q.q.as_deref().map(|s| {
        format!(
            "%{}%",
            s.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    let rows = sqlx::query_as::<_, CveRow>(&format!(
        "{CVE_SELECT} WHERE ($1::bool IS NOT TRUE OR w.cve_id IS NOT NULL) \
         AND ($2::text IS NULL OR c.id ILIKE $2 OR c.description ILIKE $2) \
         GROUP BY c.id, w.cve_id, w.note \
         ORDER BY (w.cve_id IS NOT NULL) DESC, c.updated_at DESC, c.id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(q.watchlist)
    .bind(pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(rows))
}

pub async fn detail(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_cve_id(&id) {
        return Err(ApiError::BadRequest("ungültige CVE-ID".into()));
    }
    let cve = sqlx::query_as::<_, CveRow>(&format!(
        "{CVE_SELECT} WHERE c.id = $1 GROUP BY c.id, w.cve_id, w.note"
    ))
    .bind(&id)
    .fetch_optional(&st.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let sources = sqlx::query_as::<_, SourceRow>(
        "SELECT source, release, package, status, fix_version, updated_at FROM cve_source_status \
         WHERE cve_id = $1 ORDER BY source, release, package",
    )
    .bind(&id)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(serde_json::json!({ "cve": cve, "sources": sources })))
}

pub async fn watchlist(admin: Admin, State(st): State<AppState>) -> ApiResult<Json<Vec<CveRow>>> {
    list(
        admin,
        State(st),
        Query(ListQuery {
            watchlist: Some(true),
            q: None,
            limit: Some(500),
            offset: None,
        }),
    )
    .await
}

#[derive(Deserialize, Default)]
pub struct WatchBody {
    note: Option<String>,
}

/// Fügt eine CVE zur Watchlist hinzu (auch, wenn die Feeds sie noch nicht kennen).
pub async fn watch(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<WatchBody>>,
) -> ApiResult<StatusCode> {
    if !valid_cve_id(&id) {
        return Err(ApiError::BadRequest("ungültige CVE-ID".into()));
    }
    let note = body.and_then(|b| b.0.note).filter(|n| !n.is_empty());
    if note.as_ref().is_some_and(|n| n.len() > 500) {
        return Err(ApiError::BadRequest(
            "Notiz zu lang (max. 500 Zeichen)".into(),
        ));
    }
    let mut tx = st.pool.begin().await?;
    sqlx::query("INSERT INTO cves (id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO cve_watchlist (cve_id, note) VALUES ($1, $2) ON CONFLICT (cve_id) DO UPDATE SET note = EXCLUDED.note")
        .bind(&id)
        .bind(note)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unwatch(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM cve_watchlist WHERE cve_id = $1")
        .bind(&id)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_id_validation() {
        assert!(valid_cve_id("CVE-2024-1086"));
        assert!(valid_cve_id("CVE-2021-44228"));
        assert!(!valid_cve_id("cve-2024-1086"));
        assert!(!valid_cve_id("CVE-24-1086"));
        assert!(!valid_cve_id("CVE-2024-12"));
        assert!(!valid_cve_id("CVE-2024-1086; DROP"));
    }
}
