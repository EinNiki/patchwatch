//! Installierte Pakete und ausstehende Updates: je Host und über alle Hosts (nur lesend, Recht `hosts.read`).
use crate::authz;
use crate::error::{ApiError, ApiResult};
use crate::extract::Authed;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct PackagesQuery {
    /// Suchtext im Paketnamen (Teilstring, ohne Beachtung der Groß-/Kleinschreibung).
    q: Option<String>,
    /// `1` = nur Pakete mit ausstehendem Update.
    update: Option<u8>,
    /// `1` = nur Sicherheitsupdates.
    security: Option<u8>,
    sort: Option<String>,
    dir: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Suchmuster für `ILIKE ... ESCAPE '\'`: Platzhalterzeichen des Nutzers werden wörtlich genommen.
fn like_pattern(q: &Option<String>) -> Option<String> {
    q.as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            format!(
                "%{}%",
                t.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            )
        })
}

fn direction(q: &PackagesQuery) -> Result<&'static str, ApiError> {
    match q.dir.as_deref() {
        None | Some("asc") => Ok("ASC"),
        Some("desc") => Ok("DESC"),
        Some(_) => Err(ApiError::BadRequest("Ungültige Richtung".into())),
    }
}

#[derive(Serialize, sqlx::FromRow)]
struct PackageRow {
    name: String,
    installed: Option<String>,
    arch: Option<String>,
    candidate: Option<String>,
    /// `upgrade`, `new` oder `remove`; ohne Update leer.
    kind: Option<String>,
    origin: Option<String>,
    security: bool,
    update_since: Option<DateTime<Utc>>,
}

/// Pakete eines Hosts: installierte und ausstehende (auch neue) zusammengeführt, serverseitig gefiltert,
/// sortiert und seitenweise. Antwort: `{items, total, host}`. Sortierung kommt aus einer festen Liste,
/// nur der Suchtext ist ein (gebundener) Parameter.
pub async fn host_packages(
    _: Authed<authz::p::HostsRead>,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<PackagesQuery>,
) -> ApiResult<Json<Value>> {
    let dir = direction(&q)?;
    // Feste Fragmente je Sortierung (kein Nutzertext in der Abfrage); Name als stabiler Zweitschlüssel.
    let order = match q.sort.as_deref() {
        None | Some("name") => format!("name {dir}"),
        Some("installed") => format!("installed {dir} NULLS LAST, name"),
        Some("candidate") => format!("candidate {dir} NULLS LAST, name"),
        Some("origin") => format!("origin {dir} NULLS LAST, name"),
        // Sicherheit zuerst, wenn absteigend (Standard der Oberfläche); dann Updates vor dem Rest.
        Some("security") => format!("security {dir}, (kind IS NOT NULL) {dir}, name"),
        Some(_) => return Err(ApiError::BadRequest("Ungültige Sortierung".into())),
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let pattern = like_pattern(&q.q);

    #[derive(sqlx::FromRow)]
    struct Head {
        packages_count: Option<i32>,
        packages_truncated: bool,
        packages_updated_at: Option<DateTime<Utc>>,
        apt_lists_updated_at: Option<DateTime<Utc>>,
        updates_listed: bool,
        updates_remove: Option<i32>,
        installed: i64,
        updates: i64,
        security: i64,
        new: i64,
    }
    let head: Head = sqlx::query_as(
        "SELECT h.packages_count, h.packages_truncated, h.packages_updated_at, h.apt_lists_updated_at, \
                h.updates_listed, h.updates_remove, \
                (SELECT count(*) FROM host_packages WHERE host_id = h.id) AS installed, \
                (SELECT count(*) FROM host_updates WHERE host_id = h.id) AS updates, \
                (SELECT count(*) FROM host_updates WHERE host_id = h.id AND security) AS security, \
                (SELECT count(*) FROM host_updates WHERE host_id = h.id AND kind = 'new') AS new \
         FROM hosts h WHERE h.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?
    .ok_or(ApiError::NotFound)?;

    let sql = format!(
        "WITH merged AS ( \
            SELECT COALESCE(p.name, u.name) AS name, p.version AS installed, p.arch, \
                   u.candidate, u.kind, u.origin, COALESCE(u.security, false) AS security, u.first_seen AS update_since \
            FROM (SELECT name, version, arch FROM host_packages WHERE host_id = $1) p \
            FULL OUTER JOIN (SELECT * FROM host_updates WHERE host_id = $1) u ON u.name = p.name) \
         SELECT name, installed, arch, candidate, kind, origin, security, update_since FROM merged \
         WHERE ($2::text IS NULL OR name ILIKE $2) \
           AND (NOT $3 OR kind IS NOT NULL) AND (NOT $4 OR security) \
         ORDER BY {order} LIMIT $5 OFFSET $6"
    );
    let items: Vec<PackageRow> = sqlx::query_as(&sql)
        .bind(id)
        .bind(&pattern)
        .bind(q.update == Some(1))
        .bind(q.security == Some(1))
        .bind(limit)
        .bind(offset)
        .fetch_all(&st.pool)
        .await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ( \
            SELECT COALESCE(p.name, u.name) AS name, u.kind, COALESCE(u.security, false) AS security \
            FROM (SELECT name FROM host_packages WHERE host_id = $1) p \
            FULL OUTER JOIN (SELECT name, kind, security FROM host_updates WHERE host_id = $1) u ON u.name = p.name) m \
         WHERE ($2::text IS NULL OR name ILIKE $2) AND (NOT $3 OR kind IS NOT NULL) AND (NOT $4 OR security)",
    )
    .bind(id)
    .bind(&pattern)
    .bind(q.update == Some(1))
    .bind(q.security == Some(1))
    .fetch_one(&st.pool)
    .await?;

    Ok(Json(json!({
        "items": items,
        "total": total,
        "host": {
            "installed": head.installed,
            "packages_count": head.packages_count,
            "truncated": head.packages_truncated,
            "packages_updated_at": head.packages_updated_at,
            "apt_lists_updated_at": head.apt_lists_updated_at,
            "updates_listed": head.updates_listed,
            "updates": head.updates,
            "security": head.security,
            "new": head.new,
            "remove": head.updates_remove,
        },
    })))
}

#[derive(Serialize, sqlx::FromRow)]
struct OverviewRow {
    name: String,
    /// Hosts, auf denen das Paket installiert ist.
    hosts: i64,
    /// Verschiedene installierte Versionen (Streuung).
    versions: i64,
    /// Hosts mit ausstehendem Update bzw. Sicherheitsupdate.
    updates: i64,
    security: i64,
}

/// Pakete über alle Hosts: je Name Hosts gesamt, mit Update, mit Sicherheitsupdate und Versionsstreuung.
/// Antwort: `{items, total}`.
pub async fn overview(
    _: Authed<authz::p::HostsRead>,
    State(st): State<AppState>,
    Query(q): Query<PackagesQuery>,
) -> ApiResult<Json<Value>> {
    let dir = direction(&q)?;
    let order = match q.sort.as_deref() {
        None | Some("name") => format!("name {dir}"),
        Some("hosts") => format!("hosts {dir}, name"),
        Some("versions") => format!("versions {dir}, name"),
        Some("updates") => format!("updates {dir}, name"),
        Some("security") => format!("security {dir}, updates {dir}, name"),
        Some(_) => return Err(ApiError::BadRequest("Ungültige Sortierung".into())),
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let pattern = like_pattern(&q.q);
    let base = "WITH inst AS (SELECT name, count(*) AS hosts, count(DISTINCT version) AS versions \
                              FROM host_packages GROUP BY name), \
                     upd AS (SELECT name, count(*) AS updates, count(*) FILTER (WHERE security) AS security \
                             FROM host_updates GROUP BY name), \
                     merged AS (SELECT COALESCE(i.name, u.name) AS name, COALESCE(i.hosts, 0) AS hosts, \
                                       COALESCE(i.versions, 0) AS versions, COALESCE(u.updates, 0) AS updates, \
                                       COALESCE(u.security, 0) AS security \
                                FROM inst i FULL OUTER JOIN upd u ON u.name = i.name) ";
    let filter = "WHERE ($1::text IS NULL OR name ILIKE $1) AND (NOT $2 OR updates > 0) AND (NOT $3 OR security > 0)";
    let items: Vec<OverviewRow> = sqlx::query_as(&format!(
        "{base}SELECT name, hosts, versions, updates, security FROM merged {filter} \
         ORDER BY {order} LIMIT $4 OFFSET $5"
    ))
    .bind(&pattern)
    .bind(q.update == Some(1))
    .bind(q.security == Some(1))
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.pool)
    .await?;
    let total: i64 = sqlx::query_scalar(&format!("{base}SELECT count(*) FROM merged {filter}"))
        .bind(&pattern)
        .bind(q.update == Some(1))
        .bind(q.security == Some(1))
        .fetch_one(&st.pool)
        .await?;
    Ok(Json(json!({ "items": items, "total": total })))
}
