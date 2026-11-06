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
    COALESCE(c.unknown, 0) AS cve_unknown, COALESCE(c.reboot, 0) AS cve_reboot, COALESCE(c.fixed, 0) AS cve_fixed \
    FROM hosts h LEFT JOIN LATERAL ( \
        SELECT count(*) FILTER (WHERE status = 'vulnerable') AS vulnerable, \
               count(*) FILTER (WHERE status = 'fix_pending') AS fix_pending, \
               count(*) FILTER (WHERE status = 'unknown') AS unknown, \
               count(*) FILTER (WHERE status = 'fixed_installed_reboot_required') AS reboot, \
               count(*) FILTER (WHERE status = 'fixed') AS fixed \
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
    cve_reboot: i64,
    cve_fixed: i64,
    /// Warum die CVE-Lage unbekannt ist ("Quelle Ubuntu unvollständig / veraltet / fehlerhaft"); sonst `null`.
    #[sqlx(skip)]
    cve_source_issue: Option<String>,
}

/// Trägt die Begründung "keine nutzbare CVE-Quelle" ein (nur Debian/Ubuntu-Hosts außer Proxmox).
async fn with_source_issues(st: &AppState, mut rows: Vec<HostRow>) -> ApiResult<Vec<HostRow>> {
    let issues = crate::hostops::cve_source_issues(&st.pool).await?;
    for r in &mut rows {
        if !r.is_proxmox {
            r.cve_source_issue = r
                .os_id
                .as_deref()
                .and_then(|os| issues.for_host(os, r.os_codename.as_deref()));
        }
    }
    Ok(rows)
}

pub async fn list(_: Admin, State(st): State<AppState>) -> ApiResult<Json<Vec<HostRow>>> {
    let rows = sqlx::query_as::<_, HostRow>(&format!("{HOST_SELECT} ORDER BY h.name"))
        .fetch_all(&st.pool)
        .await?;
    Ok(Json(with_source_issues(&st, rows).await?))
}

pub async fn detail(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<HostRow>> {
    let row = sqlx::query_as::<_, HostRow>(&format!("{HOST_SELECT} WHERE h.id = $1"))
        .bind(id)
        .fetch_optional(&st.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut rows = with_source_issues(&st, vec![row]).await?;
    Ok(Json(rows.remove(0)))
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
    /// Seit wann die CVE öffentlich bekannt ist.
    published_at: Option<DateTime<Utc>>,
    /// Priorität als Stufe 0–10 (0 = unbekannt).
    #[sqlx(skip)]
    level: u8,
    /// Fix-Version der zuständigen Quelle (aus `sources`) und deren Name.
    #[sqlx(skip)]
    fix_version: Option<String>,
    #[sqlx(skip)]
    source: Option<String>,
    /// `security`: ein Fix ist in der Security-Suite von Debian erhältlich, aber auf diesem Host noch nicht installiert.
    #[sqlx(skip)]
    fix_hint: Option<&'static str>,
}

#[derive(Deserialize)]
pub struct CvesQuery {
    /// Gruppe: `open` (offen, Fix angekündigt, Neustart nötig), `fixed`, `all` (Standard).
    group: Option<String>,
    /// Ein Status oder eine kommagetrennte Liste; hat Vorrang vor `group`.
    status: Option<String>,
    q: Option<String>,
    /// `importance` (Standard), `cve`, `level`, `changed`.
    sort: Option<String>,
    /// `asc` oder `desc`.
    dir: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    /// Nur Einträge mit genau dieser Fix-Version (Gruppe aus `cves/groups`).
    fix_version: Option<String>,
    /// Mindest-Level 0–10 (Priorität).
    level_min: Option<i64>,
}

const ALL_STATES: [&str; 6] = [
    "vulnerable",
    "fix_pending",
    "fixed_installed_reboot_required",
    "unknown",
    "fixed",
    "not_affected",
];

/// Fix-Version der zuständigen Quelle eines Eintrags: die erste Angabe in `sources` mit Fix-Version (wie `cves`).
const FIX_SQL: &str = "(SELECT e->>'fix_version' FROM jsonb_array_elements(s.sources) e WHERE e->>'fix_version' IS NOT NULL LIMIT 1)";

/// Reihenfolge der Dringlichkeit: Neustart nötig vor offen, dann Fix angekündigt, unbekannt, gefixt, nicht betroffen.
const RANK_SQL: &str =
    "CASE s.status WHEN 'fixed_installed_reboot_required' THEN 0 WHEN 'vulnerable' THEN 1 \
    WHEN 'fix_pending' THEN 2 WHEN 'unknown' THEN 3 WHEN 'fixed' THEN 4 ELSE 5 END";
const LEVEL_SQL: &str =
    "CASE c.priority WHEN 'critical' THEN 10 WHEN 'high' THEN 8 WHEN 'medium' THEN 5 \
    WHEN 'low' THEN 3 WHEN 'negligible' THEN 1 WHEN 'unimportant' THEN 1 ELSE 0 END";

/// CVE-Bewertungen eines Hosts mit allen Zuständen, serverseitig gefiltert, sortiert und seitenweise.
/// Antwort: `{items, total, counts, host, issue}`. Die Zähler gelten für den ganzen Host (ohne Suche/Filter), `total`
/// für die gefilterte Liste. Sortierung und Gruppen stammen aus festen Listen; nur der Suchtext ist ein Parameter.
pub async fn cves(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<CvesQuery>,
) -> ApiResult<Json<Value>> {
    let statuses: Option<Vec<String>> = match (q.status.as_deref(), q.group.as_deref()) {
        // Kommagetrennte Liste, jeder Eintrag muss aus der festen Liste stammen.
        (Some(s), _) => {
            let list: Vec<String> = s.split(',').map(str::to_owned).collect();
            if list.is_empty() || !list.iter().all(|x| ALL_STATES.contains(&x.as_str())) {
                return Err(ApiError::BadRequest("Ungültiger Status".into()));
            }
            Some(list)
        }
        (None, Some("open")) => Some(
            [
                "vulnerable",
                "fix_pending",
                "fixed_installed_reboot_required",
            ]
            .map(String::from)
            .to_vec(),
        ),
        (None, Some("fixed")) => Some(vec!["fixed".to_owned()]),
        (None, Some("all") | None) => None,
        (None, Some(_)) => return Err(ApiError::BadRequest("Ungültige Gruppe".into())),
    };
    let desc = match q.dir.as_deref() {
        None | Some("desc") => true,
        Some("asc") => false,
        Some(_) => return Err(ApiError::BadRequest("Ungültige Richtung".into())),
    };
    let dir = if desc { "DESC" } else { "ASC" };
    // Feste Fragmente je Sortierung (kein Nutzertext in der Abfrage).
    let order = match q.sort.as_deref() {
        None | Some("importance") => {
            if desc {
                format!(
                    "{RANK_SQL} ASC, {LEVEL_SQL} DESC, (w.cve_id IS NOT NULL) DESC, s.cve_id DESC"
                )
            } else {
                format!("{RANK_SQL} DESC, {LEVEL_SQL} ASC, s.cve_id ASC")
            }
        }
        Some("cve") => format!("s.cve_id {dir}"),
        // Level, dann Alter: bei gleichem Level steht die am längsten bekannte CVE zuerst.
        Some("level") => format!("{LEVEL_SQL} {dir}, c.published_at ASC NULLS LAST, s.cve_id DESC"),
        Some("changed") => format!("s.computed_at {dir}, s.cve_id DESC"),
        Some(_) => return Err(ApiError::BadRequest("Ungültige Sortierung".into())),
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let offset = q.offset.unwrap_or(0).max(0);
    let pattern =
        q.q.as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| {
                format!(
                    "%{}%",
                    t.replace('\\', "\\\\")
                        .replace('%', "\\%")
                        .replace('_', "\\_")
                )
            });

    let host: Option<HostCveHeader> = sqlx::query_as(
        "SELECT os_id, os_codename, is_proxmox, running_kernel, kernel_package_version, newest_kernel, \
                newest_kernel_version, (COALESCE(reboot_required_file, false) OR COALESCE(reboot_needed_kernel, false)) AS reboot_needed \
         FROM hosts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let host = host.ok_or(ApiError::NotFound)?;

    let count_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, count(*) FROM host_cve_status WHERE host_id = $1 GROUP BY status",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let mut counts = serde_json::Map::new();
    for state in ALL_STATES {
        let n = count_rows
            .iter()
            .find(|(s, _)| s == state)
            .map_or(0, |(_, n)| *n);
        counts.insert(state.to_owned(), json!(n));
    }

    let level_min = q.level_min.unwrap_or(0).clamp(0, 10);
    let fix_filter = q
        .fix_version
        .as_deref()
        .filter(|f| !f.is_empty() && f.len() <= 128);
    let where_sql = format!(
        "s.host_id = $1 AND ($2::text[] IS NULL OR s.status = ANY($2)) \
         AND ($3::text IS NULL OR s.cve_id ILIKE $3 OR c.description ILIKE $3) \
         AND ($4::text IS NULL OR {FIX_SQL} = $4) AND ({LEVEL_SQL}) >= $5"
    );
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM host_cve_status s JOIN cves c ON c.id = s.cve_id WHERE {where_sql}"
    ))
    .bind(id)
    .bind(&statuses)
    .bind(&pattern)
    .bind(fix_filter)
    .bind(level_min)
    .fetch_one(&st.pool)
    .await?;
    // Offene mit Fix in einer Quelle (im Archiv erhältlich, auf dem Host nicht installiert).
    let open_with_fix: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM host_cve_status s WHERE s.host_id = $1 AND s.status IN ('vulnerable', 'fix_pending') AND {FIX_SQL} IS NOT NULL"
    ))
    .bind(id)
    .fetch_one(&st.pool)
    .await?;

    let rows = sqlx::query_as::<_, HostCveRow>(&format!(
        "SELECT s.cve_id, s.status, s.reason, s.computed_at, s.sources, \
                left(c.description, 300) AS description, c.priority, \
                (w.cve_id IS NOT NULL) AS watched, m.reviewed_at, m.reviewed_by, c.published_at \
         FROM host_cve_status s JOIN cves c ON c.id = s.cve_id JOIN hosts h ON h.id = s.host_id \
         LEFT JOIN cve_watchlist w ON w.cve_id = s.cve_id \
         LEFT JOIN manual_reviews m ON m.host_id = s.host_id AND m.cve_id = s.cve_id AND m.kernel_version = h.running_kernel \
         WHERE {where_sql} ORDER BY {order} LIMIT $6 OFFSET $7"
    ))
    .bind(id)
    .bind(&statuses)
    .bind(&pattern)
    .bind(fix_filter)
    .bind(level_min)
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.pool)
    .await?;
    let items: Vec<HostCveRow> = rows
        .into_iter()
        .map(|mut r| {
            r.level = super::cves::priority_level(r.priority.as_deref());
            // Verantwortliche Quelle: der erste Eintrag mit Fix-Version (sonst der erste überhaupt).
            let list = r.sources.as_array().cloned().unwrap_or_default();
            let pick = list
                .iter()
                .find(|e| e["fix_version"].is_string())
                .or_else(|| list.first());
            r.fix_version = pick
                .and_then(|e| e["fix_version"].as_str())
                .map(String::from);
            r.source = pick.and_then(|e| e["source"].as_str()).map(String::from);
            r
        })
        .collect();

    // Hinweis "Fix verfügbar über Security-Updates": Debian führt je Suite eine Version; ist der Eintrag des Hosts
    // verwundbar und enthält die Security-Suite den Fix, fehlt nur das Einspielen (die Bewertung selbst bleibt).
    let mut items = items;
    if host.os_id.as_deref() == Some("debian") {
        let wanted: Vec<String> = items
            .iter()
            .filter(|i| i.status == "vulnerable" && i.fix_version.is_some())
            .map(|i| i.cve_id.clone())
            .collect();
        if !wanted.is_empty() {
            let secure: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT s.cve_id FROM cve_source_status s \
                 WHERE s.source = 'debian' AND s.cve_id = ANY($1) AND s.release = $2 \
                   AND EXISTS (SELECT 1 FROM jsonb_each(s.suites) e WHERE e.key LIKE '%-security' AND e.value->>'status' = 'fixed')",
            )
            .bind(&wanted)
            .bind(host.os_codename.as_deref().unwrap_or(""))
            .fetch_all(&st.pool)
            .await?;
            for i in items.iter_mut().filter(|i| secure.contains(&i.cve_id)) {
                i.fix_hint = Some("security");
            }
        }
    }

    // Hinweis "Bewertung eingeschränkt": die Quelle ist unvollständig, veraltet oder das Release nicht importiert.
    let issue = if host.is_proxmox {
        None
    } else {
        let issues = crate::hostops::cve_source_issues(&st.pool).await?;
        host.os_id
            .as_deref()
            .and_then(|os| issues.for_host(os, host.os_codename.as_deref()))
    };
    Ok(Json(json!({
        "items": items, "total": total, "counts": counts, "open_with_fix": open_with_fix, "issue": issue,
        "host": {
            "is_proxmox": host.is_proxmox, "running_kernel": host.running_kernel,
            "running_kernel_version": host.kernel_package_version,
            "newest_kernel": host.newest_kernel, "newest_kernel_version": host.newest_kernel_version,
            "reboot_needed": host.reboot_needed,
        },
    })))
}

#[derive(Deserialize)]
pub struct GroupsQuery {
    /// `reboot` (Neustart nötig) oder `fixed` (gefixt).
    kind: String,
    q: Option<String>,
    level_min: Option<i64>,
}

/// Einträge nach Fix-Version gruppiert (`reboot` oder `fixed`): `{groups: [{fix_version, count}], total}`, neueste Version
/// zuerst (dpkg-Reihenfolge). Einträge ohne Fix-Version stehen in einer Gruppe mit `fix_version: null`.
pub async fn cve_groups(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<GroupsQuery>,
) -> ApiResult<Json<Value>> {
    let status = match q.kind.as_str() {
        "reboot" => "fixed_installed_reboot_required",
        "fixed" => "fixed",
        _ => return Err(ApiError::BadRequest("Ungültige Gruppenart".into())),
    };
    let pattern =
        q.q.as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| {
                format!(
                    "%{}%",
                    t.replace('\\', "\\\\")
                        .replace('%', "\\%")
                        .replace('_', "\\_")
                )
            });
    let level_min = q.level_min.unwrap_or(0).clamp(0, 10);
    let rows: Vec<(Option<String>, i64)> = sqlx::query_as(&format!(
        "SELECT {FIX_SQL} AS fix, count(*) FROM host_cve_status s JOIN cves c ON c.id = s.cve_id \
         WHERE s.host_id = $1 AND s.status = $2 AND ($3::text IS NULL OR s.cve_id ILIKE $3 OR c.description ILIKE $3) \
           AND ({LEVEL_SQL}) >= $4 GROUP BY 1"
    ))
    .bind(id)
    .bind(status)
    .bind(&pattern)
    .bind(level_min)
    .fetch_all(&st.pool)
    .await?;
    let mut groups: Vec<(Option<String>, i64)> = rows;
    // Neueste Fix-Version zuerst; was sich nicht als dpkg-Version lesen lässt, steht hinten.
    groups.sort_by(|a, b| {
        let pa =
            a.0.as_deref()
                .and_then(|v| v.parse::<debversion::Version>().ok());
        let pb =
            b.0.as_deref()
                .and_then(|v| v.parse::<debversion::Version>().ok());
        pb.cmp(&pa).then_with(|| a.0.cmp(&b.0))
    });
    let total: i64 = groups.iter().map(|g| g.1).sum();
    let groups: Vec<Value> = groups
        .into_iter()
        .map(|(f, n)| json!({ "fix_version": f, "count": n }))
        .collect();
    Ok(Json(json!({ "groups": groups, "total": total })))
}

#[derive(sqlx::FromRow)]
struct HostCveHeader {
    os_id: Option<String>,
    os_codename: Option<String>,
    is_proxmox: bool,
    running_kernel: Option<String>,
    kernel_package_version: Option<String>,
    newest_kernel: Option<String>,
    newest_kernel_version: Option<String>,
    reboot_needed: bool,
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
