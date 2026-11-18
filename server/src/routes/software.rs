use crate::authz;
use crate::cve::eval::{CveStatus, SourceRow};
use crate::cve::SourceStatus;
use crate::error::{ApiError, ApiResult};
use crate::extract::Authed;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Default, Deserialize)]
pub struct SoftwareQuery {
    host_id: Option<i64>,
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    kind: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct InventoryHost {
    id: i64,
    name: String,
    packages_reported_at: Option<DateTime<Utc>>,
    last_report_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct PackageRow {
    id: String,
    host_id: i64,
    host_name: String,
    os_id: Option<String>,
    os_codename: Option<String>,
    name: String,
    version: Option<String>,
    source_name: Option<String>,
    source_version: Option<String>,
    last_seen: DateTime<Utc>,
    last_report_at: Option<DateTime<Utc>>,
    candidate: Option<String>,
    security_update: bool,
    inventory_id: Option<i64>,
    context_label: Option<String>,
    context_kind: Option<String>,
    identity: Option<String>,
    purl: Option<String>,
    location: Option<String>,
    ecosystem: String,
    assessment: Option<String>,
    assessed_at: Option<DateTime<Utc>>,
    imported_findings: Option<Value>,
    scan_error: Option<String>,
    source_enabled: bool,
}

#[derive(sqlx::FromRow)]
struct AdvisoryRow {
    cve_id: String,
    source: String,
    release: String,
    package: String,
    status: String,
    fix_version: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Finding {
    id: String,
    status: String,
    source: String,
    fix_version: Option<String>,
    reason: String,
    url: Option<String>,
}

#[derive(Serialize)]
pub struct SoftwareItem {
    id: String,
    host_id: i64,
    host_name: String,
    name: String,
    version: Option<String>,
    ecosystem: String,
    source_name: Option<String>,
    source_version: Option<String>,
    last_seen: DateTime<Utc>,
    stale: bool,
    candidate: Option<String>,
    security_update: bool,
    status: &'static str,
    reason: String,
    findings: Vec<Finding>,
    inventory_id: Option<i64>,
    context_label: Option<String>,
    context_kind: Option<String>,
    identity: Option<String>,
    purl: Option<String>,
    location: Option<String>,
    assessed_at: Option<DateTime<Utc>>,
}

const INVENTORY: &str = "FROM ( \
    SELECT 'dpkg:' || hp.host_id || ':' || hp.name AS id, hp.host_id,hp.name,hp.version,hp.source_name,hp.source_version,hp.last_seen, \
       NULL::bigint AS inventory_id,NULL::text AS context_label,NULL::text AS context_kind,NULL::text AS identity, \
       NULL::text AS purl,NULL::text AS location,'deb'::text AS ecosystem,NULL::text AS assessment, \
       NULL::timestamptz AS assessed_at,NULL::jsonb AS imported_findings,NULL::text AS scan_error,true AS source_enabled \
    FROM host_packages hp \
    UNION ALL \
    SELECT 'sbom:' || c.id,i.host_id,c.name,c.version,NULL::text,NULL::text,i.imported_at, \
       i.id,i.label,i.kind,i.identity,c.purl,c.location,COALESCE(c.ecosystem,'unknown'),c.assessment,c.assessed_at,c.findings,i.scan_error, \
       EXISTS(SELECT 1 FROM cve_sources d WHERE d.id=i.scan_source_id AND d.kind='osv' AND d.enabled AND d.deleted_at IS NULL) \
    FROM software_components c JOIN software_inventories i ON i.id=c.inventory_id \
    ) p JOIN hosts h ON h.id=p.host_id";

fn imported_item(p: PackageRow, security_visible: bool, stale: bool) -> SoftwareItem {
    let mut findings: Vec<Finding> = if security_visible && p.source_enabled {
        p.imported_findings
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let fresh = p.assessed_at.is_some_and(|at| {
        Utc::now() - at < chrono::Duration::hours(crate::software_scan::FRESH_HOURS)
    });
    let (status, reason) = if !security_visible {
        findings.clear();
        (
            "unknown",
            "Für Sicherheitsbewertungen fehlt das Recht cves.read.",
        )
    } else if findings.iter().any(|f| f.status == "vulnerable") {
        (
            "vulnerable",
            "OSV meldet mindestens eine bekannte Schwachstelle für diese Paketversion.",
        )
    } else if p.purl.is_none() || p.version.is_none() {
        (
            "unknown",
            "Für eine eindeutige Prüfung fehlen Package URL oder Version.",
        )
    } else if crate::sbom::osv_ecosystem(&p.ecosystem).is_none() {
        ("unknown","Dieses Ökosystem benötigt eine weitere Quelle oder Distributionsangaben; es wurde nicht bei OSV geprüft.")
    } else if !p.source_enabled {
        (
            "unknown",
            "Noch keine Prüfung mit einer aktiven OSV-Quelle vorhanden.",
        )
    } else if p.scan_error.is_some() {
        (
            "unknown",
            "Die letzte OSV-Prüfung war unvollständig oder ist fehlgeschlagen.",
        )
    } else if !fresh || stale {
        (
            "unknown",
            "Inventar oder Sicherheitsabgleich ist veraltet oder wurde noch nicht geprüft.",
        )
    } else if p.assessment.as_deref() == Some("no_known_findings") {
        ("no_known_findings","OSV liefert für diese Paketversion keine bekannten Meldungen. Das ist kein Nachweis für vollständige Sicherheit.")
    } else {
        ("unknown","Keine passende OSV-Prüfung vorhanden; möglicherweise ist die Quelle auf ein anderes Ökosystem beschränkt.")
    };
    SoftwareItem {
        id: p.id,
        host_id: p.host_id,
        host_name: p.host_name,
        name: p.name,
        version: p.version,
        ecosystem: p.ecosystem,
        source_name: p.source_name,
        source_version: p.source_version,
        last_seen: p.last_seen,
        stale,
        candidate: None,
        security_update: false,
        status,
        reason: reason.into(),
        findings,
        inventory_id: p.inventory_id,
        context_label: p.context_label,
        context_kind: p.context_kind,
        identity: p.identity,
        purl: p.purl,
        location: p.location,
        assessed_at: security_visible.then_some(p.assessed_at).flatten(),
    }
}

#[derive(Serialize)]
pub struct SoftwareResponse {
    items: Vec<SoftwareItem>,
    total: i64,
    limit: i64,
    offset: i64,
    security_visible: bool,
    hosts: Vec<InventoryHost>,
}

/// A bounded, searchable inventory. Findings are computed from current source rows,
/// so disabled feeds, package removals and version changes cannot leave stale verdicts.
pub async fn list(
    user: Authed<authz::p::HostsRead>,
    State(st): State<AppState>,
    Query(q): Query<SoftwareQuery>,
) -> ApiResult<Json<SoftwareResponse>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);
    let needle = q.q.unwrap_or_default().trim().to_lowercase();
    let kind = q.kind.unwrap_or_default();
    if !["", "system", "application", "container", "manual"].contains(&kind.as_str()) {
        return Err(ApiError::BadRequest("Unbekannte Inventarart.".into()));
    }
    if !(0..=1_000_000).contains(&offset) || needle.len() > 200 {
        return Err(ApiError::BadRequest("ungültiger Software-Filter".into()));
    }
    let security_visible = user.0.can(authz::Permission::CvesRead);
    let stale_after = crate::schedule::stale_after(&st.pool, st.cfg.stale_after_hours).await;
    let mut tx = st.pool.begin().await?;
    // Counts, page and assessment use the same snapshot during concurrent reports.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    let hosts: Vec<InventoryHost> = sqlx::query_as(
        "SELECT id, name, packages_reported_at, last_report_at FROM hosts \
         ORDER BY name, id",
    )
    .fetch_all(&mut *tx)
    .await?;
    if q.host_id
        .is_some_and(|id| !hosts.iter().any(|h| h.id == id))
    {
        return Err(ApiError::NotFound);
    }
    let filter = format!("{INVENTORY} \
        WHERE ($1::bigint IS NULL OR h.id = $1) \
        AND ($2 = '' OR strpos(lower(concat_ws(' ',p.name,p.source_name,h.name,p.context_label,p.identity,p.purl)), $2) > 0) \
        AND ($3 = '' OR ($3='system' AND p.inventory_id IS NULL) OR p.context_kind=$3)");
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) {filter}"))
        .bind(q.host_id)
        .bind(&needle)
        .bind(&kind)
        .fetch_one(&mut *tx)
        .await?;
    let packages: Vec<PackageRow> = sqlx::query_as(&format!(
        "SELECT p.*, h.name AS host_name, h.os_id, h.os_codename, h.last_report_at, \
         (SELECT u->>'to' FROM jsonb_array_elements(COALESCE(h.updates_list, '[]'::jsonb)) u \
           WHERE p.inventory_id IS NULL AND u->>'name' = p.name ORDER BY u->>'to' LIMIT 1) AS candidate, \
         EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(h.updates_list, '[]'::jsonb)) u \
           WHERE p.inventory_id IS NULL AND u->>'name' = p.name AND u->>'security' = 'true') AS security_update \
         {filter} ORDER BY p.name, h.name, p.id LIMIT $4 OFFSET $5"
    ))
    .bind(q.host_id)
    .bind(&needle)
    .bind(&kind)
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut *tx)
    .await?;
    let names: Vec<String> = packages
        .iter()
        .filter(|p| p.inventory_id.is_none())
        .map(|p| p.source_name.as_ref().unwrap_or(&p.name).clone())
        .collect();
    let releases: Vec<String> = packages
        .iter()
        .filter_map(|p| p.os_codename.clone())
        .collect();
    let rows: Vec<AdvisoryRow> = if security_visible && !packages.is_empty() {
        sqlx::query_as(
            "SELECT cve_id, source, release, package, status, fix_version FROM cve_source_status c \
             WHERE package = ANY($1) AND release = ANY($2) AND source IN ('debian', 'ubuntu') \
             AND NOT EXISTS (SELECT 1 FROM cve_sources d WHERE d.id = c.source_id \
                 AND (NOT d.enabled OR d.deleted_at IS NOT NULL)) ORDER BY cve_id"
        ).bind(&names).bind(&releases).fetch_all(&mut *tx).await?
    } else {
        Vec::new()
    };
    let mut indexed: HashMap<(String, String, String), Vec<&AdvisoryRow>> = HashMap::new();
    for r in &rows {
        indexed
            .entry((r.source.clone(), r.release.clone(), r.package.clone()))
            .or_default()
            .push(r);
    }
    let mut source_missing = HashMap::new();
    let mut items = Vec::with_capacity(packages.len());
    for p in packages {
        if p.inventory_id.is_some() {
            let stale = Utc::now() - p.last_seen > stale_after;
            items.push(imported_item(p, security_visible, stale));
            continue;
        }
        if security_visible && !source_missing.contains_key(&p.host_id) {
            let missing =
                crate::hostops::cve_source_missing(&mut tx, p.host_id, Utc::now()).await?;
            source_missing.insert(p.host_id, missing);
        }
        let stale = p.last_report_at.is_none_or(|t| p.last_seen < t)
            || Utc::now() - p.last_seen > stale_after;
        let source = p.source_name.as_deref().unwrap_or(&p.name);
        // A binary package's version cannot substitute for a different source package's version.
        let version = p
            .source_version
            .as_deref()
            .or_else(|| (source == p.name).then_some(p.version.as_deref()).flatten());
        let key = (
            p.os_id.clone().unwrap_or_default(),
            p.os_codename.clone().unwrap_or_default(),
            source.to_owned(),
        );
        let mut findings = Vec::new();
        for r in indexed
            .get(&key)
            .into_iter()
            .flatten()
            .filter(|_| !crate::cve::is_kernel_source(source))
        {
            let row = SourceRow {
                source: r.source.clone(),
                release: r.release.clone(),
                package: r.package.clone(),
                status: SourceStatus::parse(&r.status),
                fix_version: r.fix_version.clone(),
            };
            let mut v = crate::software::evaluate(version, &row);
            if (stale || source_missing.get(&p.host_id) == Some(&true))
                && matches!(v.status, CveStatus::Fixed | CveStatus::NotAffected)
            {
                v.status = CveStatus::Unknown;
                v.reason =
                    "Paketliste oder Sicherheitsquelle ist nicht aktuell und vollständig.".into();
            }
            findings.push(Finding {
                id: r.cve_id.clone(),
                status: v.status.as_str().to_owned(),
                source: r.source.clone(),
                fix_version: r.fix_version.clone(),
                reason: v.reason,
                url: None,
            });
        }
        let (status, reason) = if !security_visible {
            (
                "unknown",
                "Für Sicherheitsbewertungen fehlt das Recht cves.read.",
            )
        } else if findings.iter().any(|f| f.status == "vulnerable") {
            (
                "vulnerable",
                "Mindestens eine bekannte Schwachstelle betrifft diese Paketversion.",
            )
        } else if crate::cve::is_kernel_source(source) {
            (
                "unknown",
                "Den laufenden Kernel und nötige Neustarts bewertet die Host-Seite.",
            )
        } else if findings.is_empty() {
            ("unknown", "Keine passende Sicherheitsbewertung vorhanden; das ist kein Nachweis für Sicherheit.")
        } else if findings.iter().any(|f| f.status == "unknown") {
            (
                "unknown",
                "Mindestens eine Bewertung ist unklar oder die Daten sind veraltet.",
            )
        } else {
            ("known_fixed", "Die zugeordneten Meldungen sind für diese installierte Version erledigt. Laufende Prozesse wurden nicht geprüft.")
        };
        items.push(SoftwareItem {
            id: p.id,
            host_id: p.host_id,
            host_name: p.host_name,
            name: p.name,
            version: p.version,
            ecosystem: "deb".into(),
            source_name: p.source_name,
            source_version: p.source_version,
            last_seen: p.last_seen,
            stale,
            candidate: p.candidate,
            security_update: p.security_update,
            status,
            reason: reason.into(),
            findings,
            inventory_id: None,
            context_label: None,
            context_kind: None,
            identity: None,
            purl: None,
            location: None,
            assessed_at: None,
        });
    }
    // Prioritize the verdict for this installed version, not the advisory ID or
    // upstream status: a published fix can still leave this package vulnerable.
    for item in &mut items {
        item.findings
            .sort_by_key(|finding| match finding.status.as_str() {
                "vulnerable" => 0,
                "fixed" | "not_affected" => 2,
                _ => 1,
            });
    }
    tx.commit().await?;
    Ok(Json(SoftwareResponse {
        items,
        total,
        limit,
        offset,
        security_visible,
        hosts,
    }))
}
