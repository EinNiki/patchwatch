//! Bewertung von Hosts gegen CVEs, Persistenz in `host_cve_status`, Events bei Statuswechsel.

use super::eval::{self, CveStatus, HostKernel, SourceRow, Verdict};
use super::{HostRef, SourceStatus};
use crate::hostops;
use crate::state::AppState;
use anyhow::Result;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use std::collections::{HashMap, HashSet};

const MAX_EVENTS_PER_RUN: usize = 50;

#[derive(sqlx::FromRow)]
struct HostRow {
    os_id: Option<String>,
    os_version: Option<String>,
    os_codename: Option<String>,
    running_kernel: Option<String>,
    kernel_package: Option<String>,
    kernel_package_version: Option<String>,
    kernel_source: Option<String>,
    newest_kernel_version: Option<String>,
}

impl HostRow {
    fn kernel(&self) -> HostKernel {
        HostKernel {
            distro_id: self.os_id.clone().unwrap_or_default(),
            codename: self.os_codename.clone(),
            running_release: self.running_kernel.clone(),
            package: self.kernel_package.clone(),
            package_version: self.kernel_package_version.clone(),
            source: self.kernel_source.clone(),
            newest_version: self.newest_kernel_version.clone(),
        }
    }
}

const HOST_COLS: &str =
    "os_id, os_version, os_codename, running_kernel, kernel_package, kernel_package_version, \
                         kernel_source, newest_kernel_version";

async fn load_host(conn: &mut PgConnection, host_id: i64) -> sqlx::Result<Option<HostRow>> {
    sqlx::query_as(&format!(
        "SELECT {HOST_COLS} FROM hosts WHERE id = $1 AND running_kernel IS NOT NULL"
    ))
    .bind(host_id)
    .fetch_optional(conn)
    .await
}

#[derive(sqlx::FromRow)]
struct RowDb {
    cve_id: String,
    source: String,
    release: String,
    package: String,
    status: String,
    fix_version: Option<String>,
}

async fn load_rows(
    conn: &mut PgConnection,
    cves: &[String],
    release: &str,
    package: &str,
) -> sqlx::Result<HashMap<String, Vec<SourceRow>>> {
    let rows: Vec<RowDb> = sqlx::query_as(
        "SELECT cve_id, source, release, package, status, fix_version FROM cve_source_status \
         WHERE cve_id = ANY($1) AND release = $2 AND package = $3 \
         AND NOT EXISTS (SELECT 1 FROM cve_sources d WHERE d.id = cve_source_status.source_id \
              AND (NOT d.enabled OR d.deleted_at IS NOT NULL))",
    )
    .bind(cves)
    .bind(release)
    .bind(package)
    .fetch_all(conn)
    .await?;
    let mut map: HashMap<String, Vec<SourceRow>> = HashMap::new();
    for r in rows {
        map.entry(r.cve_id).or_default().push(SourceRow {
            source: r.source,
            release: r.release,
            package: r.package,
            status: SourceStatus::parse(&r.status),
            fix_version: r.fix_version,
        });
    }
    Ok(map)
}

/// Welche CVEs für diesen Host zu bewerten sind: Watchlist plus alle CVEs mit Daten für (Release, Paket).
async fn candidates(
    conn: &mut PgConnection,
    k: &HostKernel,
) -> sqlx::Result<(Vec<String>, HashSet<String>)> {
    let watched: Vec<String> = sqlx::query_scalar("SELECT cve_id FROM cve_watchlist")
        .fetch_all(&mut *conn)
        .await?;
    let mut all: HashSet<String> = watched.iter().cloned().collect();
    if !eval::is_proxmox_kernel(k) {
        if let (Some(rel), Some(pkg)) = (
            k.codename.as_deref(),
            eval::tracker_package(&k.distro_id, k.source.as_deref()),
        ) {
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT cve_id FROM cve_source_status WHERE release = $1 AND package = $2",
            )
            .bind(rel)
            .bind(pkg)
            .fetch_all(&mut *conn)
            .await?;
            all.extend(ids);
        }
    }
    Ok((all.into_iter().collect(), watched.into_iter().collect()))
}

/// Nur Ergebnisse mit Handlungsbezug werden gespeichert (Watchlist immer); `fixed`/`not_affected` sind es nicht.
fn worth_storing(s: CveStatus, watched: bool) -> bool {
    watched
        || matches!(
            s,
            CveStatus::Vulnerable
                | CveStatus::FixPending
                | CveStatus::FixedInstalledRebootRequired
                | CveStatus::Unknown
        )
}

/// Bewertet einen Host neu, speichert Änderungen, erzeugt Events und berechnet den Host-Status.
/// Gibt die Zahl geänderter CVE-Status zurück.
pub async fn evaluate_host(pool: &PgPool, host_id: i64, stale_after: Duration) -> Result<usize> {
    let mut tx = pool.begin().await?;
    let Some(host) = load_host(&mut tx, host_id).await? else {
        return Ok(0);
    };
    let kernel = host.kernel();
    let (cands, watched) = candidates(&mut tx, &kernel).await?;

    let rows = match (
        kernel.codename.as_deref(),
        eval::tracker_package(&kernel.distro_id, kernel.source.as_deref()),
    ) {
        (Some(rel), Some(pkg)) if !eval::is_proxmox_kernel(&kernel) => {
            load_rows(&mut tx, &cands, rel, &pkg).await?
        }
        _ => HashMap::new(),
    };

    let existing: HashMap<String, String> = sqlx::query_as::<_, (String, String)>(
        "SELECT cve_id, status FROM host_cve_status WHERE host_id = $1",
    )
    .bind(host_id)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();
    let initial = existing.is_empty();

    let mut keep: Vec<(String, Verdict)> = Vec::new();
    let mut changes: Vec<(String, Option<String>, CveStatus)> = Vec::new();
    let mut kept_ids: HashSet<&str> = HashSet::new();
    let verdicts: Vec<(String, Verdict)> = cands
        .iter()
        .map(|c| {
            (
                c.clone(),
                eval::evaluate(&kernel, rows.get(c).map_or(&[][..], Vec::as_slice)),
            )
        })
        .collect();
    for (cve, v) in &verdicts {
        let old = existing.get(cve);
        if worth_storing(v.status, watched.contains(cve)) {
            kept_ids.insert(cve);
            keep.push((cve.clone(), v.clone()));
            if old.map(String::as_str) != Some(v.status.as_str()) {
                changes.push((cve.clone(), old.cloned(), v.status));
            }
        } else if let Some(old) = old {
            changes.push((cve.clone(), Some(old.clone()), v.status));
        }
    }
    let gone: Vec<String> = existing
        .keys()
        .filter(|c| !kept_ids.contains(c.as_str()))
        .cloned()
        .collect();

    for chunk in keep.chunks(5000) {
        sqlx::query(
            "INSERT INTO host_cve_status (host_id, cve_id, status, computed_at, reason, sources) \
             SELECT $1, c, s, now(), r, src::jsonb FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[]) AS t(c, s, r, src) \
             ON CONFLICT (host_id, cve_id) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason, \
               sources = EXCLUDED.sources, computed_at = EXCLUDED.computed_at \
             WHERE (host_cve_status.status, host_cve_status.reason) IS DISTINCT FROM (EXCLUDED.status, EXCLUDED.reason)",
        )
        .bind(host_id)
        .bind(chunk.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, v)| v.status.as_str().to_owned()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, v)| v.reason.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, v)| Value::Array(v.sources.clone()).to_string()).collect::<Vec<_>>())
        .execute(&mut *tx)
        .await?;
    }
    if !gone.is_empty() {
        sqlx::query("DELETE FROM host_cve_status WHERE host_id = $1 AND cve_id = ANY($2)")
            .bind(host_id)
            .bind(&gone)
            .execute(&mut *tx)
            .await?;
    }

    // Erste Bewertung eines Hosts erzeugt keine Event-Flut; danach je Statuswechsel ein Event.
    if !initial && !changes.is_empty() {
        let name: String = sqlx::query_scalar("SELECT name FROM hosts WHERE id = $1")
            .bind(host_id)
            .fetch_one(&mut *tx)
            .await?;
        for (cve, from, to) in changes.iter().take(MAX_EVENTS_PER_RUN) {
            sqlx::query("INSERT INTO events (kind, payload) VALUES ('host_cve_status_changed', $1)")
                .bind(json!({ "host_id": host_id, "host": name, "cve_id": cve, "from": from, "to": to.as_str(),
                              "watched": watched.contains(cve) }))
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("SELECT pg_notify('pw_events', '')")
            .execute(&mut *tx)
            .await?;
    }

    hostops::recompute_host(&mut tx, host_id, stale_after, Utc::now()).await?;
    tx.commit().await?;
    Ok(changes.len())
}

/// Live-Bewertung für Zellen ohne gespeicherten Status (Matrix): `(host_id, cve_id) -> Verdict`.
pub async fn evaluate_live(
    pool: &PgPool,
    host_ids: &[i64],
    cve_ids: &[String],
) -> Result<HashMap<(i64, String), Verdict>> {
    let mut conn = pool.acquire().await?;
    let mut out = HashMap::new();
    for &hid in host_ids {
        let Some(host) = load_host(&mut conn, hid).await? else {
            continue;
        };
        let kernel = host.kernel();
        let rows = match (
            kernel.codename.as_deref(),
            eval::tracker_package(&kernel.distro_id, kernel.source.as_deref()),
        ) {
            (Some(rel), Some(pkg)) if !eval::is_proxmox_kernel(&kernel) => {
                load_rows(&mut conn, cve_ids, rel, &pkg).await?
            }
            _ => HashMap::new(),
        };
        for c in cve_ids {
            out.insert(
                (hid, c.clone()),
                eval::evaluate(&kernel, rows.get(c).map_or(&[][..], Vec::as_slice)),
            );
        }
    }
    Ok(out)
}

#[derive(sqlx::FromRow)]
struct HostKey {
    id: i64,
    os_id: Option<String>,
    os_codename: Option<String>,
    kernel_source: Option<String>,
}

/// Hosts, deren Kernel zu den geänderten (Release, Paket)-Paaren passt, neu bewerten.
pub async fn reevaluate_affected(
    state: &AppState,
    pairs: &HashSet<(String, String)>,
) -> Result<usize> {
    let hosts: Vec<HostKey> = sqlx::query_as(
        "SELECT id, os_id, os_codename, kernel_source FROM hosts WHERE running_kernel IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await?;
    let stale_after = Duration::hours(state.cfg.stale_after_hours);
    let mut n = 0;
    for h in hosts {
        let hit = match (
            h.os_codename,
            eval::tracker_package(h.os_id.as_deref().unwrap_or(""), h.kernel_source.as_deref()),
        ) {
            (Some(c), Some(p)) => pairs.contains(&(c, p)),
            _ => false,
        };
        if hit {
            match evaluate_host(&state.pool, h.id, stale_after).await {
                Ok(_) => n += 1,
                Err(e) => tracing::error!(host = h.id, error = %e, "Neubewertung fehlgeschlagen"),
            }
        }
    }
    Ok(n)
}

/// Alle Hosts neu bewerten (z. B. nach Änderung der Watchlist).
pub async fn reevaluate_all(state: &AppState) -> Result<usize> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM hosts WHERE running_kernel IS NOT NULL")
        .fetch_all(&state.pool)
        .await?;
    let stale_after = Duration::hours(state.cfg.stale_after_hours);
    let mut n = 0;
    for id in ids {
        match evaluate_host(&state.pool, id, stale_after).await {
            Ok(_) => n += 1,
            Err(e) => tracing::error!(host = id, error = %e, "Neubewertung fehlgeschlagen"),
        }
    }
    Ok(n)
}

/// Host-Kernels für Quellen mit versionsbezogener Abfrage (OSV); Proxmox-Kernel werden ausgelassen.
pub async fn host_refs(pool: &PgPool) -> Result<Vec<HostRef>> {
    let rows: Vec<HostRow> = sqlx::query_as(&format!(
        "SELECT {HOST_COLS} FROM hosts WHERE running_kernel IS NOT NULL AND kernel_package_version IS NOT NULL"
    ))
    .fetch_all(pool)
    .await?;
    let mut out = HashSet::new();
    for r in rows {
        let k = r.kernel();
        if eval::is_proxmox_kernel(&k) {
            continue;
        }
        if let (Some(codename), Some(version), Some(os_version), Some(package)) = (
            r.os_codename.clone(),
            r.kernel_package_version.clone(),
            r.os_version.clone(),
            eval::tracker_package(&k.distro_id, k.source.as_deref()),
        ) {
            out.insert(HostRef {
                distro_id: k.distro_id,
                os_version,
                codename,
                package,
                version,
            });
        }
    }
    Ok(out.into_iter().collect())
}
