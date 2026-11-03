use crate::status::{self, HostStatus, Snapshot};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;

/// Setzt den Host-Status; bei Änderung entsteht ein Event (und ein NOTIFY für den Worker).
pub async fn set_status(conn: &mut PgConnection, host_id: i64, new: &str) -> sqlx::Result<bool> {
    let changed: Option<(String, String)> = sqlx::query_as(
        "WITH old AS (SELECT id, status, name FROM hosts WHERE id = $1 FOR UPDATE) \
         UPDATE hosts h SET status = $2, status_changed_at = now() \
         FROM old WHERE h.id = old.id AND old.status <> $2 \
         RETURNING old.status, old.name",
    )
    .bind(host_id)
    .bind(new)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((from, name)) = changed else {
        return Ok(false);
    };
    sqlx::query("INSERT INTO events (kind, payload) VALUES ('host_status_changed', $1)")
        .bind(serde_json::json!({ "host_id": host_id, "name": name, "from": from, "to": new }))
        .execute(&mut *conn)
        .await?;
    sqlx::query("SELECT pg_notify('pw_events', '')")
        .execute(&mut *conn)
        .await?;
    Ok(true)
}

/// Nutzbar für die Bewertung ist eine Quelle (`cve_sources d`, `$2` = jetzt) nur, wenn sie mindestens einen
/// vollständigen, erfolgreichen Abruf hatte, kein Abbau (Erstabruf oder Rückstand) offen ist, der letzte Erfolg
/// nicht älter ist als max(3 x Intervall, 6 Stunden) (`usable_until`) und kein Dauerfehler vorliegt (mindestens
/// 3 Fehlschläge in Folge, wie beim Alarm).
const SOURCE_USABLE_SQL: &str = "EXISTS (SELECT 1 FROM feed_state f WHERE f.source = d.id \
     AND f.last_success_at IS NOT NULL AND f.backfill IS NULL AND f.consecutive_failures < 3 \
     AND f.usable_until > $2)";

/// SQL-Ausdruck: Für diesen Host (`h` = Tabellenalias von `hosts`) fehlt eine nutzbare CVE-Quelle. Gilt für
/// Debian/Ubuntu-Hosts außer Proxmox. Es müssen alle eingeschalteten Quellen der Distribution nutzbar sein, und
/// es muss mindestens eine geben. (Das Auswerten selbst bleibt in `eval.rs` unverändert: hier wird nur
/// entschieden, ob die Daten für ein "grün" ausreichen.)
fn cve_source_missing_sql(h: &str) -> String {
    format!(
        "(EXISTS (SELECT 1 FROM settings WHERE key = 'cve_sources.seeded') AND NOT {h}.is_proxmox \
           AND {h}.os_id IN ('debian', 'ubuntu') \
           AND (NOT EXISTS (SELECT 1 FROM cve_sources d WHERE d.kind = {h}.os_id AND d.enabled AND d.deleted_at IS NULL) \
                OR EXISTS (SELECT 1 FROM cve_sources d WHERE d.kind = {h}.os_id AND d.enabled AND d.deleted_at IS NULL \
                           AND NOT {SOURCE_USABLE_SQL})))"
    )
}

/// Berechnet den Status der Debian-/Ubuntu-Hosts (`kind` = nur diese Distribution) neu. Nötig, wenn sich die
/// Nutzbarkeit einer Quelle ändert, ohne dass ein Report oder Datenwechsel vorliegt (Abbau fertig, Fehler, Alterung).
/// `set_status` schreibt und meldet nur bei einer tatsächlichen Änderung.
pub async fn recompute_cve_gated_hosts(
    pool: &sqlx::PgPool,
    kind: Option<&str>,
    stale_after: Duration,
) -> sqlx::Result<usize> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM hosts WHERE os_id IN ('debian', 'ubuntu') AND NOT is_proxmox \
         AND ($1::text IS NULL OR os_id = $1) AND last_report_at IS NOT NULL",
    )
    .bind(kind)
    .fetch_all(pool)
    .await?;
    for id in &ids {
        let mut tx = pool.begin().await?;
        recompute_host(&mut tx, *id, stale_after, Utc::now()).await?;
        tx.commit().await?;
    }
    Ok(ids.len())
}

/// Begründung für "CVE-Lage unbekannt": welche Quelle der Distribution nicht nutzbar ist und warum.
/// `None`, wenn alle zuständigen Quellen nutzbar sind (oder der Host keine Quelle braucht).
pub async fn cve_source_issues(
    pool: &sqlx::PgPool,
) -> sqlx::Result<std::collections::HashMap<String, String>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, String, bool, Option<DateTime<Utc>>, i32, bool)> = sqlx::query_as(
        "SELECT d.kind, d.label, f.backfill IS NOT NULL, f.last_success_at, \
                COALESCE(f.consecutive_failures, 0), COALESCE(f.usable_until > now(), false) \
         FROM cve_sources d LEFT JOIN feed_state f ON f.source = d.id \
         WHERE d.enabled AND d.deleted_at IS NULL AND d.kind IN ('debian', 'ubuntu') ORDER BY d.label",
    )
    .fetch_all(pool)
    .await?;
    let mut out = std::collections::HashMap::new();
    let mut seen_kinds = std::collections::HashSet::new();
    for (kind, label, backfill, success, failures, fresh) in rows {
        seen_kinds.insert(kind.clone());
        let why = if backfill {
            "unvollständig (Abruf wird noch aufgebaut)"
        } else if success.is_none() {
            "noch nie erfolgreich abgerufen"
        } else if failures >= 3 {
            "fehlerhaft (wiederholt Fehlschläge)"
        } else if !fresh {
            "veraltet"
        } else {
            continue;
        };
        out.entry(kind)
            .or_insert_with(|| format!("Quelle {label} {why}"));
    }
    for kind in ["debian", "ubuntu"] {
        if !seen_kinds.contains(kind) {
            out.insert(kind.to_owned(), "keine aktive CVE-Quelle".to_owned());
        }
    }
    Ok(out)
}

/// Berechnet den Status aus den gespeicherten Daten neu und setzt ihn.
pub async fn recompute_host(
    conn: &mut PgConnection,
    host_id: i64,
    stale_after: Duration,
    now: DateTime<Utc>,
) -> sqlx::Result<HostStatus> {
    #[allow(clippy::type_complexity)]
    let row: (Option<DateTime<Utc>>, Option<bool>, Option<bool>, Option<i32>, Option<i32>, bool, bool) = sqlx::query_as(&format!(
        "SELECT last_report_at, reboot_required_file, reboot_needed_kernel, updates_pending, updates_security, \
         EXISTS (SELECT 1 FROM host_cve_status c WHERE c.host_id = hosts.id AND c.status = 'vulnerable'), \
         {} \
         FROM hosts WHERE id = $1",
        cve_source_missing_sql("hosts")
    ))
    .bind(host_id)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;
    let snap = Snapshot {
        last_report_at: row.0,
        reboot_required_file: row.1.unwrap_or(false),
        reboot_needed_kernel: row.2,
        updates_pending: row.3.unwrap_or(0),
        updates_security: row.4.unwrap_or(0),
        cve_vulnerable: row.5,
        cve_source_missing: row.6,
    };
    let status = status::derive(&snap, now, stale_after);
    set_status(conn, host_id, status.as_str()).await?;
    Ok(status)
}

/// Markiert Hosts als "stale", die sich zu lange nicht gemeldet haben.
pub async fn mark_stale_hosts(pool: &sqlx::PgPool, stale_after: Duration) -> sqlx::Result<usize> {
    let cutoff = Utc::now() - stale_after;
    let ids: Vec<(i64,)> = sqlx::query_as(
        "SELECT id FROM hosts WHERE last_report_at IS NOT NULL AND last_report_at < $1 AND status <> 'stale'",
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    for (id,) in &ids {
        let mut tx = pool.begin().await?;
        recompute_host(&mut tx, *id, stale_after, Utc::now()).await?;
        tx.commit().await?;
    }
    Ok(ids.len())
}
