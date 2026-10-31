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

/// Berechnet den Status aus den gespeicherten Daten neu und setzt ihn.
pub async fn recompute_host(
    conn: &mut PgConnection,
    host_id: i64,
    stale_after: Duration,
    now: DateTime<Utc>,
) -> sqlx::Result<HostStatus> {
    #[allow(clippy::type_complexity)]
    let row: (Option<DateTime<Utc>>, Option<bool>, Option<bool>, Option<i32>, Option<i32>, bool, bool) = sqlx::query_as(
        "SELECT last_report_at, reboot_required_file, reboot_needed_kernel, updates_pending, updates_security, \
         EXISTS (SELECT 1 FROM host_cve_status c WHERE c.host_id = hosts.id AND c.status = 'vulnerable'), \
         EXISTS (SELECT 1 FROM settings WHERE key = 'cve_sources.seeded') AND NOT is_proxmox \
           AND os_id IN ('debian', 'ubuntu') \
           AND NOT EXISTS (SELECT 1 FROM cve_sources d WHERE d.kind = hosts.os_id AND d.enabled AND d.deleted_at IS NULL) \
         FROM hosts WHERE id = $1",
    )
    .bind(host_id)
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
