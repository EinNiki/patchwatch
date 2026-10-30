use crate::hostops;
use crate::jobs::{self, Job};
use crate::notify;
use crate::state::AppState;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::postgres::PgListener;
use std::time::Duration as StdDuration;

/// Verarbeitet unverarbeitete Events und fällige Jobs; wacht per LISTEN/NOTIFY oder nach 15 s auf.
pub async fn run(state: AppState) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(&state.pool).await?;
    listener.listen_all(["pw_events", "pw_jobs"]).await?;
    loop {
        if let Err(e) = tick(&state).await {
            tracing::error!(error = %e, "Worker-Durchlauf fehlgeschlagen");
        }
        let _ = tokio::time::timeout(StdDuration::from_secs(15), listener.recv()).await;
    }
}

pub async fn tick(state: &AppState) -> anyhow::Result<()> {
    while process_events(state).await? > 0 {}
    while let Some(job) = jobs::claim(&state.pool).await? {
        match handle_job(state, &job).await {
            Ok(()) => jobs::complete(&state.pool, job.id).await?,
            Err(e) => {
                tracing::warn!(job = job.id, kind = %job.kind, attempt = job.attempts, error = %e, "Job fehlgeschlagen");
                jobs::fail(&state.pool, &job, &e.to_string()).await?;
            }
        }
    }
    Ok(())
}

/// Events -> Benachrichtigungs-Jobs (in einer Transaktion, `SKIP LOCKED`).
pub async fn process_events(state: &AppState) -> anyhow::Result<usize> {
    let mut tx = state.pool.begin().await?;
    let events: Vec<(i64, String, Value)> = sqlx::query_as(
        "SELECT id, kind, payload FROM events WHERE processed_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 50",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (id, kind, payload) in &events {
        if kind == "host_status_changed" && state.cfg.ntfy.enabled() {
            let s = |k: &str| payload.get(k).and_then(Value::as_str).unwrap_or("");
            if let Some(m) = notify::status_change_message(s("name"), s("from"), s("to")) {
                let msg = json!({ "title": m.title, "body": m.body, "priority": m.priority, "tags": m.tags });
                jobs::enqueue(&mut tx, "notify", msg, Utc::now(), None).await?;
            }
        }
        sqlx::query("UPDATE events SET processed_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(events.len())
}

async fn handle_job(state: &AppState, job: &Job) -> anyhow::Result<()> {
    match job.kind.as_str() {
        "notify" => {
            let p = &job.payload;
            let text = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            let tags: Vec<String> = p
                .get("tags")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let tags: Vec<&str> = tags.iter().map(String::as_str).collect();
            let prio = p
                .get("priority")
                .and_then(Value::as_u64)
                .unwrap_or(3)
                .clamp(1, 5) as u8;
            notify::send(
                &state.http,
                &state.cfg.ntfy,
                &text("title"),
                &text("body"),
                prio,
                &tags,
            )
            .await
        }
        "cleanup" => cleanup(state).await,
        "daily_summary" => daily_summary(state).await,
        other => anyhow::bail!("unbekannter Job-Typ {other}"),
    }
}

/// Entfernt alte Reports (Aufbewahrung konfigurierbar), abgelaufene Sessions, erledigte Jobs/Events.
pub async fn cleanup(state: &AppState) -> anyhow::Result<()> {
    let days = state.cfg.report_retention_days as f64;
    let reports = sqlx::query(
        "DELETE FROM reports WHERE received_at < now() - make_interval(days => $1::int)",
    )
    .bind(days as i32)
    .execute(&state.pool)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM jobs WHERE done_at < now() - interval '7 days'")
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM events WHERE processed_at < now() - interval '30 days'")
        .execute(&state.pool)
        .await?;
    tracing::info!(reports_deleted = reports, "Cleanup abgeschlossen");
    Ok(())
}

async fn daily_summary(state: &AppState) -> anyhow::Result<()> {
    if !state.cfg.ntfy.enabled() {
        return Ok(());
    }
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, count(*) FROM hosts GROUP BY status ORDER BY status")
            .fetch_all(&state.pool)
            .await?;
    let total: i64 = rows.iter().map(|r| r.1).sum();
    let attention: i64 = rows.iter().filter(|r| r.0 != "ok").map(|r| r.1).sum();
    let lines: Vec<String> = rows
        .iter()
        .map(|(s, n)| format!("{n} × {}", crate::status::HostStatus::label_de(s)))
        .collect();
    let (title, prio) = if attention == 0 {
        (format!("Tagesübersicht: alle {total} Hosts aktuell"), 2)
    } else {
        (
            format!("Tagesübersicht: {attention} von {total} Hosts mit Handlungsbedarf"),
            3,
        )
    };
    let body = if lines.is_empty() {
        "Keine Hosts angelegt.".to_owned()
    } else {
        lines.join("\n")
    };
    notify::send(
        &state.http,
        &state.cfg.ntfy,
        &title,
        &body,
        prio,
        &["bar_chart"],
    )
    .await
}

/// Minütlicher Scheduler: Stale-Erkennung, tägliches Cleanup, Tageszusammenfassung.
pub async fn scheduler(state: AppState) {
    let mut interval = tokio::time::interval(StdDuration::from_secs(60));
    loop {
        interval.tick().await;
        if let Err(e) = schedule_once(&state).await {
            tracing::error!(error = %e, "Scheduler-Durchlauf fehlgeschlagen");
        }
    }
}

pub async fn schedule_once(state: &AppState) -> anyhow::Result<()> {
    let stale_after = Duration::hours(state.cfg.stale_after_hours);
    hostops::mark_stale_hosts(&state.pool, stale_after).await?;

    let now = Utc::now();
    let mut conn = state.pool.acquire().await?;
    jobs::enqueue(
        &mut conn,
        "cleanup",
        json!({}),
        now,
        Some(&format!("cleanup:{}", now.date_naive())),
    )
    .await?;

    let local = now.with_timezone(&state.cfg.tz());
    if state.cfg.ntfy.enabled() && local.time() >= state.cfg.summary_time() {
        let key = format!("daily:{}", local.date_naive());
        jobs::enqueue(&mut conn, "daily_summary", json!({}), now, Some(&key)).await?;
    }
    Ok(())
}
