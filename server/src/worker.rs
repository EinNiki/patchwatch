use crate::hostops;
use crate::jobs::{self, Job};
use crate::live;
use crate::notify::{self, events, store};
use crate::state::AppState;
use chrono::Utc;
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

/// Events -> Benachrichtigungen (in einer Transaktion, `SKIP LOCKED`). Je aktivem Kanal, der die
/// Ereignisart abonniert hat, entsteht ein eigener Job (eigene Wiederholungen); der Browser-Kanal geht direkt
/// über NOTIFY an die WebSocket-Clients.
pub async fn process_events(state: &AppState) -> anyhow::Result<usize> {
    let channels: Vec<store::Effective> = store::load_all(&state.pool, &state.cfg)
        .await?
        .into_iter()
        .filter(|c| c.enabled)
        .collect();
    let my_releases: std::collections::HashSet<String> = sqlx::query_scalar(
        "SELECT DISTINCT os_codename FROM hosts WHERE os_codename IS NOT NULL AND os_codename <> ''",
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .collect();
    let mut tx = state.pool.begin().await?;
    let events: Vec<(i64, String, Value)> = sqlx::query_as(
        "SELECT id, kind, payload FROM events WHERE processed_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 50",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (id, kind, payload) in &events {
        // UI-Aktualisierung unabhängig von Benachrichtigungskanälen.
        let live_type = match kind.as_str() {
            "host_status_changed" => Some("host_status"),
            "host_cve_status_changed" => Some("host_cve_status"),
            _ => None,
        };
        if let Some(t) = live_type {
            live::notify(
                &mut tx,
                t,
                payload.get("host_id").and_then(Value::as_i64),
                payload.get("cve_id").and_then(Value::as_str),
            )
            .await;
        }
        if !channels.is_empty() {
            let cve_id = payload.get("cve_id").and_then(Value::as_str).unwrap_or("");
            // Nur Watchlist-CVEs sind eine Meldung wert.
            let watched: bool = if matches!(kind.as_str(), "cve_new" | "cve_status_changed") {
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM cve_watchlist WHERE cve_id = $1)")
                    .bind(cve_id)
                    .fetch_one(&mut *tx)
                    .await?
            } else {
                false
            };
            if let Some((category, m)) = events::route(kind, payload, watched, &my_releases) {
                for ch in channels.iter().filter(|c| c.subscribes(category)) {
                    if ch.kind == "browser" {
                        live::publish(&mut tx, &browser_payload(&m)).await;
                        continue;
                    }
                    let job = json!({
                        "channel": ch.kind, "title": m.title, "body": m.body,
                        "priority": m.priority, "tags": m.tags,
                    });
                    jobs::enqueue(&mut tx, "notify", job, Utc::now(), None).await?;
                }
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

fn browser_payload(m: &notify::Message) -> Value {
    let level = if m.priority >= 4 {
        "crit"
    } else if m.priority == 3 {
        "warn"
    } else {
        "info"
    };
    json!({ "type": "notification", "title": m.title, "body": m.body, "level": level })
}

/// Sendet über einen Kanal und merkt sich das (generische) Ergebnis.
async fn deliver(state: &AppState, kind: &str, msg: &notify::Message) -> anyhow::Result<()> {
    let Some(ch) = store::load(&state.pool, &state.cfg, kind).await? else {
        return Ok(());
    };
    // Zwischenzeitlich abgeschaltet: Nachricht verwerfen.
    if !ch.enabled {
        return Ok(());
    }
    let result = match ch.build(&state.cfg, &state.pool) {
        Ok(c) => c.send(msg).await,
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => {
            store::record_result(&state.pool, kind, Ok(())).await;
            Ok(())
        }
        Err(e) => {
            let summary = e.summary();
            tracing::warn!(channel = kind, error = %summary, "Benachrichtigung fehlgeschlagen");
            store::record_result(&state.pool, kind, Err(&summary)).await;
            anyhow::bail!("{kind}: {summary}")
        }
    }
}

async fn handle_job(state: &AppState, job: &Job) -> anyhow::Result<()> {
    match job.kind.as_str() {
        "notify" => {
            let p = &job.payload;
            let text = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            let tags: Vec<&'static str> = p
                .get("tags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(known_tag)
                .collect();
            let priority = p
                .get("priority")
                .and_then(Value::as_u64)
                .unwrap_or(3)
                .clamp(1, 5) as u8;
            let msg = notify::Message {
                title: text("title"),
                body: text("body"),
                priority,
                tags,
            };
            deliver(state, &text("channel"), &msg).await
        }
        "cleanup" => cleanup(state).await,
        "daily_summary" => {
            let kind = job
                .payload
                .get("channel")
                .and_then(Value::as_str)
                .unwrap_or("");
            let msg = notify::daily_summary_message(&state.pool).await?;
            deliver(state, kind, &msg).await
        }
        other => anyhow::bail!("unbekannter Job-Typ {other}"),
    }
}

/// Entfernt alte Reports (Aufbewahrung konfigurierbar), abgelaufene Sessions, erledigte Jobs/Events.
pub async fn cleanup(state: &AppState) -> anyhow::Result<()> {
    let days = crate::routes::settings::retention_days(&state.pool, state.cfg.report_retention_days)
        .await as f64;
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

/// Tags der Nachrichten sind feste Zeichenketten; aus der Job-Queue werden nur bekannte wieder zugelassen.
fn known_tag(t: &str) -> Option<&'static str> {
    [
        "warning",
        "hourglass",
        "white_check_mark",
        "information_source",
        "mag",
        "bar_chart",
    ]
    .into_iter()
    .find(|k| *k == t)
}

/// Serverseitiger Report-Zeitplan: zur fälligen Zeit wird bei allen Hosts ein Report angefordert.
/// Das Beanspruchen des Laufs ist atomar (auch bei mehreren Instanzen kein doppeltes Auslösen).
async fn request_reports_if_due(state: &AppState) -> anyhow::Result<()> {
    let sched = crate::schedule::report_schedule(&state.pool).await;
    let now = Utc::now();
    let last = crate::schedule::reports_last_run(&state.pool).await;
    let Some(due) = sched.last_due(last, now) else {
        return Ok(());
    };
    if crate::schedule::claim_report_run(&state.pool, due, now).await? {
        let (requested, total) = crate::routes::hosts::request_all(&state.pool).await?;
        tracing::info!(requested, total, "Geplante Report-Anforderung");
    }
    Ok(())
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
    let stale_after = crate::schedule::stale_after(&state.pool, state.cfg.stale_after_hours).await;
    hostops::mark_stale_hosts(&state.pool, stale_after).await?;
    request_reports_if_due(state).await?;

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

    // Tageszusammenfassung: je Kanal mit eigener Uhrzeit und Zeitzone (Voreinstellung aus der Server-Konfiguration).
    for ch in store::load_all(&state.pool, &state.cfg).await? {
        if !ch.enabled || !ch.subscribes(events::DAILY_SUMMARY) {
            continue;
        }
        let tz = ch
            .timezone
            .as_deref()
            .and_then(|t| t.parse::<chrono_tz::Tz>().ok())
            .unwrap_or_else(|| state.cfg.tz());
        let local = now.with_timezone(&tz);
        if local.time() >= ch.summary_time.unwrap_or_else(|| state.cfg.summary_time()) {
            let key = format!("daily:{}:{}", ch.kind, local.date_naive());
            jobs::enqueue(
                &mut conn,
                "daily_summary",
                json!({ "channel": ch.kind }),
                now,
                Some(&key),
            )
            .await?;
        }
    }
    Ok(())
}
