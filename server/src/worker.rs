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
    let sources = crate::cve::sources::purge_deleted(&state.pool).await?;
    // Aktivitätsprotokoll: Aufbewahrung in Tagen (Setting `audit.retention_days`, Standard 365, mindestens 30).
    let days: i64 = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM settings WHERE key = 'audit.retention_days'",
    )
    .fetch_optional(&state.pool)
    .await?
    .and_then(|v| v.as_i64())
    .unwrap_or(365)
    .clamp(30, 3650);
    crate::audit::purge_older_than(&state.pool, days).await?;
    tracing::info!(
        reports_deleted = reports,
        sources_purged = sources,
        "Cleanup abgeschlossen"
    );
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

/// Dedupe-Schlüssel der Tageszusammenfassung, sobald die lokale Uhrzeit `at` erreicht ist (sonst `None`). Der
/// Schlüssel enthält das lokale Datum: der Minuten-Scheduler stellt den Job beliebig oft ein, versendet wird je Kanal
/// und Kalendertag genau einmal (`ON CONFLICT (dedupe_key) DO NOTHING`), auch an 23- und 25-Stunden-Tagen.
pub fn daily_summary_key(
    kind: &str,
    now: chrono::DateTime<Utc>,
    tz: chrono_tz::Tz,
    at: chrono::NaiveTime,
) -> Option<String> {
    let local = now.with_timezone(&tz);
    (local.time() >= at).then(|| format!("daily:{kind}:{}", local.date_naive()))
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
        let at = ch.summary_time.unwrap_or_else(|| state.cfg.summary_time());
        if let Some(key) = daily_summary_key(&ch.kind, now, tz, at) {
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

#[cfg(test)]
mod tests {
    use super::daily_summary_key;
    use chrono::{DateTime, Duration, NaiveTime, Utc};
    use std::collections::BTreeMap;

    /// Minuten-Scheduler über den Berliner Kalendertag simulieren: Schlüssel je lokalem Datum mit dem ersten
    /// Zeitpunkt, an dem er entsteht (ein Schlüssel = ein Versand).
    fn keys_for(from: &str, to: &str, at: &str) -> BTreeMap<String, DateTime<Utc>> {
        let tz: chrono_tz::Tz = "Europe/Berlin".parse().unwrap();
        let at = NaiveTime::parse_from_str(at, "%H:%M").unwrap();
        let (mut t, end) = (
            from.parse::<DateTime<Utc>>().unwrap(),
            to.parse::<DateTime<Utc>>().unwrap(),
        );
        let mut out = BTreeMap::new();
        while t < end {
            if let Some(k) = daily_summary_key("email", t, tz, at) {
                out.entry(k).or_insert(t);
            }
            t += Duration::minutes(1);
        }
        out
    }

    #[test]
    fn daily_summary_once_on_spring_forward_day() {
        // 29.03.2026 (letzter Sonntag im März, 23-Stunden-Tag): Berliner Tag = 28.03. 23:00Z bis 29.03. 22:00Z.
        // 08:00 existiert: genau ein Versand um 08:00 Sommerzeit = 06:00 UTC.
        let k = keys_for("2026-03-28T23:00:00Z", "2026-03-29T22:00:00Z", "08:00");
        assert_eq!(k.len(), 1, "{k:?}");
        assert_eq!(
            k["daily:email:2026-03-29"],
            "2026-03-29T06:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        // 02:30 existiert an diesem Tag nicht: genau ein Versand zum ersten Zeitpunkt danach (03:00 = 01:00 UTC).
        let k = keys_for("2026-03-28T23:00:00Z", "2026-03-29T22:00:00Z", "02:30");
        assert_eq!(k.len(), 1, "{k:?}");
        assert_eq!(
            k["daily:email:2026-03-29"],
            "2026-03-29T01:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn daily_summary_once_on_fall_back_day() {
        // 25.10.2026 (letzter Sonntag im Oktober, 25-Stunden-Tag): Berliner Tag = 24.10. 22:00Z bis 25.10. 23:00Z.
        let k = keys_for("2026-10-24T22:00:00Z", "2026-10-25T23:00:00Z", "08:00");
        assert_eq!(k.len(), 1, "{k:?}");
        assert_eq!(
            k["daily:email:2026-10-25"],
            "2026-10-25T07:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        // 02:30 kommt zweimal vor: der Schlüssel entsteht beim ersten (00:30 UTC), das zweite ergibt denselben Schlüssel.
        let k = keys_for("2026-10-24T22:00:00Z", "2026-10-25T23:00:00Z", "02:30");
        assert_eq!(k.len(), 1, "{k:?}");
        assert_eq!(
            k["daily:email:2026-10-25"],
            "2026-10-25T00:30:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }
}
