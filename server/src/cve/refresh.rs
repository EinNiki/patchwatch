//! Feed-Abruf mit Fehlerrobustheit: Bei Fehlern bleibt der alte Stand erhalten, der Fehler wird gespeichert
//! und im UI sichtbar ("veraltet seit …"); ein Feed wird nie stillschweigend als gesund gewertet.

use super::debian::Debian;
use super::http::jitter;
use super::osv::Osv;
use super::ubuntu::Ubuntu;
use super::{ingest, reeval, CveSource, FeedState, FetchCtx, FetchOutcome};
use crate::state::AppState;
use anyhow::Result;
use std::time::Duration;

/// Ab so vielen Fehlschlägen in Folge gibt es eine Benachrichtigung.
const ALERT_AFTER_FAILURES: i32 = 3;

pub fn build_sources(cfg: &crate::config::Config) -> Vec<Box<dyn CveSource>> {
    cfg.cve
        .sources
        .iter()
        .filter_map(|s| -> Option<Box<dyn CveSource>> {
            match s.as_str() {
                "ubuntu" => Some(Box::new(Ubuntu::new(&cfg.cve))),
                "debian" => Some(Box::new(Debian::new(&cfg.cve))),
                "osv" => Some(Box::new(Osv::new(&cfg.cve))),
                _ => None,
            }
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    NotModified,
    Updated { changed_rows: usize, events: usize },
    Failed(String),
}

async fn load_state(state: &AppState, name: &str) -> Result<FeedState> {
    sqlx::query("INSERT INTO feed_state (source) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(name)
        .execute(&state.pool)
        .await?;
    sqlx::query("UPDATE feed_state SET last_attempt_at = now() WHERE source = $1")
        .bind(name)
        .execute(&state.pool)
        .await?;
    let (etag, last_modified, cursor): (Option<String>, Option<String>, Option<String>) =
        sqlx::query_as("SELECT etag, last_modified, cursor FROM feed_state WHERE source = $1")
            .bind(name)
            .fetch_one(&state.pool)
            .await?;
    Ok(FeedState {
        etag,
        last_modified,
        cursor,
    })
}

async fn context(state: &AppState, name: &str) -> Result<FetchCtx> {
    let watch_missing = sqlx::query_scalar(
        "SELECT w.cve_id FROM cve_watchlist w WHERE NOT EXISTS \
         (SELECT 1 FROM cve_source_status s WHERE s.cve_id = w.cve_id AND s.source = $1) ORDER BY w.cve_id",
    )
    .bind(name)
    .fetch_all(&state.pool)
    .await?;
    let hosts = if name == "osv" {
        reeval::host_refs(&state.pool).await?
    } else {
        Vec::new()
    };
    Ok(FetchCtx {
        watch_missing,
        hosts,
    })
}

async fn record_failure(state: &AppState, name: &str, error: &str) -> Result<()> {
    let msg: String = error.chars().take(500).collect();
    let failures: i32 = sqlx::query_scalar(
        "UPDATE feed_state SET last_error = $2, last_error_at = now(), consecutive_failures = consecutive_failures + 1 \
         WHERE source = $1 RETURNING consecutive_failures",
    )
    .bind(name)
    .bind(&msg)
    .fetch_one(&state.pool)
    .await?;
    // Einmalige Meldung beim Überschreiten der Schwelle, nicht bei jedem weiteren Fehlschlag.
    if failures == ALERT_AFTER_FAILURES {
        sqlx::query("INSERT INTO events (kind, payload) VALUES ('feed_failing', $1)")
            .bind(serde_json::json!({ "source": name, "error": msg, "failures": failures }))
            .execute(&state.pool)
            .await?;
        sqlx::query("SELECT pg_notify('pw_events', '')")
            .execute(&state.pool)
            .await?;
    }
    Ok(())
}

/// Ruft eine Quelle ab und führt Buch über Erfolg und Misserfolg.
pub async fn refresh_source(state: &AppState, src: &dyn CveSource) -> Result<Outcome> {
    let name = src.name();
    let feed_state = load_state(state, name).await?;
    let ctx = context(state, name).await?;

    match src.fetch(&state.http, &feed_state, &ctx).await {
        Ok(FetchOutcome::NotModified) => {
            sqlx::query("UPDATE feed_state SET last_success_at = now(), last_error = NULL, consecutive_failures = 0 WHERE source = $1")
                .bind(name)
                .execute(&state.pool)
                .await?;
            Ok(Outcome::NotModified)
        }
        Ok(FetchOutcome::Records {
            records,
            state: new_state,
        }) => {
            // Daten und Feed-Zustand gemeinsam übernehmen: schlägt das Speichern fehl, bleibt der alte Stand.
            let mut tx = state.pool.begin().await?;
            let stats = match ingest::ingest(&mut tx, name, &records).await {
                Ok(s) => s,
                Err(e) => {
                    drop(tx);
                    let msg = format!("Speichern fehlgeschlagen: {e}");
                    record_failure(state, name, &msg).await?;
                    return Ok(Outcome::Failed(msg));
                }
            };
            sqlx::query(
                "UPDATE feed_state SET etag = $2, last_modified = $3, cursor = $4, last_success_at = now(), \
                 last_error = NULL, consecutive_failures = 0 WHERE source = $1",
            )
            .bind(name)
            .bind(&new_state.etag)
            .bind(&new_state.last_modified)
            .bind(&new_state.cursor)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            let hosts = reeval::reevaluate_affected(state, &stats.changed_pairs).await?;
            tracing::info!(
                source = name,
                records = records.len(),
                changed_rows = stats.changed_rows,
                new_cves = stats.new_cves,
                hosts_reevaluated = hosts,
                "Feed aktualisiert"
            );
            Ok(Outcome::Updated {
                changed_rows: stats.changed_rows,
                events: stats.events,
            })
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(source = name, error = %msg, "Feed-Abruf fehlgeschlagen, alter Stand bleibt erhalten");
            record_failure(state, name, &msg).await?;
            Ok(Outcome::Failed(msg))
        }
    }
}

/// Alle aktiven Quellen nacheinander abrufen.
pub async fn refresh_all(state: &AppState) -> Vec<(&'static str, Outcome)> {
    let mut out = Vec::new();
    for src in build_sources(&state.cfg) {
        let name = src.name();
        match refresh_source(state, src.as_ref()).await {
            Ok(o) => out.push((name, o)),
            Err(e) => {
                tracing::error!(source = name, error = %e, "Feed-Verarbeitung fehlgeschlagen");
                out.push((name, Outcome::Failed(e.to_string())));
            }
        }
    }
    out
}

/// Fällig ist eine Quelle, wenn der letzte Versuch länger als ihr Intervall zurückliegt (oder es noch keinen gab).
fn is_due(
    last_attempt: Option<chrono::DateTime<chrono::Utc>>,
    interval_minutes: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    last_attempt.is_none_or(|t| now - t >= chrono::Duration::minutes(interval_minutes))
}

/// Hintergrund-Scheduler: prüft alle 30 s, welche Quellen nach ihrem eigenen Intervall fällig sind.
/// Die Intervalle stehen in den Einstellungen und werden bei jedem Durchlauf neu gelesen (wirkt ohne Neustart).
pub async fn run(state: AppState) {
    if !state.cfg.cve.enabled {
        tracing::info!("CVE-Feeds sind deaktiviert");
        return;
    }
    tokio::time::sleep(Duration::from_secs(20) + jitter(10_000)).await;
    loop {
        // Läuft nie parallel zu einem manuell ausgelösten Abruf.
        if let Ok(_guard) = state.refresh_lock.try_lock() {
            for src in build_sources(&state.cfg) {
                let name = src.name();
                let minutes = crate::schedule::feed_interval_minutes(
                    &state.pool,
                    name,
                    state.cfg.cve.interval_minutes as i64,
                )
                .await;
                let last: Option<chrono::DateTime<chrono::Utc>> =
                    sqlx::query_scalar("SELECT last_attempt_at FROM feed_state WHERE source = $1")
                        .bind(name)
                        .fetch_optional(&state.pool)
                        .await
                        .ok()
                        .flatten()
                        .flatten();
                if !is_due(last, minutes, chrono::Utc::now()) {
                    continue;
                }
                if let Err(e) = refresh_source(&state, src.as_ref()).await {
                    tracing::error!(source = name, error = %e, "Feed-Verarbeitung fehlgeschlagen");
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(30) + jitter(2_000)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::is_due;
    use chrono::{Duration, Utc};

    #[test]
    fn due_after_interval() {
        let now = Utc::now();
        assert!(is_due(None, 60, now));
        assert!(!is_due(Some(now - Duration::minutes(59)), 60, now));
        assert!(is_due(Some(now - Duration::minutes(60)), 60, now));
    }
}
