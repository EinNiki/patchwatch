//! Feed-Abruf mit Fehlerrobustheit: Bei Fehlern bleibt der alte Stand erhalten, der Fehler wird gespeichert
//! und im UI sichtbar ("veraltet seit …"); ein Feed wird nie stillschweigend als gesund gewertet.

use super::http::jitter;
use super::{ingest, reeval, sources, CveSource, FeedState, FetchCtx, FetchOutcome, Record};
use crate::state::AppState;
use anyhow::Result;
use std::time::Duration;

/// Ab so vielen Fehlschlägen in Folge gibt es eine Benachrichtigung.
const ALERT_AFTER_FAILURES: i32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    NotModified,
    Updated {
        changed_rows: usize,
        events: usize,
    },
    /// Teilabruf: Daten sind gespeichert, aber eine Lücke ist noch offen (Rückstandsabbau); nie "grün".
    Incomplete {
        changed_rows: usize,
        events: usize,
    },
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
    #[allow(clippy::type_complexity)]
    let (etag, last_modified, cursor, backfill, covered): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<serde_json::Value>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT etag, last_modified, cursor, backfill, covered_since FROM feed_state WHERE source = $1",
    )
    .bind(name)
    .fetch_one(&state.pool)
    .await?;
    Ok(FeedState {
        etag,
        last_modified,
        cursor,
        // Ein unlesbarer Eintrag zählt als "kein Fortschritt": der Abruf beginnt dann wieder vorn.
        backfill: backfill.and_then(|v| serde_json::from_value(v).ok()),
        covered_since: covered.map(|t| t.to_rfc3339()),
    })
}

async fn context(state: &AppState, id: &str, kind: &str) -> Result<FetchCtx> {
    let watch_missing = sqlx::query_scalar(
        "SELECT w.cve_id FROM cve_watchlist w WHERE NOT EXISTS \
         (SELECT 1 FROM cve_source_status s WHERE s.cve_id = w.cve_id AND s.source_id = $1) ORDER BY w.cve_id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let hosts = if kind == "osv" {
        reeval::host_refs(&state.pool).await?
    } else {
        Vec::new()
    };
    // Anreicherung (NVD): nur bereits bekannte CVEs, die für Hosts relevant sind oder auf der Watchlist stehen.
    let enrich = if kind == "nvd" {
        sqlx::query_scalar(
            "SELECT c.id FROM cves c WHERE NOT EXISTS (SELECT 1 FROM cve_source_status s WHERE s.cve_id = c.id AND s.source_id = $1) \
             AND (EXISTS (SELECT 1 FROM cve_watchlist w WHERE w.cve_id = c.id) OR EXISTS (SELECT 1 FROM host_cve_status h WHERE h.cve_id = c.id)) \
             ORDER BY EXISTS (SELECT 1 FROM cve_watchlist w WHERE w.cve_id = c.id) DESC, c.id LIMIT 200",
        )
        .bind(id)
        .fetch_all(&state.pool)
        .await?
    } else {
        Vec::new()
    };
    Ok(FetchCtx {
        watch_missing,
        hosts,
        enrich,
    })
}

/// Bis wann ein vollständiger Abruf als frisch gilt: max(3 x Intervall, 6 Stunden).
async fn usable_until(state: &AppState, name: &str) -> chrono::DateTime<chrono::Utc> {
    let minutes = crate::schedule::feed_interval_minutes(
        &state.pool,
        name,
        state.cfg.cve.interval_minutes as i64,
    )
    .await;
    chrono::Utc::now() + chrono::Duration::minutes((3 * minutes).max(6 * 60))
}

/// Host-Status der Distribution neu berechnen, weil sich die Nutzbarkeit der Quelle geändert haben kann.
/// Fehler werden nur protokolliert: der Abruf selbst ist davon unabhängig.
async fn gate_hosts(state: &AppState, kind: Option<&str>) {
    let stale_after = crate::schedule::stale_after(&state.pool, state.cfg.stale_after_hours).await;
    if let Err(e) = crate::hostops::recompute_cve_gated_hosts(&state.pool, kind, stale_after).await
    {
        tracing::warn!(error = %e, "Host-Status nach Quellenänderung nicht aktualisiert");
    }
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
    // Ab dem 3. Fehlschlag in Folge gilt die Quelle als dauerhaft fehlerhaft und ist nicht mehr nutzbar.
    gate_hosts(state, None).await;
    Ok(())
}

/// Anreicherungsquellen (OSV, NVD, CISA KEV) dürfen nie neue CVEs anlegen: nur Records zu bereits bekannten CVEs
/// (Tabelle `cves`, Watchlist-CVEs stehen dort ebenfalls) werden übernommen. Beschreibung und Priorität, die schon
/// aus Debian/Ubuntu stammen, bleiben unangetastet.
async fn restrict_to_known(state: &AppState, records: Vec<Record>) -> Result<Vec<Record>> {
    let ids: Vec<String> = records.iter().map(|r| r.cve_id.clone()).collect();
    let known: std::collections::HashMap<String, (bool, bool)> =
        sqlx::query_as::<_, (String, bool, bool)>(
            "SELECT id, description IS NOT NULL, priority IS NOT NULL FROM cves WHERE id = ANY($1)",
        )
        .bind(&ids)
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(|(id, d, p)| (id, (d, p)))
        .collect();
    Ok(records
        .into_iter()
        .filter_map(|mut r| {
            let (has_desc, has_prio) = *known.get(&r.cve_id)?;
            if has_desc {
                r.description = None;
            }
            if has_prio {
                r.priority = None;
            }
            Some(r)
        })
        .collect())
}

/// Ruft eine Quelle ab und führt Buch über Erfolg und Misserfolg.
pub async fn refresh_source(state: &AppState, id: &str, src: &dyn CveSource) -> Result<Outcome> {
    // `kind` ist der Typ der Quelle (steht in cve_source_status.source), `name` die stabile ID für Feed-Zustand und Meldungen.
    let kind = src.name();
    let name = id;
    let feed_state = load_state(state, name).await?;
    let ctx = context(state, id, kind).await?;

    match src.fetch(&state.http, &feed_state, &ctx).await {
        Ok(FetchOutcome::NotModified) => {
            // Nichts Neues, aber ein vollständiger, erfolgreicher Abruf: die Quelle ist wieder frisch.
            let until = usable_until(state, name).await;
            sqlx::query("UPDATE feed_state SET last_success_at = now(), last_error = NULL, consecutive_failures = 0, usable_until = $2 WHERE source = $1")
                .bind(name)
                .bind(until)
                .execute(&state.pool)
                .await?;
            // Ein offener Abbau bleibt offen (NotModified wird dann nie geliefert); nur den Host-Status auffrischen.
            gate_hosts(state, Some(kind)).await;
            Ok(Outcome::NotModified)
        }
        Ok(FetchOutcome::Records {
            records,
            state: new_state,
        }) => store(state, kind, id, records, new_state, None).await,
        Ok(FetchOutcome::Partial {
            records,
            state: new_state,
            interrupted,
        }) => store(state, kind, id, records, new_state, Some(interrupted)).await,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(source = name, error = %msg, "Feed-Abruf fehlgeschlagen, alter Stand bleibt erhalten");
            record_failure(state, name, &msg).await?;
            Ok(Outcome::Failed(msg))
        }
    }
}

/// Speichert die Records eines Abrufs zusammen mit dem Feed-Zustand in einer Transaktion: schlägt das Speichern
/// fehl, bleibt der alte Stand. `partial` ist `None` bei einem vollständigen Abruf; bei einem Teilabruf
/// (`Some`) bleibt der bestätigte Cursor unverändert, der Fortschritt wird gespeichert, `last_success_at` rückt
/// nicht vor und der Feed bleibt unvollständig (nie "ok"). `Some(Some(fehler))` heißt: der Lauf brach mittendrin ab.
async fn store(
    state: &AppState,
    kind: &str,
    name: &str,
    records: Vec<Record>,
    new_state: FeedState,
    partial: Option<Option<String>>,
) -> Result<Outcome> {
    let enrich = sources::enrich_only(kind);
    let records = if enrich {
        restrict_to_known(state, records).await?
    } else {
        records
    };
    let mut tx = state.pool.begin().await?;
    let stats = match ingest::ingest_with(&mut tx, kind, name, &records, !enrich).await {
        Ok(s) => s,
        Err(e) => {
            drop(tx);
            let msg = format!("Speichern fehlgeschlagen: {e}");
            record_failure(state, name, &msg).await?;
            return Ok(Outcome::Failed(msg));
        }
    };
    let backfill = new_state
        .backfill
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    match &partial {
        None => {
            let until = usable_until(state, name).await;
            let covered = new_state
                .covered_since
                .as_deref()
                .and_then(|c| chrono::DateTime::parse_from_rfc3339(c).ok());
            sqlx::query(
                "UPDATE feed_state SET etag = $2, last_modified = $3, cursor = $4, backfill = $5, \
                 last_success_at = now(), last_error = NULL, consecutive_failures = 0, usable_until = $6, \
                 covered_since = COALESCE($7, covered_since) WHERE source = $1",
            )
            .bind(name)
            .bind(&new_state.etag)
            .bind(&new_state.last_modified)
            .bind(&new_state.cursor)
            .bind(&backfill)
            .bind(until)
            .bind(covered)
            .execute(&mut *tx)
            .await?;
        }
        Some(interrupted) => {
            // Fortschritt zählt nicht als Fehlschlag (kein Alarm); ein Abbruch mittendrin bleibt aber sichtbar.
            sqlx::query(
                "UPDATE feed_state SET etag = $2, last_modified = $3, cursor = $4, backfill = $5, \
                 last_error = $6, last_error_at = CASE WHEN $6::text IS NULL THEN last_error_at ELSE now() END, \
                 consecutive_failures = 0 WHERE source = $1",
            )
            .bind(name)
            .bind(&new_state.etag)
            .bind(&new_state.last_modified)
            .bind(&new_state.cursor)
            .bind(&backfill)
            .bind(interrupted.as_deref().map(|m| format!("Lauf unterbrochen: {m}")))
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    let hosts = reeval::reevaluate_affected(state, &stats.changed_pairs).await?;
    // Ob die Quelle für die Bewertung nutzbar ist, kann sich geändert haben (Abbau fertig, Teilabruf, ...).
    gate_hosts(state, Some(kind)).await;
    tracing::info!(
        source = name,
        records = records.len(),
        changed_rows = stats.changed_rows,
        new_cves = stats.new_cves,
        hosts_reevaluated = hosts,
        incomplete = partial.is_some(),
        "Feed aktualisiert"
    );
    let (changed_rows, events) = (stats.changed_rows, stats.events);
    Ok(if partial.is_some() {
        Outcome::Incomplete {
            changed_rows,
            events,
        }
    } else {
        Outcome::Updated {
            changed_rows,
            events,
        }
    })
}

/// Alle eingeschalteten Quellen nacheinander abrufen (Ergebnis je stabiler Quellen-ID). Abgeschaltete oder gelöschte
/// Quellen werden nicht abgerufen (und nie als "ok" gezeigt).
pub async fn refresh_all(state: &AppState) -> Vec<(String, Outcome)> {
    let mut out = Vec::new();
    for b in sources::build_enabled(state).await {
        match b.source {
            Ok(src) => match refresh_source(state, &b.id, src.as_ref()).await {
                Ok(o) => out.push((b.id, o)),
                Err(e) => {
                    tracing::error!(source = %b.id, error = %e, "Feed-Verarbeitung fehlgeschlagen");
                    out.push((b.id, Outcome::Failed(e.to_string())));
                }
            },
            Err(e) => {
                let msg = fail_unbuildable(state, &b.id, &e).await;
                out.push((b.id, Outcome::Failed(msg)));
            }
        }
    }
    out
}

/// Eine nicht baubare Quelle (z. B. Spiegel nicht mehr erlaubt, Schlüssel nicht entschlüsselbar) zählt als Fehlschlag.
async fn fail_unbuildable(state: &AppState, name: &str, e: &anyhow::Error) -> String {
    let msg = format!("Quelle nicht nutzbar: {e}");
    if sqlx::query("INSERT INTO feed_state (source) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(name)
        .execute(&state.pool)
        .await
        .is_ok()
    {
        let _ = sqlx::query("UPDATE feed_state SET last_attempt_at = now() WHERE source = $1")
            .bind(name)
            .execute(&state.pool)
            .await;
        let _ = record_failure(state, name, &msg).await;
    }
    msg
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
            for b in sources::build_enabled(&state).await {
                let name = b.id.clone();
                let built = b.source;
                let minutes = crate::schedule::feed_interval_minutes(
                    &state.pool,
                    &name,
                    state.cfg.cve.interval_minutes as i64,
                )
                .await;
                let last: Option<chrono::DateTime<chrono::Utc>> =
                    sqlx::query_scalar("SELECT last_attempt_at FROM feed_state WHERE source = $1")
                        .bind(&name)
                        .fetch_optional(&state.pool)
                        .await
                        .ok()
                        .flatten()
                        .flatten();
                if !is_due(last, minutes, chrono::Utc::now()) {
                    continue;
                }
                match built {
                    Ok(src) => {
                        if let Err(e) = refresh_source(&state, &name, src.as_ref()).await {
                            tracing::error!(source = name, error = %e, "Feed-Verarbeitung fehlgeschlagen");
                        }
                    }
                    Err(e) => {
                        fail_unbuildable(&state, &name, &e).await;
                    }
                }
            }
        }
        // Zeitabhängig: eine Quelle kann auch ohne neuen Abruf veralten; dann dürfen Hosts nicht grün bleiben.
        gate_hosts(&state, None).await;
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
