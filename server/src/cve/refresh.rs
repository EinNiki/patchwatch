//! Feed-Abruf mit Fehlerrobustheit: Bei Fehlern bleibt der alte Stand erhalten, der Fehler wird gespeichert
//! und im UI sichtbar ("veraltet seit …"); ein Feed wird nie stillschweigend als gesund gewertet.

use super::http::jitter;
use super::runs;
use super::{
    ingest, reeval, sources, CveSource, FeedError, FeedState, FetchCtx, FetchOutcome, Record,
};
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
    /// Eine andere Instanz ruft diese Quelle gerade ab (Advisory-Lock); dieser Lauf wird ausgelassen.
    Skipped,
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
    let (etag, last_modified, cursor, backfill, covered, bulk, parked): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<serde_json::Value>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
    ) = sqlx::query_as(
        "SELECT etag, last_modified, cursor, backfill, covered_since, bulk, backfill_parked FROM feed_state WHERE source = $1",
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
        bulk: bulk.and_then(|v| serde_json::from_value(v).ok()),
        parked: parked.and_then(|v| serde_json::from_value(v).ok()),
        usable_until: None,
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
    let hosts = if kind == "osv" || kind == "ubuntu" {
        reeval::host_refs(&state.pool).await?
    } else {
        Vec::new()
    };
    // Anreicherung (NVD): nur bereits bekannte CVEs, die für Hosts relevant sind oder auf der Watchlist stehen.
    let enrich = if kind == "nvd" {
        sqlx::query_scalar(
            "SELECT c.id FROM cves c WHERE NOT EXISTS (SELECT 1 FROM cve_source_status s WHERE s.cve_id = c.id AND s.source_id = $1) \
             AND (EXISTS (SELECT 1 FROM cve_watchlist w WHERE w.cve_id = c.id) OR EXISTS (SELECT 1 FROM host_cve_status h WHERE h.cve_id = c.id AND h.status NOT IN ('fixed', 'not_affected'))) \
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
        progress: super::Heartbeat::default(),
        bulk_interval_minutes: if kind == "ubuntu" {
            crate::schedule::bulk_interval_minutes(
                &state.pool,
                id,
                state.cfg.cve.ubuntu_bulk_interval_minutes as i64,
            )
            .await
        } else {
            0
        },
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

pub(crate) async fn record_failure(
    state: &AppState,
    name: &str,
    error: &str,
    retry_after: Option<Duration>,
) -> Result<()> {
    let msg: String = error.chars().take(500).collect();
    let failures: i32 = sqlx::query_scalar(
        "UPDATE feed_state SET last_error = $2, last_error_at = now(), consecutive_failures = consecutive_failures + 1 \
         WHERE source = $1 RETURNING consecutive_failures",
    )
    .bind(name)
    .bind(&msg)
    .fetch_one(&state.pool)
    .await?;
    schedule_retry(&mut *state.pool.acquire().await?, name, retry_after).await?;
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

/// Wartezeiten nach dem 1., 2., 3. und 4. Fehllauf in Folge (Minuten); danach gilt wieder das normale Intervall.
const RETRY_LADDER_MINUTES: [i64; 4] = [2, 5, 10, 30];

/// Wartezeit bis zum nächsten Versuch nach dem `step`-ten Fehllauf in Folge (ab 1). `None` = normales Intervall.
/// Eine ausdrückliche Bitte der Quelle (`Retry-After`) verlängert die Leiter, verkürzt sie aber nie.
fn retry_gap(step: i32, retry_after: Option<Duration>) -> Option<chrono::Duration> {
    let ladder = usize::try_from(step - 1)
        .ok()
        .and_then(|i| RETRY_LADDER_MINUTES.get(i))
        .map(|m| chrono::Duration::minutes(*m));
    let asked = retry_after.and_then(|d| chrono::Duration::from_std(d).ok());
    match (ladder, asked) {
        (Some(l), Some(a)) => Some(l.max(a)),
        (l, a) => l.or(a),
    }
}

/// Zählt einen Fehllauf und legt den nächsten Versuch nach der Leiter fest (Erfolg setzt beides zurück).
async fn schedule_retry(
    conn: &mut sqlx::PgConnection,
    name: &str,
    retry_after: Option<Duration>,
) -> Result<()> {
    let step: i32 = sqlx::query_scalar(
        "UPDATE feed_state SET retry_step = retry_step + 1 WHERE source = $1 RETURNING retry_step",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await?;
    let at = retry_gap(step, retry_after).map(|g| chrono::Utc::now() + g);
    sqlx::query("UPDATE feed_state SET next_attempt_at = $2 WHERE source = $1")
        .bind(name)
        .bind(at)
        .execute(&mut *conn)
        .await?;
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

/// Schlüssel der Advisory-Sperre einer Quelle (Text, in Postgres zu einem 64-Bit-Wert gehasht).
fn lock_key(id: &str) -> String {
    format!("patchwatch.feed:{id}")
}

/// Versucht, die Sperre dieser Quelle über alle Server-Instanzen hinweg zu nehmen. Eigene, aus dem Pool gelöste
/// Verbindung: eine Sitzungssperre würde sonst mit der Verbindung in den Pool zurückkehren und hängen bleiben.
/// Wird die Verbindung geschlossen (Ende des Laufs, Abbruch der Aufgabe, Absturz), gibt Postgres die Sperre frei.
async fn try_lock_source(state: &AppState, id: &str) -> Result<Option<sqlx::PgConnection>> {
    let mut conn = state.pool.acquire().await?.detach();
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
        .bind(lock_key(id))
        .fetch_one(&mut conn)
        .await?;
    if got {
        Ok(Some(conn))
    } else {
        let _ = sqlx::Connection::close(conn).await;
        Ok(None)
    }
}

/// Ruft eine Quelle ab und führt Buch über Erfolg und Misserfolg. Je Quelle läuft über alle Instanzen höchstens ein
/// Abruf (`pg_try_advisory_lock`); ist die Sperre vergeben, wird der Lauf ausgelassen.
pub async fn refresh_source(state: &AppState, id: &str, src: &dyn CveSource) -> Result<Outcome> {
    let Some(lock) = try_lock_source(state, id).await? else {
        tracing::info!(
            source = id,
            "Feed-Abruf läuft bereits in einer anderen Instanz, ausgelassen"
        );
        return Ok(Outcome::Skipped);
    };
    let out = refresh_source_locked(state, id, src).await;
    let _ = sqlx::Connection::close(lock).await;
    out
}

/// Führt den Abruf mit Watchdog aus: meldet die Quelle länger als `stall_timeout_secs` keinen Fortschritt, wird der
/// Lauf abgebrochen (und damit die Sperre freigegeben), statt die Quelle dauerhaft als "läuft" zu blockieren.
async fn fetch_watched(
    state: &AppState,
    src: &dyn CveSource,
    feed_state: &FeedState,
    ctx: &FetchCtx,
) -> Result<FetchOutcome, FeedError> {
    let stall = Duration::from_secs(state.cfg.cve.stall_timeout_secs);
    let tick = (stall / 4).clamp(Duration::from_millis(100), Duration::from_secs(10));
    ctx.progress.beat();
    let fetch = src.fetch(&state.http, feed_state, ctx);
    tokio::pin!(fetch);
    loop {
        tokio::select! {
            r = &mut fetch => return r,
            () = tokio::time::sleep(tick) => {
                if ctx.progress.idle() > stall {
                    return Err(FeedError::Stalled(stall.as_secs().div_ceil(60)));
                }
            }
        }
    }
}

async fn refresh_source_locked(state: &AppState, id: &str, src: &dyn CveSource) -> Result<Outcome> {
    // `kind` ist der Typ der Quelle (steht in cve_source_status.source), `name` die stabile ID für Feed-Zustand und Meldungen.
    let kind = src.name();
    let name = id;
    let feed_state = load_state(state, name).await?;
    let ctx = context(state, id, kind).await?;
    // Waren Hosts dieser Distribution wegen der Quelle "unbekannt" und ist sie danach nutzbar, werden sie neu bewertet:
    // "gefixt"/"nicht betroffen" wird erst jetzt gespeichert (siehe `reeval::evaluate_host`).
    let was_gated = crate::hostops::kind_has_gated_hosts(&state.pool, kind)
        .await
        .unwrap_or(false);
    let out = refresh_inner(state, id, src, kind, name, feed_state, ctx).await?;
    if was_gated
        && !crate::hostops::kind_has_gated_hosts(&state.pool, kind)
            .await
            .unwrap_or(true)
    {
        if let Err(e) = reeval::reevaluate_kind(state, kind).await {
            tracing::warn!(error = %e, "Neubewertung nach nutzbarer Quelle fehlgeschlagen");
        }
    }
    Ok(out)
}

async fn refresh_inner(
    state: &AppState,
    id: &str,
    src: &dyn CveSource,
    kind: &str,
    name: &str,
    feed_state: FeedState,
    ctx: FetchCtx,
) -> Result<Outcome> {
    match fetch_watched(state, src, &feed_state, &ctx).await {
        Ok(FetchOutcome::NotModified) => {
            // Nichts Neues, aber ein vollständiger, erfolgreicher Abruf: die Quelle ist wieder frisch.
            let until = usable_until(state, name).await;
            sqlx::query("UPDATE feed_state SET last_success_at = now(), last_error = NULL, consecutive_failures = 0, usable_until = $2, \
                 retry_step = 0, next_attempt_at = NULL WHERE source = $1")
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
            retry_after,
        }) => {
            store(
                state,
                kind,
                id,
                records,
                new_state,
                Some((interrupted, retry_after)),
            )
            .await
        }
        Ok(FetchOutcome::Failed {
            state: new_state,
            error,
        }) => {
            // Einzelheiten (Fehler je Release, Seitengröße, geparkter Abbau) bleiben erhalten, Daten ändern sich nicht.
            let bulk = new_state
                .bulk
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?;
            let parked = new_state
                .parked
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?;
            let backfill = new_state
                .backfill
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?;
            sqlx::query(
                "UPDATE feed_state SET bulk = $2, backfill_parked = $3, backfill = $4, cursor = $5 WHERE source = $1",
            )
            .bind(name)
            .bind(&bulk)
            .bind(&parked)
            .bind(&backfill)
            .bind(&new_state.cursor)
            .execute(&state.pool)
            .await?;
            let msg = error.to_string();
            let hint = match &error {
                FeedError::Throttled { retry_after, .. } => *retry_after,
                _ => None,
            };
            record_failure(state, name, &msg, hint).await?;
            Ok(Outcome::Failed(msg))
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(source = name, error = %msg, "Feed-Abruf fehlgeschlagen, alter Stand bleibt erhalten");
            let hint = match &e {
                FeedError::Throttled { retry_after, .. } => *retry_after,
                _ => None,
            };
            record_failure(state, name, &msg, hint).await?;
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
    partial: Option<(Option<String>, Option<Duration>)>,
) -> Result<Outcome> {
    runs::report_phase(runs::Phase::Store);
    runs::report_items(records.len());
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
            record_failure(state, name, &msg, None).await?;
            return Ok(Outcome::Failed(msg));
        }
    };
    let backfill = new_state
        .backfill
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let bulk = new_state
        .bulk
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let parked = new_state
        .parked
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    match &partial {
        None => {
            let until = match new_state.usable_until {
                Some(u) => u,
                None => usable_until(state, name).await,
            };
            let covered = new_state
                .covered_since
                .as_deref()
                .and_then(|c| chrono::DateTime::parse_from_rfc3339(c).ok());
            sqlx::query(
                "UPDATE feed_state SET etag = $2, last_modified = $3, cursor = $4, backfill = $5, \
                 last_success_at = now(), last_error = NULL, consecutive_failures = 0, usable_until = $6, \
                 retry_step = 0, next_attempt_at = NULL, covered_since = COALESCE($7, covered_since), \
                 bulk = $8, backfill_parked = $9 WHERE source = $1",
            )
            .bind(name)
            .bind(&new_state.etag)
            .bind(&new_state.last_modified)
            .bind(&new_state.cursor)
            .bind(&backfill)
            .bind(until)
            .bind(covered)
            .bind(&bulk)
            .bind(&parked)
            .execute(&mut *tx)
            .await?;
        }
        Some((interrupted, retry_after)) => {
            // Fortschritt zählt nicht als Fehlschlag (kein Alarm); ein Abbruch mittendrin bleibt aber sichtbar.
            sqlx::query(
                "UPDATE feed_state SET etag = $2, last_modified = $3, cursor = $4, backfill = $5, \
                 last_error = $6, last_error_at = CASE WHEN $6::text IS NULL THEN last_error_at ELSE now() END, \
                 consecutive_failures = 0, bulk = $7, backfill_parked = $8 WHERE source = $1",
            )
            .bind(name)
            .bind(&new_state.etag)
            .bind(&new_state.last_modified)
            .bind(&new_state.cursor)
            .bind(&backfill)
            .bind(interrupted.as_deref().map(|m| format!("Lauf unterbrochen: {m}")))
            .bind(&bulk)
            .bind(&parked)
            .execute(&mut *tx)
            .await?;
            if interrupted.is_some() {
                // Ein Abbruch mittendrin wartet nach der Leiter (2/5/10/30 Min.), nicht ein volles Intervall.
                schedule_retry(&mut tx, name, *retry_after).await?;
            } else {
                // Seitenlimit erreicht, kein Fehler: weiter im normalen Takt.
                sqlx::query("UPDATE feed_state SET retry_step = 0, next_attempt_at = NULL WHERE source = $1")
                    .bind(name)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    tx.commit().await?;
    runs::report_phase(runs::Phase::Evaluate);
    let hosts = reeval::reevaluate_affected(state, &stats.changed_pairs).await?;
    runs::report_hosts(hosts);
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

/// Ruft genau eine Quelle ab (für das Laufprotokoll in `runs`): baut sie neu aus den Einstellungen, damit Änderungen
/// (Adresse, Schlüssel, abgeschaltet) auch für Läufe gelten, die in der Warteschlange standen.
pub async fn refresh_one(state: &AppState, id: &str) -> Outcome {
    let Some(b) = sources::build_enabled(state)
        .await
        .into_iter()
        .find(|b| b.id == id)
    else {
        return Outcome::Skipped;
    };
    match b.source {
        Ok(src) => match refresh_source(state, &b.id, src.as_ref()).await {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(source = %b.id, error = %e, "Feed-Verarbeitung fehlgeschlagen");
                Outcome::Failed(e.to_string())
            }
        },
        Err(e) => Outcome::Failed(fail_unbuildable(state, &b.id, &e).await),
    }
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
        let _ = record_failure(state, name, &msg, None).await;
    }
    msg
}

/// Fällig ist eine Quelle, wenn der letzte Versuch länger als ihr Intervall zurückliegt (oder es noch keinen gab).
/// Nach einem Fehllauf gilt stattdessen `next_attempt_at` (Wiederholungsleiter); das normale Intervall bleibt die
/// Obergrenze der Wartezeit.
fn is_due(
    last_attempt: Option<chrono::DateTime<chrono::Utc>>,
    next_attempt: Option<chrono::DateTime<chrono::Utc>>,
    interval_minutes: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let interval_over =
        last_attempt.is_none_or(|t| now - t >= chrono::Duration::minutes(interval_minutes));
    interval_over || next_attempt.is_some_and(|n| now >= n)
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
        // Verwaiste Läufe (Prozess beendet) als unterbrochen markieren, damit nichts dauerhaft als "läuft" erscheint.
        runs::sweep_stale(&state.pool).await;
        {
            // Jede fällige Quelle wird als eigener Lauf protokolliert; die Ausführungssperre in `runs::execute`
            // sorgt dafür, dass nie zwei Quellen (und nie ein manueller Abruf parallel) gleichzeitig laufen.
            for b in sources::build_enabled(&state).await {
                let name = b.id.clone();
                let minutes = crate::schedule::feed_interval_minutes(
                    &state.pool,
                    &name,
                    state.cfg.cve.interval_minutes as i64,
                )
                .await;
                let (last, next): (
                    Option<chrono::DateTime<chrono::Utc>>,
                    Option<chrono::DateTime<chrono::Utc>>,
                ) = sqlx::query_as(
                    "SELECT last_attempt_at, next_attempt_at FROM feed_state WHERE source = $1",
                )
                .bind(&name)
                .fetch_optional(&state.pool)
                .await
                .ok()
                .flatten()
                .unwrap_or((None, None));
                if !is_due(last, next, minutes, chrono::Utc::now()) {
                    continue;
                }
                match runs::start(&state.pool, &name, runs::Trigger::Scheduled, None).await {
                    Ok(runs::Start::Created(run)) => {
                        runs::execute(&state, run, &name).await;
                    }
                    // Läuft oder wartet schon (z. B. von Hand gestartet): nicht doppelt abrufen.
                    Ok(runs::Start::Running(_)) => {}
                    Err(e) => {
                        tracing::error!(source = name, error = %e, "Lauf konnte nicht angelegt werden")
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
    use super::{is_due, retry_gap};
    use chrono::{Duration, Utc};
    use std::time::Duration as Std;

    #[test]
    fn due_after_interval() {
        let now = Utc::now();
        assert!(is_due(None, None, 60, now));
        assert!(!is_due(Some(now - Duration::minutes(59)), None, 60, now));
        assert!(is_due(Some(now - Duration::minutes(60)), None, 60, now));
    }

    #[test]
    fn due_follows_retry_time_but_never_waits_longer_than_interval() {
        let now = Utc::now();
        let last = Some(now - Duration::minutes(3));
        // Leiter: erst nach `next_attempt_at` fällig, nicht erst nach dem vollen Intervall.
        assert!(!is_due(last, Some(now + Duration::minutes(2)), 60, now));
        assert!(is_due(last, Some(now - Duration::seconds(1)), 60, now));
        // Das Intervall bleibt die Obergrenze (z. B. 5 Min. Intervall, 30 Min. Leiter).
        assert!(is_due(
            Some(now - Duration::minutes(6)),
            Some(now + Duration::minutes(24)),
            5,
            now
        ));
    }

    #[test]
    fn retry_ladder_grows_then_falls_back_to_interval() {
        let m = |s| retry_gap(s, None).map(|d| d.num_minutes());
        assert_eq!(
            [m(1), m(2), m(3), m(4), m(5), m(9)],
            [Some(2), Some(5), Some(10), Some(30), None, None]
        );
        // Retry-After verlängert die Wartezeit, verkürzt sie nie.
        assert_eq!(
            retry_gap(1, Some(Std::from_secs(600))).map(|d| d.num_minutes()),
            Some(10)
        );
        assert_eq!(
            retry_gap(4, Some(Std::from_secs(60))).map(|d| d.num_minutes()),
            Some(30)
        );
        assert_eq!(
            retry_gap(7, Some(Std::from_secs(300))).map(|d| d.num_minutes()),
            Some(5)
        );
    }
}
