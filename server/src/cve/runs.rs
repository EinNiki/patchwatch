//! Protokoll der Abruf-Läufe (`feed_runs`): Start, Phasen, Fortschritt, Ergebnis.
//!
//! Ablauf eines Laufs: `start` legt die Zeile an (je Quelle höchstens ein offener Lauf), `execute` wartet auf die
//! gemeinsame Ausführungssperre (es läuft immer nur eine Quelle gleichzeitig), meldet die Phasen und schließt den
//! Lauf ab. Die Phasen werden über einen Task-lokalen Sammler gemeldet (`report_*`), damit die Adapter nichts davon
//! wissen müssen: `http.rs` meldet Verbinden/Laden/Auswerten, `refresh.rs` Speichern und Bewerten.

use crate::cve::refresh::{self, Outcome};
use crate::state::AppState;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// So viele abgeschlossene Läufe bleiben je Quelle erhalten.
pub const KEEP_PER_SOURCE: i64 = 50;
/// Mindestabstand zwischen zwei Abrufen derselben Quelle, gemessen ab dem Start des letzten Laufs.
pub const MIN_INTERVAL_SECS: i64 = 60;
/// Im Backoff (Quelle fehlerhaft, nächster Versuch noch nicht fällig) ist ein von Hand ausgelöster Abruf höchstens alle 5 Minuten erlaubt.
pub const BACKOFF_MANUAL_GAP_SECS: i64 = 300;
/// Läufe ohne Lebenszeichen seit so vielen Sekunden gelten als unterbrochen (Prozess beendet oder abgestürzt).
pub const STALE_AFTER_SECS: i64 = 120;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Phase {
    Connect = 0,
    Download = 1,
    Parse = 2,
    Store = 3,
    Evaluate = 4,
    Done = 5,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Download => "download",
            Self::Parse => "parse",
            Self::Store => "store",
            Self::Evaluate => "evaluate",
            Self::Done => "done",
        }
    }
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    since: Instant,
    /// Dauer je abgeschlossener Phase in Millisekunden.
    ms: Vec<(Phase, u128)>,
    bytes: u64,
    items: Option<i64>,
    hosts: Option<i64>,
    dirty: bool,
}

/// Sammler eines laufenden Abrufs. Phasen gehen nie zurück (ein Adapter mit mehreren Anfragen springt nicht hin und her).
#[derive(Debug)]
pub struct Sink(Mutex<Inner>);

impl Default for Sink {
    fn default() -> Self {
        Self(Mutex::new(Inner {
            phase: Phase::Connect,
            since: Instant::now(),
            ms: Vec::new(),
            bytes: 0,
            items: None,
            hosts: None,
            dirty: true,
        }))
    }
}

/// Stand des Sammlers zum Zeitpunkt der Abfrage.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub phase: Phase,
    pub bytes: u64,
    pub items: Option<i64>,
    pub hosts: Option<i64>,
    pub phases: Value,
}

impl Sink {
    pub fn set_phase(&self, p: Phase) {
        if let Ok(mut i) = self.0.lock() {
            if p > i.phase {
                let spent = i.since.elapsed().as_millis();
                let prev = i.phase;
                i.ms.push((prev, spent));
                i.phase = p;
                i.since = Instant::now();
                i.dirty = true;
            }
        }
    }

    pub fn add_bytes(&self, n: u64) {
        if let Ok(mut i) = self.0.lock() {
            i.bytes = i.bytes.saturating_add(n);
            i.dirty = true;
        }
    }

    pub fn set_items(&self, n: i64) {
        if let Ok(mut i) = self.0.lock() {
            i.items = Some(n);
            i.dirty = true;
        }
    }

    pub fn set_hosts(&self, n: i64) {
        if let Ok(mut i) = self.0.lock() {
            i.hosts = Some(n);
            i.dirty = true;
        }
    }

    /// Liefert den Stand und merkt, dass er abgeholt wurde; `None`, wenn sich nichts geändert hat und `force` fehlt.
    pub fn take(&self, force: bool) -> Option<Snapshot> {
        let mut i = self.0.lock().ok()?;
        if !i.dirty && !force {
            return None;
        }
        i.dirty = false;
        let mut phases = serde_json::Map::new();
        for (p, ms) in &i.ms {
            phases.insert(p.as_str().into(), json!(*ms as u64));
        }
        // Die laufende Phase mit ihrer bisherigen Dauer.
        phases.insert(
            i.phase.as_str().into(),
            json!(i.since.elapsed().as_millis() as u64),
        );
        Some(Snapshot {
            phase: i.phase,
            bytes: i.bytes,
            items: i.items,
            hosts: i.hosts,
            phases: Value::Object(phases),
        })
    }
}

tokio::task_local! {
    static SINK: Arc<Sink>;
}

/// Meldungen aus Adaptern und `refresh.rs`; ohne laufenden Lauf (z. B. in Tests) passiert nichts.
pub fn report_phase(p: Phase) {
    let _ = SINK.try_with(|s| s.set_phase(p));
}
pub fn report_bytes(n: u64) {
    let _ = SINK.try_with(|s| s.add_bytes(n));
}
pub fn report_items(n: usize) {
    let _ = SINK.try_with(|s| s.set_items(n as i64));
}
pub fn report_hosts(n: usize) {
    let _ = SINK.try_with(|s| s.set_hosts(n as i64));
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trigger {
    Manual,
    Scheduled,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Scheduled => "scheduled",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    /// Neuer Lauf angelegt.
    Created(i64),
    /// Für die Quelle läuft (oder wartet) schon ein Lauf; er ist der, an den sich Aufrufer anhängen.
    Running(i64),
}

/// Legt einen Lauf an. Je Quelle gibt es höchstens einen offenen; ein zweiter Start liefert dessen Nummer.
pub async fn start(
    pool: &PgPool,
    source: &str,
    trigger: Trigger,
    user: Option<&str>,
) -> sqlx::Result<Start> {
    for _ in 0..3 {
        let created: Option<i64> = sqlx::query_scalar(
            "INSERT INTO feed_runs (source, trigger, started_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id",
        )
        .bind(source)
        .bind(trigger.as_str())
        .bind(user)
        .fetch_optional(pool)
        .await?;
        if let Some(id) = created {
            return Ok(Start::Created(id));
        }
        let active: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM feed_runs WHERE source = $1 AND status IN ('queued', 'running') ORDER BY id DESC LIMIT 1",
        )
        .bind(source)
        .fetch_optional(pool)
        .await?;
        if let Some(id) = active {
            return Ok(Start::Running(id));
        }
        // Der offene Lauf endete zwischen INSERT und SELECT: noch einmal versuchen.
    }
    Err(sqlx::Error::RowNotFound)
}

#[derive(Serialize, sqlx::FromRow, Clone, Debug)]
pub struct RunRow {
    pub id: i64,
    pub source: String,
    pub trigger: String,
    pub started_by: Option<String>,
    pub status: String,
    pub phase: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub bytes: i64,
    pub items: Option<i32>,
    pub hosts: Option<i32>,
    pub error: Option<String>,
    pub phases: Value,
}

pub const RUN_COLS: &str = "id, source, trigger, started_by, status, phase, created_at, started_at, finished_at, bytes, items, hosts, error, phases";

pub async fn get(pool: &PgPool, id: i64) -> sqlx::Result<Option<RunRow>> {
    sqlx::query_as(&format!("SELECT {RUN_COLS} FROM feed_runs WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await
}

async fn publish(pool: &PgPool, row: &RunRow) {
    if let Ok(mut conn) = pool.acquire().await {
        // Klein halten (pg_notify begrenzt auf ~8 KB): nur Kennzahlen, keine Phasenzeiten und keine Fehlertexte.
        crate::live::publish(
            &mut conn,
            &json!({
                "type": "feed_run", "run_id": row.id, "source": row.source, "status": row.status, "phase": row.phase,
                "bytes": row.bytes, "items": row.items, "hosts": row.hosts,
            }),
        )
        .await;
    }
}

/// Meldet Phase und Fortschritt höchstens zweimal je Sekunde in die Datenbank und als Live-Ereignis. Dient zugleich als
/// Lebenszeichen: ohne Aktualisierung gilt der Lauf nach `STALE_AFTER_SECS` als unterbrochen.
async fn report_loop(pool: PgPool, run_id: i64, sink: Arc<Sink>) {
    let mut last_beat = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let force = last_beat.elapsed() >= Duration::from_secs(10);
        let Some(s) = sink.take(force) else { continue };
        last_beat = Instant::now();
        let res = sqlx::query(
            "UPDATE feed_runs SET phase = $2, bytes = $3, items = $4, hosts = $5, phases = $6, heartbeat_at = now() \
             WHERE id = $1 AND status IN ('queued', 'running')",
        )
        .bind(run_id)
        .bind(s.phase.as_str())
        .bind(s.bytes as i64)
        .bind(s.items.map(|v| v as i32))
        .bind(s.hosts.map(|v| v as i32))
        .bind(&s.phases)
        .execute(&pool)
        .await;
        if res.is_ok() {
            if let Ok(Some(row)) = get(&pool, run_id).await {
                publish(&pool, &row).await;
            }
        }
    }
}

fn status_of(o: &Outcome) -> &'static str {
    match o {
        Outcome::NotModified => "not_modified",
        Outcome::Updated { .. } => "ok",
        Outcome::Incomplete { .. } => "incomplete",
        Outcome::Failed(_) => "failed",
        Outcome::Skipped => "skipped",
    }
}

fn short(msg: &str) -> String {
    msg.chars().take(500).collect()
}

/// Beendet den Hintergrundtask beim Verlassen des Gültigkeitsbereichs, auch bei einem Absturz des Laufs: ein liegengebliebener
/// Melder würde sonst weiter Lebenszeichen schreiben und einen toten Lauf als lebendig erscheinen lassen.
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Mehrere angelegte Läufe nacheinander ausführen ("Alle abrufen"). Wartende Läufe bekommen währenddessen Lebenszeichen.
pub async fn execute_all(state: &AppState, items: Vec<(i64, String)>) {
    let pending = Arc::new(Mutex::new(
        items.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
    ));
    let pool = state.pool.clone();
    let ids = pending.clone();
    let _keep = AbortOnDrop(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let waiting: Vec<i64> = ids.lock().map(|g| g.clone()).unwrap_or_default();
            let _ = sqlx::query("UPDATE feed_runs SET heartbeat_at = now() WHERE id = ANY($1) AND status = 'queued'")
                .bind(&waiting)
                .execute(&pool)
                .await;
        }
    }));
    for (id, source) in items {
        if let Ok(mut g) = pending.lock() {
            g.retain(|x| *x != id);
        }
        execute(state, id, &source).await;
    }
}

/// Führt einen angelegten Lauf aus (wartet auf die Ausführungssperre) und schließt ihn ab.
pub async fn execute(state: &AppState, run_id: i64, source: &str) -> Outcome {
    let sink = Arc::new(Sink::default());
    // Lebenszeichen schon während des Wartens auf die Sperre.
    let reporter = AbortOnDrop(tokio::spawn(report_loop(
        state.pool.clone(),
        run_id,
        sink.clone(),
    )));
    let guard = state.refresh_lock.lock().await;
    let _ = sqlx::query("UPDATE feed_runs SET status = 'running', started_at = now(), heartbeat_at = now() WHERE id = $1 AND status = 'queued'")
        .bind(run_id)
        .execute(&state.pool)
        .await;
    if let Ok(Some(row)) = get(&state.pool, run_id).await {
        publish(&state.pool, &row).await;
    }

    // Harte Obergrenze: der Fortschrittswächter der Adapter deckt nur das Laden ab; Speichern und Bewerten hatten keine.
    let cap = Duration::from_secs(state.cfg.cve.stall_timeout_secs.saturating_mul(4));
    let work = SINK.scope(sink.clone(), refresh::refresh_one(state, source));
    let outcome = match tokio::time::timeout(cap, work).await {
        Ok(o) => o,
        Err(_) => {
            let msg = format!(
                "Abbruch: der Lauf dauerte länger als {} Minuten",
                cap.as_secs() / 60
            );
            let _ = refresh::record_failure(state, source, &msg, None).await;
            Outcome::Failed(msg)
        }
    };
    drop(guard);
    drop(reporter);
    // Bei einem Fehlschlag bleibt die Phase stehen, in der er auftrat (die Oberfläche zeigt sie als fehlgeschlagenen Schritt).
    if !matches!(outcome, Outcome::Failed(_)) {
        sink.set_phase(Phase::Done);
    }
    let snap = sink.take(true);
    let final_phase = snap.as_ref().map_or(Phase::Done, |s| s.phase);

    let (status, error) = match &outcome {
        Outcome::Failed(e) => (status_of(&outcome), Some(short(e))),
        o => (status_of(o), None),
    };
    let (bytes, items, hosts, phases) = snap
        .map(|s| {
            (
                s.bytes as i64,
                s.items.map(|v| v as i32),
                s.hosts.map(|v| v as i32),
                s.phases,
            )
        })
        .unwrap_or((0, None, None, json!({})));
    let _ = sqlx::query(
        "UPDATE feed_runs SET status = $2, phase = $8, finished_at = now(), heartbeat_at = now(), error = $3, \
         bytes = $4, items = $5, hosts = $6, phases = $7 WHERE id = $1",
    )
    .bind(run_id)
    .bind(status)
    .bind(&error)
    .bind(bytes)
    .bind(items)
    .bind(hosts)
    .bind(&phases)
    .bind(final_phase.as_str())
    .execute(&state.pool)
    .await;
    prune(&state.pool, source).await;
    if let Ok(Some(row)) = get(&state.pool, run_id).await {
        publish(&state.pool, &row).await;
    }
    outcome
}

/// Behält je Quelle die letzten `KEEP_PER_SOURCE` Läufe.
pub async fn prune(pool: &PgPool, source: &str) {
    let _ = sqlx::query(
        "DELETE FROM feed_runs WHERE source = $1 AND status NOT IN ('queued', 'running') \
         AND id NOT IN (SELECT id FROM feed_runs WHERE source = $1 ORDER BY id DESC LIMIT $2)",
    )
    .bind(source)
    .bind(KEEP_PER_SOURCE)
    .execute(pool)
    .await;
}

/// Läufe, deren Prozess nicht mehr lebt (kein Lebenszeichen), als unterbrochen markieren. Läuft im Scheduler-Takt.
pub async fn sweep_stale(pool: &PgPool) {
    let rows: Vec<RunRow> = sqlx::query_as(&format!(
        "UPDATE feed_runs SET status = 'interrupted', finished_at = now(), \
         error = 'Der Lauf wurde unterbrochen (Server beendet oder neu gestartet).' \
         WHERE status IN ('queued', 'running') AND heartbeat_at < now() - make_interval(secs => $1) RETURNING {RUN_COLS}"
    ))
    .bind(STALE_AFTER_SECS as f64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for r in &rows {
        publish(pool, r).await;
    }
}

/// Zustand der Quelle für die Regeln beim manuellen Abruf.
#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    Allowed,
    /// Letzter Lauf liegt weniger als `MIN_INTERVAL_SECS` zurück: so viele Sekunden warten.
    TooSoon(u64),
    /// Quelle ist im Backoff und nicht bestätigt.
    NeedsConfirm {
        next_attempt_at: Option<DateTime<Utc>>,
        failures: i32,
    },
    /// Im Backoff ist ein manueller Abruf je 5 Minuten erlaubt: so viele Sekunden warten.
    BackoffLimited(u64),
}

/// Prüft die Regeln für einen manuellen Abruf (Mindestabstand, Backoff mit Bestätigung, 1 Versuch je 5 Minuten im Backoff).
pub async fn gate(
    pool: &PgPool,
    source: &str,
    confirm: bool,
    now: DateTime<Utc>,
) -> sqlx::Result<Gate> {
    let last: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT max(created_at) FROM feed_runs WHERE source = $1")
            .bind(source)
            .fetch_one(pool)
            .await?;
    if let Some(t) = last {
        let wait = MIN_INTERVAL_SECS - (now - t).num_seconds();
        if wait > 0 {
            return Ok(Gate::TooSoon(wait as u64));
        }
    }
    let st: Option<(i32, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT consecutive_failures, next_attempt_at FROM feed_state WHERE source = $1",
    )
    .bind(source)
    .fetch_optional(pool)
    .await?;
    let Some((failures, next)) = st else {
        return Ok(Gate::Allowed);
    };
    let in_backoff = failures > 0 && next.is_some_and(|n| n > now);
    if !in_backoff {
        return Ok(Gate::Allowed);
    }
    if !confirm {
        return Ok(Gate::NeedsConfirm {
            next_attempt_at: next,
            failures,
        });
    }
    let manual: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(created_at) FROM feed_runs WHERE source = $1 AND trigger = 'manual'",
    )
    .bind(source)
    .fetch_one(pool)
    .await?;
    if let Some(t) = manual {
        let wait = BACKOFF_MANUAL_GAP_SECS - (now - t).num_seconds();
        if wait > 0 {
            return Ok(Gate::BackoffLimited(wait as u64));
        }
    }
    Ok(Gate::Allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_only_move_forward_and_record_durations() {
        let s = Sink::default();
        s.set_phase(Phase::Download);
        s.set_phase(Phase::Connect); // Rückschritt wird ignoriert
        s.set_phase(Phase::Parse);
        let snap = s.take(true).unwrap();
        assert_eq!(snap.phase, Phase::Parse);
        let p = snap.phases.as_object().unwrap();
        assert!(p.contains_key("connect") && p.contains_key("download") && p.contains_key("parse"));
    }

    #[test]
    fn take_reports_only_changes() {
        let s = Sink::default();
        assert!(s.take(false).is_some(), "erster Stand");
        assert!(s.take(false).is_none(), "nichts geändert");
        s.add_bytes(10);
        s.add_bytes(5);
        let snap = s.take(false).unwrap();
        assert_eq!(snap.bytes, 15);
        assert!(s.take(true).is_some(), "force liefert immer");
    }

    #[test]
    fn report_outside_a_run_is_a_noop() {
        report_phase(Phase::Store);
        report_bytes(1);
        report_items(1);
        report_hosts(1);
    }
}
