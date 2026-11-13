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
    /// Entpackte Bytes (was der Parser gesehen hat).
    unpacked: u64,
    /// Exakt gemessene Übertragung (OVAL: komprimierter Strom).
    wire_exact: u64,
    /// Mindestens eine Antwort wurde vom HTTP-Client entpackt (gzip): die Übertragungsmenge ist dann nicht messbar.
    wire_unknown: bool,
    /// Geschriebene Zeilen in der Datenbank.
    rows: Option<i64>,
    items: Option<i64>,
    hosts: Option<i64>,
    requests: u32,
    retries: u32,
    wait_ms: u64,
    page_size: Option<u32>,
    statuses: std::collections::BTreeMap<u16, u32>,
    /// Je Anfrage [Status, Bytes, Millisekunden]; begrenzt auf `MAX_PAGE_STATS`.
    page_stats: Vec<[u64; 3]>,
    dirty: bool,
}

/// So viele Einzelanfragen werden je Lauf festgehalten (nur Zahlen).
const MAX_PAGE_STATS: usize = 200;

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
            unpacked: 0,
            wire_exact: 0,
            wire_unknown: false,
            rows: None,
            items: None,
            hosts: None,
            requests: 0,
            retries: 0,
            wait_ms: 0,
            page_size: None,
            statuses: std::collections::BTreeMap::new(),
            page_stats: Vec::new(),
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
    pub metrics: Metrics,
}

/// Messwerte eines Laufs (nur Zahlen).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metrics {
    pub requests: u32,
    pub retries: u32,
    pub wait_ms: u64,
    pub page_size: Option<u32>,
    /// Über das Netz übertragene Bytes; `None`, wenn nicht messbar.
    pub wire: Option<u64>,
    pub unpacked: u64,
    pub rows: Option<i64>,
    /// {"200": 10, "503": 1}
    pub statuses: Value,
    /// [[Status, Bytes, ms], ...]
    pub page_stats: Value,
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

    /// Aktuelle Phase und wie lange der Lauf schon darin steht.
    pub fn phase_age(&self) -> (Phase, Duration) {
        self.0.lock().map_or((Phase::Connect, Duration::ZERO), |i| {
            (i.phase, i.since.elapsed())
        })
    }

    pub fn add_unpacked(&self, n: u64) {
        if let Ok(mut i) = self.0.lock() {
            i.unpacked = i.unpacked.saturating_add(n);
        }
    }

    pub fn add_wire(&self, n: u64) {
        if let Ok(mut i) = self.0.lock() {
            i.wire_exact = i.wire_exact.saturating_add(n);
        }
    }

    pub fn mark_wire_unknown(&self) {
        if let Ok(mut i) = self.0.lock() {
            i.wire_unknown = true;
        }
    }

    pub fn set_rows(&self, n: i64) {
        if let Ok(mut i) = self.0.lock() {
            i.rows = Some(i.rows.unwrap_or(0) + n);
        }
    }

    pub fn add_bytes(&self, n: u64) {
        if let Ok(mut i) = self.0.lock() {
            i.bytes = i.bytes.saturating_add(n);
            i.dirty = true;
        }
    }

    /// Eine abgeschlossene Anfrage: Status (0 = Netzwerkfehler), empfangene Bytes, Dauer.
    pub fn add_request(&self, status: u16, bytes: u64, ms: u64) {
        if let Ok(mut i) = self.0.lock() {
            i.requests = i.requests.saturating_add(1);
            *i.statuses.entry(status).or_insert(0) += 1;
            if i.page_stats.len() < MAX_PAGE_STATS {
                i.page_stats.push([u64::from(status), bytes, ms]);
            }
        }
    }

    pub fn add_retry(&self) {
        if let Ok(mut i) = self.0.lock() {
            i.retries = i.retries.saturating_add(1);
        }
    }

    pub fn add_wait(&self, ms: u64) {
        if let Ok(mut i) = self.0.lock() {
            i.wait_ms = i.wait_ms.saturating_add(ms);
        }
    }

    pub fn set_page_size(&self, n: u32) {
        if let Ok(mut i) = self.0.lock() {
            i.page_size = Some(n);
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
            metrics: Metrics {
                requests: i.requests,
                retries: i.retries,
                wait_ms: i.wait_ms,
                page_size: i.page_size,
                wire: (!i.wire_unknown && i.requests > 0).then_some(i.wire_exact),
                unpacked: i.unpacked,
                rows: i.rows,
                statuses: Value::Object(
                    i.statuses
                        .iter()
                        .map(|(k, v)| (k.to_string(), json!(v)))
                        .collect(),
                ),
                page_stats: json!(i.page_stats),
            },
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
/// Phase und Verweildauer des laufenden Abrufs (None außerhalb eines Laufs).
pub fn current_phase_age() -> Option<(Phase, Duration)> {
    SINK.try_with(|s| s.phase_age()).ok()
}

/// Ein Lauf hängt, wenn er länger als Anfrage-Timeout plus Puffer in "Verbinden" steht (Phasen gehen nie zurück,
/// spätere Phasen deckt der Fortschrittswächter ab).
pub fn connect_hung(
    phase: Phase,
    age: Duration,
    request_timeout_secs: u64,
    buffer_secs: u64,
) -> bool {
    phase == Phase::Connect
        && age > Duration::from_secs(request_timeout_secs.saturating_add(buffer_secs))
}

/// Beim Start: Läufe, die ein beendeter Prozess hinterließ, sofort als unterbrochen markieren (statt erst nach
/// `STALE_AFTER_SECS`). Es gibt genau einen Server-Prozess je Datenbank, also kann hier nichts mehr wirklich laufen.
pub async fn recover_on_start(pool: &PgPool) {
    let rows: Vec<RunRow> = sqlx::query_as(&format!(
        "UPDATE feed_runs SET status = 'interrupted', finished_at = now(), \
         error = 'Der Lauf wurde unterbrochen (Server beendet oder neu gestartet).' \
         WHERE status IN ('queued', 'running') RETURNING {RUN_COLS}"
    ))
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for r in &rows {
        publish(pool, r).await;
    }
}

/// Eine Anfrage ist beendet (Status 0 = ohne Antwort).
pub fn report_request(status: u16, bytes: u64, started: Instant) {
    let ms = started.elapsed().as_millis() as u64;
    let _ = SINK.try_with(|s| s.add_request(status, bytes, ms));
}
pub fn report_retry() {
    let _ = SINK.try_with(|s| s.add_retry());
}
pub fn report_page_size(n: u32) {
    let _ = SINK.try_with(|s| s.set_page_size(n));
}

/// Pause, die als Wartezeit des Laufs gezählt wird (Backoff, Retry-After, Seitenpause).
pub async fn wait(d: Duration) {
    // Die Wartezeit auf die Gegenstelle (Drosselung, Retry-After, Seitenpause) gehört zu „Herunterladen“, nicht zu
    // „Verbinden“ oder „Auswerten“; Phasen gehen nie zurück, spätere Phasen bleiben also unberührt.
    let _ = SINK.try_with(|s| {
        s.set_phase(Phase::Download);
        s.add_wait(d.as_millis() as u64)
    });
    tokio::time::sleep(d).await;
}

pub fn report_bytes(n: u64) {
    let _ = SINK.try_with(|s| s.add_bytes(n));
}
/// Entpackte Bytes (nach gzip/bzip2).
pub fn report_unpacked(n: u64) {
    let _ = SINK.try_with(|s| s.add_unpacked(n));
}
/// Exakt gemessene Übertragung (komprimierter Strom, ohne Entpacken durch den HTTP-Client).
pub fn report_wire(n: u64) {
    let _ = SINK.try_with(|s| s.add_wire(n));
}
/// Der HTTP-Client hat entpackt: die Übertragungsmenge dieser Antwort ist nicht messbar.
pub fn report_wire_unknown() {
    let _ = SINK.try_with(|s| s.mark_wire_unknown());
}
/// Tatsächlich geschriebene Datenbankzeilen.
pub fn report_rows(n: usize) {
    let _ = SINK.try_with(|s| s.set_rows(n as i64));
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
    pub requests: Option<i32>,
    pub retries: Option<i32>,
    pub wait_ms: Option<i64>,
    pub page_size: Option<i32>,
    pub statuses: Value,
    pub bytes_wire: Option<i64>,
    pub bytes_unpacked: Option<i64>,
    pub rows_written: Option<i64>,
}

pub const RUN_COLS: &str = "id, source, trigger, started_by, status, phase, created_at, started_at, finished_at, bytes, items, hosts, error, phases, requests, retries, wait_ms, page_size, statuses, bytes_wire, bytes_unpacked, rows_written";

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

/// Ergebnis eines Laufs (eine Regel für Anzeige und Speicher): Erfolgreich (`ok`, `not_modified`), Teilweise
/// (`incomplete`: der Lauf brachte Daten, die Quelle hat aber noch offene Arbeit, z. B. Rückstandsabbau oder fehlende
/// Massendaten), Fehlgeschlagen (`failed`) oder Abgebrochen (`interrupted`, vom Wächter/Neustart gesetzt).
/// Ein Lauf ohne Fehler ist nur dann „ok“, wenn die Quelle danach nichts Offenes mehr hat; sonst sagte die Zeile
/// „Erfolgreich“, während die Quelle „Unvollständig“ zeigt.
fn status_of(o: &Outcome, open_work: bool) -> &'static str {
    match o {
        Outcome::NotModified | Outcome::Updated { .. } if open_work => "incomplete",
        Outcome::NotModified => "not_modified",
        Outcome::Updated { .. } => "ok",
        Outcome::Incomplete { .. } => "incomplete",
        Outcome::Failed(_) => "failed",
        Outcome::Skipped => "skipped",
    }
}

/// Hat die Quelle nach dem Lauf noch offene Arbeit: Rückstandsabbau oder (Hybridquellen) unvollständige/abgelaufene Massendaten.
fn has_open_work(
    backfill: Option<&serde_json::Value>,
    bulk: Option<&serde_json::Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if backfill.is_some() {
        return true;
    }
    bulk.and_then(|v| serde_json::from_value::<crate::cve::Bulk>(v.clone()).ok())
        .is_some_and(|b| !b.complete || b.ok.values().any(|u| *u <= now))
}

async fn open_work_of(pool: &PgPool, source: &str) -> bool {
    let row: Option<(Option<serde_json::Value>, Option<serde_json::Value>)> =
        sqlx::query_as("SELECT backfill, bulk FROM feed_state WHERE source = $1")
            .bind(source)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    row.is_some_and(|(b, k)| has_open_work(b.as_ref(), k.as_ref(), chrono::Utc::now()))
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

/// Sperren eines Laufs (siehe `AppState::run_gate`); fällt beim Beenden des Laufs weg (nur zum Halten, nie gelesen).
#[allow(dead_code)]
enum RunGuard {
    Shared(
        tokio::sync::OwnedRwLockReadGuard<()>,
        tokio::sync::OwnedMutexGuard<()>,
    ),
    Exclusive(tokio::sync::OwnedRwLockWriteGuard<()>),
}

impl RunGuard {
    /// Debian und Ubuntu teilen sich die Lesesperre (parallel, je Typ nur ein Lauf); alle anderen Quellen laufen allein.
    async fn acquire(state: &AppState, source: &str) -> Self {
        let kind = crate::cve::sources::list(state)
            .await
            .ok()
            .and_then(|l| l.into_iter().find(|s| s.id == source).map(|s| s.kind));
        match kind.as_deref() {
            Some(k @ ("debian" | "ubuntu")) => {
                let kl = {
                    let mut m = state.kind_locks.lock().unwrap_or_else(|e| e.into_inner());
                    m.entry(k.to_owned()).or_default().clone()
                };
                // Erst die Typsperre, dann die Lesesperre: wer auf seinen Typ wartet, hält keine Lesesperre und
                // blockiert so keinen wartenden Schreiber unnötig.
                let kg = kl.lock_owned().await;
                let rg = state.run_gate.clone().read_owned().await;
                Self::Shared(rg, kg)
            }
            _ => Self::Exclusive(state.run_gate.clone().write_owned().await),
        }
    }
}

/// Mehrere angelegte Läufe ausführen ("Alle abrufen"). Debian und Ubuntu laufen unabhängig und parallel, jede Quelle
/// mit höchstens einer Anfrage gleichzeitig; Anreicherungsquellen warten, bis diese fertig sind. Der Abbruch oder
/// Fehlschlag eines Laufs berührt die anderen nicht. Wartende Läufe melden Lebenszeichen (siehe `execute`).
pub async fn execute_all(state: &AppState, items: Vec<(i64, String)>) {
    let mut set = tokio::task::JoinSet::new();
    for (id, source) in items {
        let st = state.clone();
        set.spawn(async move {
            execute(&st, id, &source).await;
        });
    }
    // Ein abgestürzter Lauf (Panic) beendet die anderen nicht; sein Eintrag wird vom Wächter als unterbrochen markiert.
    while let Some(r) = set.join_next().await {
        if let Err(e) = r {
            tracing::error!(error = %e, "Feed-Lauf abgestürzt");
        }
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
    let guard = RunGuard::acquire(state, source).await;
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

    let open_work = open_work_of(&state.pool, source).await;
    let (status, error) = match &outcome {
        Outcome::Failed(e) => (status_of(&outcome, open_work), Some(short(e))),
        o => (status_of(o, open_work), None),
    };
    let metrics = snap.as_ref().map(|s| s.metrics.clone()).unwrap_or_default();
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
         bytes = $4, items = $5, hosts = $6, phases = $7, requests = $9, retries = $10, wait_ms = $11, page_size = $12, \
         statuses = $13, page_stats = $14, bytes_wire = $15, bytes_unpacked = $16, rows_written = $17 WHERE id = $1",
    )
    .bind(run_id)
    .bind(status)
    .bind(&error)
    .bind(bytes)
    .bind(items)
    .bind(hosts)
    .bind(&phases)
    .bind(final_phase.as_str())
    .bind(metrics.requests as i32)
    .bind(metrics.retries as i32)
    .bind(metrics.wait_ms as i64)
    .bind(metrics.page_size.map(|n| n as i32))
    .bind(&metrics.statuses)
    .bind(&metrics.page_stats)
    .bind(metrics.wire.map(|n| n as i64))
    .bind(metrics.unpacked as i64)
    .bind(metrics.rows)
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
    fn connect_hang_needs_connect_phase_and_timeout_plus_buffer() {
        let limit = 120 + 30;
        let over = Duration::from_secs(limit + 1);
        assert!(connect_hung(Phase::Connect, over, 120, 30));
        assert!(
            !connect_hung(Phase::Connect, Duration::from_secs(limit), 120, 30),
            "genau am Limit noch nicht"
        );
        assert!(
            !connect_hung(Phase::Connect, Duration::from_secs(30), 120, 30),
            "läuft erst 30 s"
        );
        assert!(
            !connect_hung(Phase::Download, over, 120, 30),
            "andere Phasen deckt der Fortschrittswächter ab"
        );
    }

    #[tokio::test]
    async fn phase_age_follows_phase_changes() {
        let sink = Arc::new(Sink::default());
        SINK.scope(sink.clone(), async {
            assert_eq!(current_phase_age().unwrap().0, Phase::Connect);
            report_phase(Phase::Download);
            let (p, age) = current_phase_age().unwrap();
            assert_eq!(p, Phase::Download);
            assert!(
                age < Duration::from_secs(5),
                "Zeit zählt ab dem Phasenwechsel neu"
            );
        })
        .await;
        assert!(
            current_phase_age().is_none(),
            "außerhalb eines Laufs nichts"
        );
    }

    #[test]
    fn run_result_rule_is_consistent_with_open_work() {
        let upd = Outcome::Updated {
            changed_rows: 1,
            events: 0,
        };
        assert_eq!(status_of(&upd, false), "ok");
        // der Fall aus der Oberfläche: Lauf fehlerfrei, Quelle aber noch unvollständig -> nie „ok“
        assert_eq!(status_of(&upd, true), "incomplete");
        assert_eq!(status_of(&Outcome::NotModified, true), "incomplete");
        assert_eq!(status_of(&Outcome::NotModified, false), "not_modified");
        assert_eq!(status_of(&Outcome::Failed("x".into()), true), "failed");
        assert!(has_open_work(
            Some(&serde_json::json!({})),
            None,
            chrono::Utc::now()
        ));
        assert!(!has_open_work(None, None, chrono::Utc::now()));
    }

    #[tokio::test]
    async fn wait_counts_as_download_phase() {
        let sink = Arc::new(Sink::default());
        SINK.scope(sink.clone(), async {
            report_phase(Phase::Connect);
            wait(Duration::from_millis(1)).await;
            assert_eq!(current_phase_age().unwrap().0, Phase::Download);
            report_phase(Phase::Parse);
            wait(Duration::from_millis(1)).await;
            assert_eq!(current_phase_age().unwrap().0, Phase::Parse);
        })
        .await;
    }

    #[test]
    fn report_outside_a_run_is_a_noop() {
        report_phase(Phase::Store);
        report_bytes(1);
        report_items(1);
        report_hosts(1);
    }
}
