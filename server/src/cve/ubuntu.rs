//! Ubuntu CVE Tracker (`/security/cves.json`).
//!
//! Die API hat keinen serverseitigen "updated since"-Filter (geprüft: nur `package`, `limit`, `offset`,
//! `order`, `sort_by`, `version`, `status`, `priority`, `component`, `show_hidden`). Deshalb wird absteigend
//! nach `updated` sortiert paginiert und gestoppt, sobald der gespeicherte Cursor erreicht ist.
//!
//! Reicht das Seitenlimit eines Laufs nicht bis zum Cursor, wird der Fortschritt (`Backfill`) gespeichert und
//! der nächste Lauf setzt per Offset dort fort. Der bestätigte Cursor bleibt unverändert, bis die Lücke
//! geschlossen ist; erst dann rückt er auf den neuesten zu Beginn gesehenen Zeitstempel vor.

use super::http::{self, Limits};
use super::oval::{self, Imported, OvalParams};
use super::{
    is_cve_id, is_kernel_source, truncate, valid_version, Backfill, BulkRelease, CveSource, Entry,
    FeedError, FeedState, FetchCtx, FetchOutcome, Incr, Record, SourceStatus,
};
use crate::config::CveConfig;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{json, Value};
use std::time::Duration;

/// Seitengröße; die API erlaubt höchstens 20. Eine Seite ist ca. 3,7 MB groß (169 Kernel-Pakete je CVE).
pub const PAGE: usize = 20;
/// Höchstens so viele Watchlist-CVEs pro Lauf einzeln nachladen.
const MAX_WATCH_FETCH: usize = 25;

pub struct Ubuntu {
    base: String,
    /// Horizont des Erstabrufs in Tagen (0 = gesamte Liste).
    horizon_days: u32,
    max_pages: u32,
    /// Pause zwischen zwei Seiten: höchstens eine Anfrage gleichzeitig, dazwischen Luft für die Quelle.
    page_pause: Duration,
    lim: Limits,
    /// Hybridmodus: Massendaten (täglich) plus erste Seiten der API (stündlich); sonst nur der Rückstandsabbau.
    hybrid: bool,
    oval: OvalParams,
    bulk_client: reqwest::Client,
    extra_releases: Vec<String>,
    default_bulk_minutes: i64,
    incr_pages: u32,
    page_size: u32,
    /// Grenzen für die Seitenanfragen des stündlichen Abrufs (ein Versuch je Anfrage, die Schleife steuert Wiederholungen).
    page_lim: Limits,
}

impl Ubuntu {
    pub fn new(c: &CveConfig) -> Self {
        Self {
            base: c.ubuntu_url.trim_end_matches('/').to_owned(),
            horizon_days: c.ubuntu_horizon_days,
            max_pages: c.ubuntu_max_pages,
            page_pause: Duration::from_millis(c.ubuntu_page_pause_ms),
            lim: Limits {
                max_bytes: c.ubuntu_max_page_bytes,
                timeout: Duration::from_secs(c.request_timeout_secs),
                attempts: c.retries,
                base_delay: Duration::from_millis(c.retry_base_delay_ms),
                retry_after_cap: super::http::RETRY_AFTER_CAP,
            },
            hybrid: c.ubuntu_mode == "hybrid",
            oval: OvalParams {
                base_url: c.ubuntu_oval_url.trim_end_matches('/').to_owned(),
                max_bytes: c.ubuntu_oval_max_bytes,
                max_xml_bytes: c.ubuntu_oval_max_xml_bytes,
                timeout: Duration::from_secs(c.ubuntu_oval_timeout_secs),
            },
            bulk_client: oval::bulk_client(),
            extra_releases: c.ubuntu_bulk_releases.clone(),
            default_bulk_minutes: c.ubuntu_bulk_interval_minutes as i64,
            incr_pages: c.ubuntu_incremental_pages,
            page_size: c.ubuntu_page_size,
            page_lim: Limits {
                max_bytes: c.ubuntu_max_page_bytes,
                timeout: Duration::from_secs(c.ubuntu_page_timeout_secs),
                attempts: 1,
                base_delay: Duration::from_millis(c.retry_base_delay_ms),
                retry_after_cap: super::http::RETRY_AFTER_CAP,
            },
        }
    }
}

impl Ubuntu {
    /// Horizont des Erstabrufs: Zeitstempel, bis zu dem (nach `updated`) geladen wird. 0 Tage = gesamte Liste.
    fn horizon(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        if self.horizon_days == 0 {
            DateTime::<Utc>::UNIX_EPOCH
        } else {
            now - chrono::Duration::days(i64::from(self.horizon_days))
        }
    }
}

/// Altbestände: Quellen, die noch aus der Zeit stammen, in der der Erstabruf nach 5 Seiten als vollständig galt
/// (Cursor gesetzt, aber nie bis zu einem Horizont geladen), bekommen beim Start einen Erstabruf-Abbau und
/// gelten bis zu dessen Ende als unvollständig. Gibt die Zahl der wieder geöffneten Quellen zurück.
pub async fn reopen_legacy_imports(
    pool: &sqlx::PgPool,
    horizon_days: u32,
) -> anyhow::Result<usize> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT f.source, f.cursor FROM feed_state f JOIN cve_sources s ON s.id = f.source \
         WHERE s.kind = 'ubuntu' AND s.deleted_at IS NULL AND f.cursor IS NOT NULL \
           AND f.backfill IS NULL AND f.covered_since IS NULL",
    )
    .fetch_all(pool)
    .await?;
    let now = Utc::now();
    let horizon = if horizon_days == 0 {
        DateTime::<Utc>::UNIX_EPOCH
    } else {
        now - chrono::Duration::days(i64::from(horizon_days))
    };
    for (source, cursor) in &rows {
        let b = Backfill {
            target: horizon.to_rfc3339(),
            pending: cursor.clone(),
            next_offset: 0,
            pages_done: 0,
            runs: 0,
            started_at: now,
            initial: true,
            est_pages: None,
        };
        sqlx::query("UPDATE feed_state SET backfill = $2 WHERE source = $1 AND backfill IS NULL")
            .bind(source)
            .bind(serde_json::to_value(&b)?)
            .execute(pool)
            .await?;
    }
    Ok(rows.len())
}

fn page_url(base: &str, limit: usize, offset: usize) -> String {
    // Der Filter `package=linux` ist geprüft: kein Kernel-Paket hat mehr CVEs als `linux` (siehe README).
    format!(
        "{base}/security/cves.json?package=linux&limit={limit}&offset={offset}&order=descending&sort_by=updated"
    )
}

/// Schätzt, wie viele Seiten bis zum Horizont zu laden sind: Binärsuche nach dem ersten Eintrag mit
/// `updated_at <= Horizont` (die Liste ist absteigend sortiert). Nur eine Schätzung für die Anzeige; Fehler
/// ergeben `None` und beeinflussen den Abruf nicht.
async fn estimate_pages(
    client: &reqwest::Client,
    base: &str,
    lim: Limits,
    total: u64,
    target: DateTime<Utc>,
) -> Option<u32> {
    if target == DateTime::<Utc>::UNIX_EPOCH {
        return Some(total.div_ceil(PAGE as u64) as u32);
    }
    let (mut lo, mut hi) = (0u64, total); // erster Offset mit updated <= target liegt in [lo, hi]
    while lo < hi {
        let mid = (lo + hi) / 2;
        let url = page_url(base, 1, mid as usize);
        let page = fetch_page(client, &url, lim, Some(target), 1).await.ok()?;
        if page.reached_end {
            hi = mid; // Eintrag bei `mid` ist schon im Horizont (oder die Liste endet)
        } else {
            lo = mid + 1;
        }
    }
    Some(lo.div_ceil(PAGE as u64) as u32)
}

fn map_status(status: &str, desc: &str) -> Option<(SourceStatus, Option<String>)> {
    let d = desc.trim();
    let version = || valid_version(d).then(|| d.to_owned());
    Some(match status {
        // Paket existiert in diesem Release nicht: für Hosts irrelevant.
        "DNE" => return None,
        // Fix-Version steht im description-Feld; ohne gültige Version kein "behoben".
        "released" => match version() {
            Some(v) => (SourceStatus::Fixed, Some(v)),
            None => (SourceStatus::Unknown, None),
        },
        "pending" => (SourceStatus::FixPending, version()),
        // Offen oder vom Hersteller nicht behoben: für den Host weiterhin verwundbar.
        "needed" | "deferred" | "ignored" => (SourceStatus::Vulnerable, None),
        "not-affected" => (SourceStatus::NotAffected, None),
        // "needs-triage" und alles Unbekannte (Formatänderung) bleiben UNKNOWN, nie grün.
        _ => (SourceStatus::Unknown, None),
    })
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .map(|n| n.and_utc())
        })
}

/// Ein CVE-Objekt (Listen- und Einzelabruf haben dasselbe Format); behält nur Kernel-Pakete.
pub fn parse_cve(v: &Value) -> Option<Record> {
    let id = v.get("id")?.as_str()?;
    if !is_cve_id(id) {
        return None;
    }
    let text = |k: &str| v.get(k).and_then(Value::as_str);
    let mut rec = Record {
        cve_id: id.to_owned(),
        description: text("description")
            .map(|d| truncate(d.trim(), 2000))
            .filter(|d| !d.is_empty()),
        priority: text("priority").map(str::to_ascii_lowercase),
        published_at: text("published").and_then(parse_time),
        updated_at: text("updated_at").and_then(parse_time),
        entries: Vec::new(),
    };
    for pkg in v.get("packages")?.as_array()? {
        let name = pkg.get("name").and_then(Value::as_str).unwrap_or("");
        if !is_kernel_source(name) {
            continue;
        }
        for s in pkg
            .get("statuses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let release = s
                .get("release_codename")
                .and_then(Value::as_str)
                .unwrap_or("");
            if release.is_empty() || release == "upstream" {
                continue;
            }
            let status = s.get("status").and_then(Value::as_str).unwrap_or("");
            let desc = s.get("description").and_then(Value::as_str).unwrap_or("");
            if let Some((st, fix)) = map_status(status, desc) {
                rec.entries.push(Entry {
                    release: release.to_owned(),
                    package: name.to_owned(),
                    status: st,
                    fix_version: fix,
                    raw: json!({ "status": status, "description": truncate(desc, 200) }),
                });
            }
        }
    }
    Some(rec)
}

#[async_trait]
impl CveSource for Ubuntu {
    fn name(&self) -> &'static str {
        "ubuntu"
    }

    async fn fetch(
        &self,
        client: &reqwest::Client,
        state: &FeedState,
        ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError> {
        if self.hybrid {
            return self.fetch_hybrid(client, state, ctx).await;
        }
        // Rückfallmodus `api`: ein geparkter Rückstandsabbau wird fortgesetzt, die Hybriddaten werden verworfen
        // (die nächste Umstellung beginnt mit bedingten Anfragen ohne Wirkung auf vorhandene CVE-Daten).
        let mut restored = state.clone();
        let had_bulk = restored.bulk.take().is_some();
        if let Some(p) = restored.parked.take() {
            if restored.backfill.is_none() {
                restored.backfill = Some(p);
            }
        }
        let out = self.fetch_api(client, &restored, ctx).await?;
        Ok(match out {
            // Der Zustand (Hybriddaten entfernt) muss auch ohne neue Records gespeichert werden.
            FetchOutcome::NotModified if had_bulk || restored != *state => FetchOutcome::Records {
                records: Vec::new(),
                state: restored,
            },
            o => o,
        })
    }
}

impl Ubuntu {
    /// Bisheriger Weg (Modus `api`): absteigend nach `updated` blättern, Rückstand über Läufe abbauen.
    async fn fetch_api(
        &self,
        client: &reqwest::Client,
        state: &FeedState,
        ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError> {
        // Bestätigter Cursor: alles Neuere ist vollständig geladen. Er rückt nur vor, wenn die Lücke zwischen
        // Ziel (alter Cursor bzw. Horizont des Erstabrufs) und Listenkopf geschlossen ist; solange sie offen
        // ist, steht der Fortschritt in `backfill`. Auch der Erstabruf ist so ein Abbau: ohne Cursor gilt die
        // Quelle erst als vollständig, wenn der Horizont erreicht ist (oder die Liste endet).
        let confirmed = state.cursor.as_deref().and_then(parse_time);
        // Ein Abbau wird nur fortgesetzt, wenn er zum Zustand passt (wurde der Cursor von Hand geändert oder ist
        // der Eintrag beschädigt, beginnt der Abruf wieder bei Seite 1). Ein Erstabruf-Abbau gilt unabhängig vom
        // Cursor: er holt auch Altbestände nach, die nur den Kopf der Liste kannten.
        let resume = state.backfill.as_ref().filter(|b| {
            (b.initial || state.cursor.as_deref() == Some(b.target.as_str()))
                && parse_time(&b.target).is_some()
                && parse_time(&b.pending).is_some()
        });
        let initial = confirmed.is_none() || resume.is_some_and(|b| b.initial);
        // Ziel: bis wohin gelesen werden muss. Beim Erstabruf der Horizont, einmal festgelegt und danach
        // nicht mehr mitwandernd (sonst würde der Abbau nie fertig).
        let target = match (resume, confirmed) {
            (Some(b), _) => parse_time(&b.target),
            (None, Some(c)) => Some(c),
            (None, None) => Some(self.horizon(Utc::now())),
        };
        let mut complete = false;
        let start_offset = resume.map_or(0, |b| b.next_offset as usize);
        // Neuester gesehener Zeitstempel des gesamten Durchlaufs (über Läufe hinweg in `pending` gehalten).
        let mut newest = resume.and_then(|b| parse_time(&b.pending)).or(confirmed);
        let mut records: Vec<Record> = Vec::new();
        let mut pages_fetched = 0usize;
        let mut interrupted: Option<FeedError> = None;
        let mut est_pages = resume.and_then(|b| b.est_pages);

        'pages: for i in 0..self.max_pages as usize {
            if i > 0 && !self.page_pause.is_zero() {
                tokio::time::sleep(self.page_pause).await;
            }
            ctx.progress.beat();
            let url = page_url(&self.base, PAGE, start_offset + i * PAGE);
            // Eine Seite wird ganz oder gar nicht übernommen; so zeigt der Fortschritt nie über Daten hinaus,
            // die wirklich gespeichert werden.
            let page = match fetch_page(client, &url, self.lim, target, PAGE).await {
                Ok(p) => p,
                // Schon Fortschritt erzielt: behalten und beim nächsten Lauf weitermachen, nicht wegwerfen.
                // Ein Fehler schon auf der ersten Seite ist ein Fehlschlag (und beim Erstabruf nie "vollständig").
                Err(e) if pages_fetched > 0 => {
                    interrupted = Some(e);
                    break 'pages;
                }
                Err(e) => return Err(e),
            };
            pages_fetched += 1;
            ctx.progress.beat();
            records.extend(page.records);
            newest = newest.max(page.newest);
            // Erstabruf: einmal die Gesamtzahl der Seiten bis zum Horizont schätzen ("N von M Seiten").
            if initial
                && pages_fetched == 1
                && !page.reached_end
                && resume.is_none_or(|b| b.runs == 0 && b.est_pages.is_none())
            {
                if let (Some(total), Some(t)) = (page.total, target) {
                    est_pages = estimate_pages(client, &self.base, self.lim, total, t).await;
                }
            }
            if page.reached_end {
                complete = true;
                break;
            }
        }

        let had_backfill = state.backfill.is_some();
        let new_state = if complete {
            // Lücke geschlossen: erst jetzt rückt der bestätigte Cursor vor.
            FeedState {
                cursor: newest.map(|n| n.to_rfc3339()),
                backfill: None,
                // Ein abgeschlossener Erstabruf hat die Liste bis zum Horizont vollständig geladen.
                covered_since: match (initial, target) {
                    (true, Some(t)) => Some(t.to_rfc3339()),
                    _ => state.covered_since.clone(),
                },
                ..state.clone()
            }
        } else {
            // `complete == false` heißt: mindestens eine Seite gelesen (sonst wäre es ein Fehler gewesen).
            let (Some(target), Some(pending)) = (target, newest) else {
                return Err(FeedError::Format("Abbau ohne Ziel".into()));
            };
            // Eine Seite Überlappung: Offsets verschieben sich nur nach hinten, wenn oben neue Änderungen
            // eintreffen (Doppelte sind harmlos, der Upsert ist idempotent) -- die Überlappung fängt zusätzlich
            // gelöschte oder ausgeblendete Einträge ab. Mit nur einer Seite pro Lauf gibt es keine, damit der
            // Abruf überhaupt vorankommt.
            let end = start_offset + pages_fetched * PAGE;
            let next = if pages_fetched > 1 { end - PAGE } else { end };
            let prev = resume;
            FeedState {
                backfill: Some(Backfill {
                    // Beim Catch-up bleibt die Zeichenkette gleich dem gespeicherten Cursor.
                    target: if initial {
                        target.to_rfc3339()
                    } else {
                        state.cursor.clone().unwrap_or_else(|| target.to_rfc3339())
                    },
                    pending: pending.to_rfc3339(),
                    next_offset: next as u32,
                    pages_done: prev.map_or(0, |b| b.pages_done) + pages_fetched as u32,
                    runs: prev.map_or(0, |b| b.runs) + 1,
                    started_at: prev.map_or_else(Utc::now, |b| b.started_at),
                    initial,
                    est_pages,
                }),
                ..state.clone()
            }
        };
        // Ein Erstabruf ohne einen einzigen Eintrag ist ein Formatfehler, nie "vollständig".
        if complete && initial && !had_backfill && records.is_empty() {
            return Err(FeedError::Format("Feed liefert keine CVEs".into()));
        }

        self.fetch_watchlist(client, ctx, &mut records).await;

        if !complete {
            return Ok(FetchOutcome::Partial {
                records,
                state: new_state,
                retry_after: match &interrupted {
                    Some(FeedError::Throttled { retry_after, .. }) => *retry_after,
                    _ => None,
                },
                interrupted: interrupted.map(|e| e.to_string()),
            });
        }
        // Ein geschlossener Rückstand muss den Cursor auch dann übernehmen, wenn er keine Records brachte.
        if records.is_empty() && !had_backfill {
            return Ok(FetchOutcome::NotModified);
        }
        Ok(FetchOutcome::Records {
            records,
            state: new_state,
        })
    }
}

impl Ubuntu {
    /// Watchlist-CVEs, die nicht im neuesten Fenster liegen, gezielt nachladen.
    async fn fetch_watchlist(
        &self,
        client: &reqwest::Client,
        ctx: &FetchCtx,
        records: &mut Vec<Record>,
    ) {
        for id in ctx
            .watch_missing
            .iter()
            .filter(|id| is_cve_id(id))
            .take(MAX_WATCH_FETCH)
        {
            if records.iter().any(|r| &r.cve_id == id) {
                continue;
            }
            let url = format!("{}/security/cves/{id}.json", self.base);
            match http::get(client, &url, &[("accept", "application/json")], self.lim).await {
                Ok(f) => match serde_json::from_slice::<Value>(&f.body)
                    .ok()
                    .as_ref()
                    .and_then(parse_cve)
                {
                    Some(rec) => records.push(rec),
                    None => tracing::warn!(cve = %id, "Ubuntu: Einzelabruf ohne verwertbare Daten"),
                },
                Err(FeedError::Http(404)) => {}
                Err(e) => {
                    tracing::warn!(cve = %id, error = %e, "Ubuntu: Einzelabruf fehlgeschlagen")
                }
            }
        }
    }
}

/// Eine geladene und geprüfte Seite.
struct Page {
    records: Vec<Record>,
    /// Neuester `updated_at`-Wert der Seite.
    newest: Option<DateTime<Utc>>,
    /// Ziel (Cursor bzw. Horizont) erreicht oder Listenende: alles Ältere ist bereits bekannt bzw. uninteressant.
    reached_end: bool,
    /// `total_results` der API (nur für die Schätzung der Seitenzahl).
    total: Option<u64>,
}

async fn fetch_page(
    client: &reqwest::Client,
    url: &str,
    lim: Limits,
    stop_at: Option<DateTime<Utc>>,
    limit: usize,
) -> Result<Page, FeedError> {
    let f = http::get(client, url, &[("accept", "application/json")], lim).await?;
    let v: Value = serde_json::from_slice(&f.body)
        .map_err(|e| FeedError::Format(format!("kein JSON: {e}")))?;
    let cves = v
        .get("cves")
        .and_then(Value::as_array)
        .ok_or_else(|| FeedError::Format("Feld `cves` fehlt".into()))?;
    let mut page = Page {
        records: Vec::new(),
        newest: None,
        reached_end: cves.len() < limit,
        total: v.get("total_results").and_then(Value::as_u64),
    };
    for c in cves {
        let updated = c
            .get("updated_at")
            .and_then(Value::as_str)
            .and_then(parse_time)
            .ok_or_else(|| FeedError::Format("`updated_at` fehlt oder ist ungültig".into()))?;
        if stop_at.is_some_and(|cur| updated <= cur) {
            page.reached_end = true;
            break;
        }
        page.newest = page.newest.max(Some(updated));
        if let Some(rec) = parse_cve(c) {
            page.records.push(rec);
        }
    }
    Ok(page)
}

/// Seitengrößen der Leiter beim Verkleinern und Wachsen (nie unter 5, die API erlaubt höchstens 20).
const SIZE_LADDER: [u32; 3] = [5, 10, 20];
const MIN_PAGE: u32 = 5;

/// Nächstkleinere Stufe der Leiter (nie unter 5).
fn smaller(size: u32) -> u32 {
    SIZE_LADDER
        .iter()
        .rev()
        .copied()
        .find(|s| *s < size)
        .unwrap_or(MIN_PAGE)
}

/// Nächstgrößere Stufe der Leiter, höchstens `cap`.
fn larger(size: u32, cap: u32) -> u32 {
    SIZE_LADDER
        .iter()
        .copied()
        .find(|s| *s > size)
        .map_or(size, |s| s.min(cap))
        .max(size)
}

/// Nächste Stufe der Leiter, die nicht größer als `n` ist (Werte unter 5 bleiben 5).
fn snap(n: u32) -> u32 {
    SIZE_LADDER
        .iter()
        .rev()
        .copied()
        .find(|s| *s <= n)
        .unwrap_or(MIN_PAGE)
}

fn status_of(e: &FeedError) -> Option<u16> {
    match e {
        FeedError::Http(c) | FeedError::Throttled { status: c, .. } => Some(*c),
        _ => None,
    }
}

fn retry_after_of(e: &FeedError) -> Option<Duration> {
    match e {
        FeedError::Throttled { retry_after, .. } => *retry_after,
        _ => None,
    }
}

impl Ubuntu {
    /// Releases, für die Massendaten gebraucht werden: Releases der Ubuntu-Hosts plus Konfiguration.
    fn relevant_releases(&self, ctx: &FetchCtx) -> Vec<String> {
        let mut v: Vec<String> = ctx
            .hosts
            .iter()
            .filter(|h| h.distro_id == "ubuntu")
            .map(|h| h.codename.clone())
            .chain(self.extra_releases.iter().cloned())
            .filter(|r| oval::valid_release(r))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Hybridmodus: täglich die behobenen Kernel-Einträge aus den OVAL-Dateien (bedingt, gestreamt), stündlich die
    /// ersten Seiten der API für offene Fälle. Ein Ausfall der API ist kein Totalausfall: die Massendaten gelten
    /// weiter, aber nur innerhalb ihrer Frische (siehe docs/ubuntu-source.md).
    async fn fetch_hybrid(
        &self,
        client: &reqwest::Client,
        state: &FeedState,
        ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError> {
        let mut st = state.clone();
        // Ein vorhandener Rückstandsabbau bleibt erhalten, ruht aber (im Modus `api` läuft er weiter).
        if let Some(b) = st.backfill.take() {
            st.parked = Some(b);
        }
        let mut bulk = st.bulk.take().unwrap_or_default();
        let relevant = self.relevant_releases(ctx);
        let every = chrono::Duration::minutes(if ctx.bulk_interval_minutes > 0 {
            ctx.bulk_interval_minutes
        } else {
            self.default_bulk_minutes
        });
        // Frische der Massendaten: max(3 x tägliches Intervall, 36 Stunden).
        let window = (every * 3).max(chrono::Duration::hours(36));

        let mut records: Vec<Record> = Vec::new();
        let (mut bulk_ok_ops, mut first_error): (u32, Option<FeedError>) = (0, None);
        for rel in &relevant {
            let entry = bulk.releases.entry(rel.clone()).or_default();
            let due = if entry.last_result == "error" {
                entry.next_attempt_at.is_none_or(|n| Utc::now() >= n)
            } else {
                entry.checked_at.is_none_or(|c| Utc::now() - c >= every)
            };
            if !due {
                continue;
            }
            ctx.progress.beat();
            let res =
                oval::import_release(&self.bulk_client, rel, entry, &self.oval, &ctx.progress)
                    .await;
            let at = Utc::now();
            entry.checked_at = Some(at);
            match res {
                Ok(Imported::NotModified) => {
                    entry.verified_at = Some(at);
                    entry.last_result = "not_modified".into();
                    clear_bulk_error(entry);
                    bulk_ok_ops += 1;
                }
                Ok(Imported::Data {
                    records: r,
                    etag,
                    last_modified,
                    bytes,
                }) => {
                    entry.etag = etag;
                    entry.last_modified = last_modified;
                    entry.verified_at = Some(at);
                    entry.imported_at = Some(at);
                    entry.bytes = Some(bytes);
                    entry.records = Some(u32::try_from(r.len()).unwrap_or(u32::MAX));
                    entry.last_result = "imported".into();
                    clear_bulk_error(entry);
                    records.extend(r);
                    bulk_ok_ops += 1;
                }
                Err(e) => {
                    // Ein Fehler verändert die gespeicherten Daten nie; er wird nur vermerkt.
                    entry.failures += 1;
                    entry.last_result = "error".into();
                    entry.last_error = Some(e.to_string());
                    entry.last_status = status_of(&e);
                    entry.retry_after_secs = retry_after_of(&e).map(|d| d.as_secs());
                    let backoff = chrono::Duration::minutes(
                        (15i64 << entry.failures.saturating_sub(1).min(5)).min(360),
                    );
                    let asked = retry_after_of(&e)
                        .and_then(|d| chrono::Duration::from_std(d).ok())
                        .unwrap_or_else(chrono::Duration::zero);
                    entry.next_attempt_at = Some(at + backoff.max(asked));
                    tracing::warn!(release = %rel, error = %e, "Ubuntu: Massendaten-Import fehlgeschlagen");
                    first_error.get_or_insert(e);
                }
            }
        }

        // Stündlich: die ersten Seiten der API (offene Fälle, neue Änderungen).
        let incr_res = self
            .incremental(client, &mut st.cursor, &mut bulk.incr, ctx, &mut records)
            .await;
        let incr_ok = incr_res.is_ok();
        if let Err(e) = incr_res {
            tracing::warn!(error = %e, "Ubuntu: stündlicher Abruf fehlgeschlagen, Massendaten gelten weiter");
            first_error.get_or_insert(e);
        }
        if incr_ok {
            self.fetch_watchlist(client, ctx, &mut records).await;
        }

        // Frische und Vollständigkeit neu bestimmen.
        let now = Utc::now();
        bulk.ok.clear();
        for rel in &relevant {
            if let Some(until) = bulk
                .releases
                .get(rel)
                .and_then(|r| r.verified_at)
                .map(|v| v + window)
                .filter(|u| *u > now)
            {
                bulk.ok.insert(rel.clone(), until);
            }
        }
        bulk.complete = relevant.iter().all(|r| {
            bulk.ok.contains_key(r)
                && bulk
                    .releases
                    .get(r)
                    .is_some_and(|b| b.last_result != "error")
        });
        bulk.relevant = relevant;
        st.usable_until = bulk.ok.values().max().copied();
        let nothing_usable = bulk.ok.is_empty() && !bulk.relevant.is_empty();
        st.bulk = Some(bulk);

        if let (true, Some(error)) = (nothing_usable && bulk_ok_ops == 0 && !incr_ok, first_error) {
            return Ok(FetchOutcome::Failed { state: st, error });
        }
        Ok(FetchOutcome::Records { records, state: st })
    }

    /// Erste Seiten von `cves.json` bis zum bestätigten Cursor. Seitengröße 20, bei Fehlern 10, dann 5 (nie darunter),
    /// bei HTTP 422 wird das Maximum gelernt; eine Anfrage gleichzeitig mit Pause dazwischen. Reicht das Seitenlimit
    /// nicht bis zum Cursor, bleibt der Fortschritt (`pending`, `next_offset`) erhalten und der Cursor unverändert,
    /// sodass keine Lücke entsteht.
    async fn incremental(
        &self,
        client: &reqwest::Client,
        cursor: &mut Option<String>,
        incr: &mut Incr,
        ctx: &FetchCtx,
        records: &mut Vec<Record>,
    ) -> Result<(), FeedError> {
        incr.last_run_at = Some(Utc::now());
        let confirmed = cursor.as_deref().and_then(parse_time);
        let cap = snap(incr.max_page.unwrap_or(self.page_size).min(self.page_size));
        let mut size = if incr.page_size == 0 {
            cap
        } else {
            snap(incr.page_size).min(cap)
        };
        // Fortschritt nur fortsetzen, wenn er zum bestätigten Cursor gehört.
        let resume = confirmed.is_some() && incr.pending.as_deref().and_then(parse_time).is_some();
        let mut offset = if resume { incr.next_offset as usize } else { 0 };
        let mut newest = if resume {
            incr.pending.as_deref().and_then(parse_time)
        } else {
            None
        }
        .or(confirmed);
        let (mut pages, mut shrunk, mut min_retry) = (0u32, false, false);
        let mut reached = false;
        let mut failure: Option<FeedError> = None;

        while pages < self.incr_pages {
            if (pages > 0 || shrunk) && !self.page_pause.is_zero() {
                tokio::time::sleep(self.page_pause).await;
            }
            ctx.progress.beat();
            let url = page_url(&self.base, size as usize, offset);
            match fetch_page(client, &url, self.page_lim, confirmed, size as usize).await {
                Ok(p) => {
                    pages += 1;
                    min_retry = false;
                    records.extend(p.records);
                    newest = newest.max(p.newest);
                    offset += size as usize;
                    // Ohne bestätigten Cursor beginnt die Verfolgung mit der ersten Seite (kein Rückstand bekannt).
                    if p.reached_end || confirmed.is_none() {
                        reached = true;
                        break;
                    }
                }
                Err(FeedError::Http(422)) => {
                    // Die Quelle lehnt die Seitengröße ab: Maximum lernen und mit der kleineren Stufe wiederholen.
                    if size <= MIN_PAGE {
                        failure = Some(FeedError::Http(422));
                        break;
                    }
                    size = smaller(size);
                    incr.max_page = Some(size);
                    shrunk = true;
                }
                Err(
                    e
                    @ (FeedError::Throttled { .. } | FeedError::Network(_) | FeedError::Format(_)),
                ) => {
                    // Überlastung, Zeitüberschreitung, Verbindungsabbruch: kleinere Seiten, nach Wartezeit (Retry-After
                    // gilt, Jitter gegen Gleichtakt). Auf der kleinsten Stufe gibt es noch einen Versuch, dann Schluss.
                    if size > MIN_PAGE {
                        size = smaller(size);
                        shrunk = true;
                    } else if min_retry {
                        failure = Some(e);
                        break;
                    } else {
                        min_retry = true;
                        shrunk = true;
                    }
                    let wait = retry_after_of(&e)
                        .unwrap_or(Duration::ZERO)
                        .min(super::http::RETRY_AFTER_CAP)
                        + http::jitter(self.lim.base_delay.as_millis() as u64);
                    if failure.is_none() && !wait.is_zero() {
                        ctx.progress.beat();
                        tokio::time::sleep(wait).await;
                    }
                    incr.last_status = status_of(&e);
                    incr.last_error = Some(e.to_string());
                    incr.retry_after_secs = retry_after_of(&e).map(|d| d.as_secs());
                }
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }

        // Fortschritt festhalten.
        if reached {
            *cursor = newest.map(|n| n.to_rfc3339());
            incr.pending = None;
            incr.next_offset = 0;
        } else if pages > 0 && confirmed.is_some() {
            // Eine Seite Überlappung (Verschiebungen oben, ausgeblendete Einträge); bei einer Seite geht es direkt weiter.
            incr.pending = newest.map(|n| n.to_rfc3339());
            incr.next_offset = if pages > 1 {
                offset.saturating_sub(size as usize) as u32
            } else {
                offset as u32
            };
        }
        incr.pages_last = pages;
        match failure {
            None => {
                // Nach einem fehlerfreien Lauf wieder wachsen, höchstens bis zum (gelernten) Maximum.
                incr.page_size = if shrunk { size } else { larger(size, cap) };
                incr.last_ok_at = Some(Utc::now());
                incr.last_error = None;
                incr.last_status = None;
                incr.retry_after_secs = None;
                incr.failures = 0;
                Ok(())
            }
            Some(e) => {
                incr.page_size = size;
                incr.failures += 1;
                incr.last_error = Some(e.to_string());
                incr.last_status = status_of(&e);
                incr.retry_after_secs = retry_after_of(&e).map(|d| d.as_secs());
                Err(e)
            }
        }
    }
}

fn clear_bulk_error(e: &mut BulkRelease) {
    e.last_error = None;
    e.last_status = None;
    e.retry_after_secs = None;
    e.failures = 0;
    e.next_attempt_at = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/ubuntu/cves_page_real.json"
        ))
        .unwrap()
    }

    fn find<'a>(r: &'a Record, release: &str, package: &str) -> &'a Entry {
        r.entries
            .iter()
            .find(|e| e.release == release && e.package == package)
            .unwrap_or_else(|| panic!("{release}/{package}"))
    }

    /// Echte Antwort: nur Kernel-Pakete, kein `upstream`, kein DNE.
    #[test]
    fn real_page_keeps_only_kernel_entries() {
        let recs: Vec<Record> = page()["cves"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(parse_cve)
            .collect();
        assert_eq!(recs.len(), 5);
        for r in &recs {
            assert!(
                r.entries.iter().all(|e| is_kernel_source(&e.package)),
                "{}",
                r.cve_id
            );
            assert!(r.entries.iter().all(|e| e.release != "upstream"));
            assert!(r.entries.iter().all(|e| e.raw["status"] != "DNE"));
            assert!(r.updated_at.is_some(), "{}", r.cve_id);
        }
        assert!(recs.iter().all(|r| r
            .entries
            .iter()
            .all(|e| e.package != "openssl" && e.package != "linux-firmware")));
    }

    #[test]
    fn real_cve_2024_1086_statuses() {
        let single: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/ubuntu/cve_single_real.json"
        ))
        .unwrap();
        let r = parse_cve(&single).unwrap();
        assert_eq!(r.cve_id, "CVE-2024-1086");
        assert_eq!(r.priority.as_deref(), Some("high"));
        let released: Vec<_> = r
            .entries
            .iter()
            .filter(|e| e.status == SourceStatus::Fixed)
            .collect();
        assert!(!released.is_empty());
        // Fix-Versionen sind gültige dpkg-Versionen.
        assert!(released
            .iter()
            .all(|e| e.fix_version.as_deref().is_some_and(valid_version)));
        let jammy = find(&r, "jammy", "linux");
        assert_eq!(jammy.status, SourceStatus::Fixed);
    }

    #[test]
    fn status_mapping() {
        use SourceStatus::*;
        assert_eq!(
            map_status("released", "6.8.0-35.35"),
            Some((Fixed, Some("6.8.0-35.35".into())))
        );
        assert_eq!(map_status("released", ""), Some((Unknown, None)));
        assert_eq!(
            map_status("released", "7.3~rc2, 6.17.y"),
            Some((Unknown, None))
        );
        assert_eq!(
            map_status("pending", "6.8.0-149.149"),
            Some((FixPending, Some("6.8.0-149.149".into())))
        );
        assert_eq!(map_status("pending", ""), Some((FixPending, None)));
        assert_eq!(map_status("needed", ""), Some((Vulnerable, None)));
        assert_eq!(
            map_status("ignored", "end of standard support"),
            Some((Vulnerable, None))
        );
        assert_eq!(
            map_status("not-affected", "5.13.0-19.19"),
            Some((NotAffected, None))
        );
        assert_eq!(map_status("needs-triage", ""), Some((Unknown, None)));
        assert_eq!(map_status("DNE", ""), None);
        assert_eq!(map_status("brand-new-status", ""), Some((Unknown, None)));
    }

    #[test]
    fn rejects_non_cve_and_broken_objects() {
        assert!(parse_cve(&json!({"id": "USN-1234-1", "packages": []})).is_none());
        assert!(parse_cve(&json!({"id": "CVE-2024-1086"})).is_none());
        assert!(parse_cve(&json!("quatsch")).is_none());
    }
}
