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
use super::{
    is_cve_id, is_kernel_source, truncate, valid_version, Backfill, CveSource, Entry, FeedError,
    FeedState, FetchCtx, FetchOutcome, Record, SourceStatus,
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
    lim: Limits,
}

impl Ubuntu {
    pub fn new(c: &CveConfig) -> Self {
        Self {
            base: c.ubuntu_url.trim_end_matches('/').to_owned(),
            horizon_days: c.ubuntu_horizon_days,
            max_pages: c.ubuntu_max_pages,
            lim: Limits {
                max_bytes: c.ubuntu_max_page_bytes,
                timeout: Duration::from_secs(c.request_timeout_secs),
                attempts: c.retries,
                base_delay: Duration::from_millis(c.retry_base_delay_ms),
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

        // Watchlist-CVEs, die nicht im neuesten Fenster liegen, gezielt nachladen.
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

        if !complete {
            return Ok(FetchOutcome::Partial {
                records,
                state: new_state,
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
