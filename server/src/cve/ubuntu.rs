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

/// Seitengröße; eine Seite ist ca. 3,7 MB groß (eingebettete `notices`), daher klein halten.
const PAGE: usize = 20;
/// Höchstens so viele Watchlist-CVEs pro Lauf einzeln nachladen.
const MAX_WATCH_FETCH: usize = 25;

pub struct Ubuntu {
    base: String,
    backfill_pages: u32,
    max_pages: u32,
    lim: Limits,
}

impl Ubuntu {
    pub fn new(c: &CveConfig) -> Self {
        Self {
            base: c.ubuntu_url.trim_end_matches('/').to_owned(),
            backfill_pages: c.ubuntu_backfill_pages,
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
        // altem Cursor und Listenkopf geschlossen ist; solange sie offen ist, steht der Fortschritt in `backfill`.
        let confirmed = state.cursor.as_deref().and_then(parse_time);
        // Ein Rückstandsabbau wird nur fortgesetzt, wenn er zum bestätigten Cursor passt (wurde der Cursor
        // von Hand geändert oder ist der Eintrag beschädigt, beginnt der Abruf wieder bei Seite 1).
        let resume = state.backfill.as_ref().filter(|b| {
            state.cursor.as_deref() == Some(b.target.as_str())
                && parse_time(&b.target).is_some()
                && parse_time(&b.pending).is_some()
        });
        let max_pages = if confirmed.is_some() {
            self.max_pages
        } else {
            self.backfill_pages
        };
        // Ohne Cursor ist es der Erstabruf: bewusst begrenzt (Backfill) und danach als vollständig gewertet.
        let mut complete = confirmed.is_none();
        let start_offset = resume.map_or(0, |b| b.next_offset as usize);
        // Neuester gesehener Zeitstempel des gesamten Durchlaufs (über Läufe hinweg in `pending` gehalten).
        let mut newest = resume.and_then(|b| parse_time(&b.pending)).or(confirmed);
        let mut records: Vec<Record> = Vec::new();
        let mut pages_fetched = 0usize;
        let mut interrupted: Option<FeedError> = None;

        'pages: for i in 0..max_pages as usize {
            let url = format!(
                "{}/security/cves.json?package=linux&limit={PAGE}&offset={}&order=descending&sort_by=updated",
                self.base,
                start_offset + i * PAGE
            );
            // Eine Seite wird ganz oder gar nicht übernommen; so zeigt der Fortschritt nie über Daten hinaus,
            // die wirklich gespeichert werden.
            let page = match fetch_page(client, &url, self.lim, confirmed).await {
                Ok(p) => p,
                // Schon Fortschritt erzielt: behalten und beim nächsten Lauf weitermachen, nicht wegwerfen.
                Err(e) if pages_fetched > 0 => {
                    interrupted = Some(e);
                    break 'pages;
                }
                Err(e) => return Err(e),
            };
            pages_fetched += 1;
            records.extend(page.records);
            newest = newest.max(page.newest);
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
                ..state.clone()
            }
        } else {
            // `complete == false` heißt: es gibt einen Cursor und wir haben mindestens eine Seite gelesen.
            let (Some(target), Some(pending)) = (state.cursor.clone(), newest) else {
                return Err(FeedError::Format("Rückstand ohne Cursor".into()));
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
                    target,
                    pending: pending.to_rfc3339(),
                    next_offset: next as u32,
                    pages_done: prev.map_or(0, |b| b.pages_done) + pages_fetched as u32,
                    runs: prev.map_or(0, |b| b.runs) + 1,
                    started_at: prev.map_or_else(Utc::now, |b| b.started_at),
                }),
                ..state.clone()
            }
        };
        if complete && confirmed.is_none() && records.is_empty() {
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
    /// Bestätigter Cursor erreicht oder Listenende: alles Ältere ist bereits bekannt.
    reached_end: bool,
}

async fn fetch_page(
    client: &reqwest::Client,
    url: &str,
    lim: Limits,
    stop_at: Option<DateTime<Utc>>,
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
        reached_end: cves.len() < PAGE,
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
