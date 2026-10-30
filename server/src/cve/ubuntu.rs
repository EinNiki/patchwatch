//! Ubuntu CVE Tracker (`/security/cves.json`).
//!
//! Die API hat keinen serverseitigen "updated since"-Filter (geprüft: nur `package`, `limit`, `offset`,
//! `order`, `sort_by`, `version`, `status`, `priority`, `component`, `show_hidden`). Deshalb wird absteigend
//! nach `updated` sortiert paginiert und gestoppt, sobald der gespeicherte Cursor erreicht ist.

use super::http::{self, Limits};
use super::{
    is_cve_id, is_kernel_source, truncate, valid_version, CveSource, Entry, FeedError, FeedState,
    FetchCtx, FetchOutcome, Record, SourceStatus,
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
        let cursor = state.cursor.as_deref().and_then(parse_time);
        let max_pages = if cursor.is_some() {
            self.max_pages
        } else {
            self.backfill_pages
        };
        let mut records: Vec<Record> = Vec::new();
        let mut newest = cursor;
        // Erstabruf ist bewusst begrenzt (Backfill); danach muss der Cursor erreicht werden.
        let mut complete = cursor.is_none();

        'pages: for page in 0..max_pages as usize {
            let url = format!(
                "{}/security/cves.json?package=linux&limit={PAGE}&offset={}&order=descending&sort_by=updated",
                self.base,
                page * PAGE
            );
            let f = http::get(client, &url, &[("accept", "application/json")], self.lim).await?;
            let v: Value = serde_json::from_slice(&f.body)
                .map_err(|e| FeedError::Format(format!("kein JSON: {e}")))?;
            let cves = v
                .get("cves")
                .and_then(Value::as_array)
                .ok_or_else(|| FeedError::Format("Feld `cves` fehlt".into()))?;
            for c in cves {
                let updated = c
                    .get("updated_at")
                    .and_then(Value::as_str)
                    .and_then(parse_time)
                    .ok_or_else(|| {
                        FeedError::Format("`updated_at` fehlt oder ist ungültig".into())
                    })?;
                if cursor.is_some_and(|cur| updated <= cur) {
                    complete = true;
                    break 'pages;
                }
                newest = Some(newest.map_or(updated, |n| n.max(updated)));
                if let Some(rec) = parse_cve(c) {
                    records.push(rec);
                }
            }
            if cves.len() < PAGE {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(FeedError::Incomplete(format!(
                "Cursor nach {max_pages} Seiten nicht erreicht"
            )));
        }
        if cursor.is_none() && records.is_empty() {
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

        if records.is_empty() {
            return Ok(FetchOutcome::NotModified);
        }
        Ok(FetchOutcome::Records {
            records,
            state: FeedState {
                cursor: newest.map(|n| n.to_rfc3339()),
                ..state.clone()
            },
        })
    }
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
