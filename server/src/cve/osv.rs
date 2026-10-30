//! OSV.dev als optionale dritte Quelle, abgefragt je Host-Kernelversion (`POST /v1/query`).
//!
//! Aus Echtdaten gelernt: Die Antwort enthält in `affected[]` auch fremde Ökosysteme (z. B. `Ubuntu:Pro:…`),
//! bei Ubuntu steckt die CVE-ID nur in der OSV-ID (`UBUNTU-CVE-…`, `aliases` leer), und Debian paginiert
//! (`next_page_token`, ca. 2000 Treffer je Seite).

use super::http::{self, Limits};
use super::{
    is_cve_id, truncate, valid_version, CveSource, Entry, FeedError, FeedState, FetchCtx,
    FetchOutcome, HostRef, Record, SourceStatus,
};
use crate::config::CveConfig;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use debversion::Version;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

const MAX_PAGES: usize = 5;
/// Ergebnisse gelten höchstens so lange als aktuell (neue Abfrage spätestens nach 6 h).
const REFRESH_SECS: u64 = 6 * 3600;

pub struct Osv {
    base: String,
    lim: Limits,
}

impl Osv {
    pub fn new(c: &CveConfig) -> Self {
        Self {
            base: c.osv_url.trim_end_matches('/').to_owned(),
            lim: Limits {
                max_bytes: 32 * 1024 * 1024,
                timeout: Duration::from_secs(c.request_timeout_secs),
                attempts: c.retries,
                base_delay: Duration::from_millis(c.retry_base_delay_ms),
            },
        }
    }
}

/// OSV-Ökosystem eines Hosts; `None` für nicht unterstützte Distributionen (z. B. Proxmox-Kernel).
pub fn ecosystem(distro_id: &str, os_version: &str) -> Option<String> {
    match distro_id {
        "ubuntu" => {
            let (year, month) = os_version.split_once('.')?;
            let lts = month == "04" && year.parse::<u32>().ok()? % 2 == 0;
            Some(if lts {
                format!("Ubuntu:{os_version}:LTS")
            } else {
                format!("Ubuntu:{os_version}")
            })
        }
        "debian" => Some(format!("Debian:{}", os_version.split('.').next()?)),
        _ => None,
    }
}

/// CVE-ID aus der OSV-ID (`UBUNTU-CVE-…`, `DEBIAN-CVE-…`) oder den Aliasen.
fn cve_id(v: &Value) -> Option<String> {
    let id = v.get("id")?.as_str()?;
    let stripped = id
        .strip_prefix("UBUNTU-")
        .or_else(|| id.strip_prefix("DEBIAN-"))
        .unwrap_or(id);
    if is_cve_id(stripped) {
        return Some(stripped.to_owned());
    }
    v.get("aliases")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find(|a| is_cve_id(a))
        .map(str::to_owned)
}

/// Kleinste Fix-Version oberhalb der abgefragten Version; ohne Fix gilt "verwundbar".
fn fix_above(affected: &Value, version: &Version) -> Option<String> {
    affected
        .get("ranges")?
        .as_array()?
        .iter()
        .flat_map(|r| {
            r.get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|e| e.get("fixed").and_then(Value::as_str))
        .filter_map(|f| f.parse::<Version>().ok().map(|p| (p, f)))
        .filter(|(p, _)| p > version)
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, f)| f.to_owned())
}

/// Antwort einer Versionsabfrage in Records übersetzen.
pub fn parse_response(body: &Value, eco: &str, host: &HostRef) -> Result<Vec<Record>, FeedError> {
    let Some(version) = host.version.parse::<Version>().ok() else {
        return Err(FeedError::Format(format!(
            "ungültige Hostversion {}",
            host.version
        )));
    };
    let mut out = Vec::new();
    for v in body
        .get("vulns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(id) = cve_id(v) else { continue };
        // Nur der Eintrag für exakt dieses Ökosystem und Paket zählt.
        let Some(aff) = v
            .get("affected")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|a| {
                a["package"]["ecosystem"] == eco && a["package"]["name"] == host.package.as_str()
            })
        else {
            continue;
        };
        let fix = fix_above(aff, &version).filter(|f| valid_version(f));
        let (status, fix_version) = match fix {
            Some(f) => (SourceStatus::Fixed, Some(f)),
            None => (SourceStatus::Vulnerable, None),
        };
        let time = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
        };
        out.push(Record {
            cve_id: id,
            description: v.get("details").and_then(Value::as_str).map(|d| truncate(d.trim(), 2000)).filter(|d| !d.is_empty()),
            published_at: time("published"),
            updated_at: time("modified"),
            entries: vec![Entry {
                release: host.codename.clone(),
                package: host.package.clone(),
                status,
                fix_version: fix_version.clone(),
                raw: json!({ "osv_id": v.get("id"), "ecosystem": eco, "queried_version": host.version, "fixed": fix_version }),
            }],
            ..Record::default()
        });
    }
    Ok(out)
}

fn digest(hosts: &[(String, &HostRef)]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for (eco, host) in hosts {
        (eco, &host.package, &host.version, &host.codename).hash(&mut h);
    }
    h.finish()
}

#[async_trait]
impl CveSource for Osv {
    fn name(&self) -> &'static str {
        "osv"
    }

    async fn fetch(
        &self,
        client: &reqwest::Client,
        state: &FeedState,
        ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError> {
        let mut queries: BTreeMap<(String, String, String), (String, &HostRef)> = BTreeMap::new();
        for h in &ctx.hosts {
            if let Some(eco) = ecosystem(&h.distro_id, &h.os_version) {
                queries.insert(
                    (eco.clone(), h.package.clone(), h.version.clone()),
                    (eco, h),
                );
            }
        }
        let list: Vec<(String, &HostRef)> = queries.into_values().collect();
        if list.is_empty() {
            return Ok(FetchOutcome::NotModified);
        }
        // Cursor = Hash der Abfragen + 6-Stunden-Fenster: unverändert -> keine neue Anfrage.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let cursor = format!("{:x}:{}", digest(&list), now / REFRESH_SECS);
        if state.cursor.as_deref() == Some(cursor.as_str()) {
            return Ok(FetchOutcome::NotModified);
        }

        let mut records = Vec::new();
        for (eco, host) in &list {
            let mut token: Option<String> = None;
            for _ in 0..MAX_PAGES {
                let mut body = json!({ "version": host.version, "package": { "name": host.package, "ecosystem": eco } });
                if let Some(t) = &token {
                    body["page_token"] = json!(t);
                }
                let f =
                    http::post_json(client, &format!("{}/v1/query", self.base), &body, self.lim)
                        .await?;
                let v: Value = serde_json::from_slice(&f.body)
                    .map_err(|e| FeedError::Format(format!("kein JSON: {e}")))?;
                if !v.is_object() {
                    return Err(FeedError::Format("Antwort ist kein Objekt".into()));
                }
                records.extend(parse_response(&v, eco, host)?);
                token = v
                    .get("next_page_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if token.is_none() {
                    break;
                }
            }
        }
        Ok(FetchOutcome::Records {
            records,
            state: FeedState {
                cursor: Some(cursor),
                ..state.clone()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(distro: &str, ver: &str, codename: &str, version: &str) -> HostRef {
        HostRef {
            distro_id: distro.into(),
            os_version: ver.into(),
            codename: codename.into(),
            package: "linux".into(),
            version: version.into(),
        }
    }

    fn load(name: &str) -> Value {
        let text = match name {
            "ubuntu" => include_str!("../../tests/fixtures/osv/query_ubuntu_real.json"),
            _ => include_str!("../../tests/fixtures/osv/query_debian_real.json"),
        };
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn ecosystem_names() {
        assert_eq!(
            ecosystem("ubuntu", "24.04").as_deref(),
            Some("Ubuntu:24.04:LTS")
        );
        assert_eq!(
            ecosystem("ubuntu", "22.04").as_deref(),
            Some("Ubuntu:22.04:LTS")
        );
        assert_eq!(
            ecosystem("ubuntu", "25.10").as_deref(),
            Some("Ubuntu:25.10")
        );
        assert_eq!(
            ecosystem("ubuntu", "23.04").as_deref(),
            Some("Ubuntu:23.04")
        );
        assert_eq!(ecosystem("debian", "13").as_deref(), Some("Debian:13"));
        assert_eq!(ecosystem("proxmox", "9"), None);
    }

    /// Echte Ubuntu-Antwort: ID nur in der OSV-ID, fremdes Ökosystem (Pro) wird ignoriert.
    #[test]
    fn real_ubuntu_response() {
        let h = host("ubuntu", "24.04", "noble", "6.8.0-31.31");
        let recs = parse_response(&load("ubuntu"), "Ubuntu:24.04:LTS", &h).unwrap();
        let fixed = recs.iter().find(|r| r.cve_id == "CVE-2020-12351").unwrap();
        let e = &fixed.entries[0];
        assert_eq!(
            (e.status, e.fix_version.as_deref(), e.release.as_str()),
            (SourceStatus::Fixed, Some("6.8.0-35.35"), "noble")
        );
        let open = recs.iter().find(|r| r.cve_id == "CVE-2012-4542").unwrap();
        assert_eq!(open.entries[0].status, SourceStatus::Vulnerable);
        assert!(recs.iter().all(|r| r.entries.len() == 1));
    }

    #[test]
    fn real_debian_response_and_ecosystem_filter() {
        let h = host("debian", "13", "trixie", "6.12.48-1");
        let recs = parse_response(&load("debian"), "Debian:13", &h).unwrap();
        assert!(recs.iter().any(|r| r.cve_id == "CVE-2024-14027"
            && r.entries[0].fix_version.as_deref() == Some("6.12.85-1")));
        // Falsches Ökosystem findet nichts.
        assert!(parse_response(&load("debian"), "Debian:99", &h)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn fix_is_smallest_above_queried_version() {
        let aff = json!({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.1.76-1"}, {"introduced": "6.2"}, {"fixed": "6.12.10-1"}]}]});
        let v = |s: &str| s.parse::<Version>().unwrap();
        assert_eq!(fix_above(&aff, &v("6.1.10-1")).as_deref(), Some("6.1.76-1"));
        assert_eq!(fix_above(&aff, &v("6.5.0-1")).as_deref(), Some("6.12.10-1"));
        assert_eq!(fix_above(&aff, &v("7.0-1")), None);
    }

    #[test]
    fn non_cve_ids_are_skipped() {
        let h = host("debian", "13", "trixie", "6.12.48-1");
        let body = json!({"vulns": [{"id": "DEBIAN-DLA-1234-1", "aliases": [], "affected": [{"package": {"name": "linux", "ecosystem": "Debian:13"}}]}]});
        assert!(parse_response(&body, "Debian:13", &h).unwrap().is_empty());
    }
}
