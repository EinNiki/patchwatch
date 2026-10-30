//! Debian Security Tracker (`/tracker/data/json`, ca. 87 MB entpackt, 14 MB gzip).
//! Liefert keinen ETag, aber `Last-Modified` (geprüft); `If-Modified-Since` ergibt bei Unverändertem 304.
//! Geparst wird streamend: nur Kernel-Quellpakete werden materialisiert, der Rest wird übersprungen.

use super::http::{self, header_str, Limits};
use super::{
    is_cve_id, is_kernel_source, truncate, valid_version, CveSource, Entry, FeedError, FeedState,
    FetchCtx, FetchOutcome, Record, SourceStatus,
};
use crate::config::CveConfig;
use async_trait::async_trait;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

pub struct Debian {
    url: String,
    lim: Limits,
}

impl Debian {
    pub fn new(c: &CveConfig) -> Self {
        Self {
            url: c.debian_url.clone(),
            lim: Limits {
                max_bytes: c.debian_max_bytes,
                timeout: Duration::from_secs(c.request_timeout_secs),
                attempts: c.retries,
                base_delay: Duration::from_millis(c.retry_base_delay_ms),
            },
        }
    }
}

#[derive(Deserialize)]
struct DebCve {
    description: Option<String>,
    #[serde(default)]
    releases: BTreeMap<String, DebRelease>,
}

#[derive(Deserialize)]
struct DebRelease {
    #[serde(default)]
    status: String,
    fixed_version: Option<String>,
    urgency: Option<String>,
}

fn map_status(r: &DebRelease) -> (SourceStatus, Option<String>) {
    match (r.status.as_str(), r.fixed_version.as_deref()) {
        // "0" heißt im Tracker: war nie betroffen.
        ("resolved", Some("0")) => (SourceStatus::NotAffected, None),
        ("resolved", Some(v)) if valid_version(v) => (SourceStatus::Fixed, Some(v.to_owned())),
        ("open", _) => (SourceStatus::Vulnerable, None),
        // "undetermined" und jede unerwartete Kombination bleiben UNKNOWN, nie grün.
        _ => (SourceStatus::Unknown, None),
    }
}

fn urgency_rank(u: &str) -> u8 {
    match u {
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "unimportant" => 1,
        _ => 0,
    }
}

struct Parsed {
    records: Vec<Record>,
    saw_linux: bool,
}

struct RootVisitor;

impl<'de> Visitor<'de> for RootVisitor {
    type Value = Parsed;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("ein Objekt Paket -> CVE -> Details")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Parsed, A::Error> {
        let mut out = Parsed {
            records: Vec::new(),
            saw_linux: false,
        };
        while let Some(pkg) = map.next_key::<String>()? {
            if !is_kernel_source(&pkg) {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            let cves: BTreeMap<String, DebCve> = map.next_value()?;
            out.saw_linux |= pkg == "linux" && !cves.is_empty();
            for (id, c) in cves {
                if !is_cve_id(&id) {
                    continue; // z. B. "TEMP-0000000-…"
                }
                let mut best = (0, None::<String>);
                let entries = c
                    .releases
                    .iter()
                    .map(|(rel, r)| {
                        let (status, fix_version) = map_status(r);
                        if let Some(u) = r.urgency.as_deref() {
                            if urgency_rank(u) > best.0 {
                                best = (urgency_rank(u), Some(u.to_owned()));
                            }
                        }
                        Entry {
                            release: rel.clone(),
                            package: pkg.clone(),
                            status,
                            fix_version,
                            raw: json!({ "status": r.status, "fixed_version": r.fixed_version, "urgency": r.urgency }),
                        }
                    })
                    .collect();
                out.records.push(Record {
                    cve_id: id,
                    description: c
                        .description
                        .as_deref()
                        .map(|d| truncate(d.trim(), 2000))
                        .filter(|d| !d.is_empty()),
                    priority: best.1,
                    entries,
                    ..Record::default()
                });
            }
        }
        Ok(out)
    }
}

impl<'de> Deserialize<'de> for Parsed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(RootVisitor)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Vec<Record>, FeedError> {
    let parsed: Parsed =
        serde_json::from_slice(bytes).map_err(|e| FeedError::Format(e.to_string()))?;
    // Ohne `linux`-Eintrag hat sich das Format geändert; nicht stillschweigend alles als "weg" werten.
    if !parsed.saw_linux {
        return Err(FeedError::Format(
            "kein Eintrag für das Quellpaket `linux`".into(),
        ));
    }
    Ok(parsed.records)
}

#[async_trait]
impl CveSource for Debian {
    fn name(&self) -> &'static str {
        "debian"
    }

    async fn fetch(
        &self,
        client: &reqwest::Client,
        state: &FeedState,
        _ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError> {
        let mut extra = Vec::new();
        if let Some(lm) = state.last_modified.as_deref() {
            extra.push(("if-modified-since", lm));
        }
        let f = http::get(client, &self.url, &extra, self.lim).await?;
        if f.status == 304 {
            return Ok(FetchOutcome::NotModified);
        }
        // Parsen ist CPU-lastig (ca. 87 MB), daher nicht auf dem Async-Executor.
        let body = f.body;
        let records = tokio::task::spawn_blocking(move || parse(&body))
            .await
            .map_err(|e| FeedError::Format(format!("Parser abgebrochen: {e}")))??;
        Ok(FetchOutcome::Records {
            records,
            state: FeedState {
                last_modified: header_str(&f.headers, "last-modified"),
                ..state.clone()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed() -> Vec<Record> {
        parse(include_bytes!(
            "../../tests/fixtures/debian/tracker_subset_real.json"
        ))
        .unwrap()
    }

    fn entry<'a>(rs: &'a [Record], cve: &str, pkg: &str, rel: &str) -> &'a Entry {
        rs.iter()
            .filter(|r| r.cve_id == cve)
            .flat_map(|r| &r.entries)
            .find(|e| e.package == pkg && e.release == rel)
            .unwrap_or_else(|| panic!("{cve} {pkg} {rel}"))
    }

    /// Echte Tracker-Daten: nur Kernel-Pakete, Nicht-CVE-IDs (TEMP-…) übersprungen.
    #[test]
    fn real_subset_filters_packages_and_ids() {
        let rs = parsed();
        assert!(rs.iter().all(|r| r.cve_id.starts_with("CVE-")));
        assert!(rs
            .iter()
            .flat_map(|r| &r.entries)
            .all(|e| is_kernel_source(&e.package)));
        assert!(rs
            .iter()
            .flat_map(|r| &r.entries)
            .all(|e| e.package != "openssl" && e.package != "linux-atm"));
    }

    #[test]
    fn real_trixie_statuses() {
        let rs = parsed();
        let e = entry(&rs, "CVE-2024-1086", "linux", "trixie");
        assert_eq!(
            (e.status, e.fix_version.as_deref()),
            (SourceStatus::Fixed, Some("6.6.15-1"))
        );
        assert_eq!(
            entry(&rs, "CVE-2004-0230", "linux", "trixie").status,
            SourceStatus::Vulnerable
        );
        assert_eq!(
            entry(&rs, "CVE-2020-0347", "linux", "trixie").status,
            SourceStatus::Unknown
        );
        let zero = entry(&rs, "CVE-2003-1604", "linux", "trixie");
        assert_eq!(
            (zero.status, zero.fix_version.as_deref()),
            (SourceStatus::NotAffected, None)
        );
    }

    #[test]
    fn format_change_is_an_error_not_silence() {
        assert!(matches!(parse(b"[]"), Err(FeedError::Format(_))));
        assert!(matches!(
            parse(b"{\"openssl\":{}}"),
            Err(FeedError::Format(_))
        ));
        assert!(matches!(
            parse(b"{\"linux\":{}}"),
            Err(FeedError::Format(_))
        ));
        assert!(matches!(parse(b"kein json"), Err(FeedError::Format(_))));
    }

    #[test]
    fn unexpected_status_combinations_stay_unknown() {
        let r = |status: &str, fv: Option<&str>| DebRelease {
            status: status.into(),
            fixed_version: fv.map(str::to_owned),
            urgency: None,
        };
        assert_eq!(map_status(&r("resolved", None)).0, SourceStatus::Unknown);
        assert_eq!(
            map_status(&r("resolved", Some("kaputt version"))).0,
            SourceStatus::Unknown
        );
        assert_eq!(map_status(&r("neu", None)).0, SourceStatus::Unknown);
    }
}
