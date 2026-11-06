//! CISA Known Exploited Vulnerabilities: Hinweis "aktiv ausgenutzt" für bereits bekannte CVEs (Anreicherung, kein Import).
//! Der Eintrag (Release `*`, Paket `cisa_kev`, Status unbekannt) trägt nur den Hinweis und beeinflusst keine Host-Bewertung.
//! Der Katalog (ca. 1,5 MB) wird je Lauf vollständig geladen, damit später bekannt gewordene CVEs nachgezogen werden; Limit 5 MiB.

use super::http::{self, Limits};
use super::{
    is_cve_id, truncate, CveSource, Entry, FeedError, FeedState, FetchCtx, FetchOutcome, Record,
    SourceStatus,
};
use crate::config::CveConfig;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::Duration;

const MAX_BYTES: u64 = 5 * 1024 * 1024;

pub struct Kev {
    url: String,
    client: Option<reqwest::Client>,
    lim: Limits,
}

impl Kev {
    pub fn new(c: &CveConfig, base: Option<String>, client: Option<reqwest::Client>) -> Self {
        Self {
            url: base.unwrap_or_else(|| c.kev_url.clone()),
            client,
            lim: Limits {
                max_bytes: MAX_BYTES,
                timeout: Duration::from_secs(c.request_timeout_secs),
                attempts: c.retries,
                base_delay: Duration::from_millis(c.retry_base_delay_ms),
                retry_after_cap: super::http::RETRY_AFTER_CAP,
            },
        }
    }
}

pub fn parse(body: &Value) -> Result<Vec<Record>, FeedError> {
    let list = body
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| FeedError::Format("vulnerabilities fehlt".into()))?;
    let s = |v: &Value, k: &str, n: usize| v.get(k).and_then(Value::as_str).map(|x| truncate(x, n));
    Ok(list
        .iter()
        .filter_map(|v| {
            let id = v.get("cveID")?.as_str()?;
            is_cve_id(id).then(|| Record {
                cve_id: id.to_owned(),
                entries: vec![Entry {
                    release: "*".into(),
                    package: "cisa_kev".into(),
                    status: SourceStatus::Unknown,
                    fix_version: None,
                    raw: json!({
                        "name": s(v, "vulnerabilityName", 200),
                        "date_added": s(v, "dateAdded", 20),
                        "due_date": s(v, "dueDate", 20),
                        "ransomware": s(v, "knownRansomwareCampaignUse", 20),
                    }),
                }],
                ..Record::default()
            })
        })
        .collect())
}

#[async_trait]
impl CveSource for Kev {
    fn name(&self) -> &'static str {
        "cisa_kev"
    }

    async fn fetch(
        &self,
        shared: &reqwest::Client,
        state: &FeedState,
        _ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError> {
        let client = self.client.as_ref().unwrap_or(shared);
        let f = http::get(client, &self.url, &[], self.lim).await?;
        let v: Value = serde_json::from_slice(&f.body)
            .map_err(|e| FeedError::Format(format!("kein JSON: {e}")))?;
        Ok(FetchOutcome::Records {
            records: parse(&v)?,
            state: state.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_catalog_and_skips_foreign_ids() {
        let v = json!({"vulnerabilities": [
            {"cveID": "CVE-2024-1086", "vulnerabilityName": "Linux Kernel Use-After-Free", "dateAdded": "2024-05-30", "dueDate": "2024-06-20", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "NOT-A-CVE"},
        ]});
        let r = parse(&v).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].entries[0].package, "cisa_kev");
        assert_eq!(r[0].entries[0].raw["ransomware"], "Known");
        assert!(parse(&json!({})).is_err());
    }
}
