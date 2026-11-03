//! NVD (CVE API 2.0) als reine Anreicherung: Beschreibung, Veröffentlichung und CVSS-Schwere für bereits bekannte CVEs
//! (Tabelle `cves`, Watchlist zuerst), nie ein Vollimport. Je CVE eine Anfrage (`?cveId=`).
//!
//! Limits der NVD: 5 Anfragen je 30 s ohne API-Schlüssel, 50 mit. Wir bleiben darunter (Pause zwischen den Anfragen) und
//! begrenzen die Menge je Lauf; was nicht drankommt, kommt beim nächsten Lauf. Antworten sind auf 5 MiB begrenzt.
//! Der Schlüssel geht nur im Header `apiKey` raus und taucht in keiner Fehlermeldung auf.
//! Der Eintrag (Release `*`, Paket `nvd`, Status unbekannt) markiert die CVE als angereichert; er beeinflusst keinen Host,
//! weil er zu keinem (Release, Paket) eines Hosts passt.

use super::http::{self, Limits};
use super::{
    is_cve_id, truncate, CveSource, Entry, FeedError, FeedState, FetchCtx, FetchOutcome, Record,
    SourceStatus,
};
use crate::config::CveConfig;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{json, Value};
use std::time::Duration;

/// CVEs je Lauf: ohne Schlüssel 10 (ca. 1 Minute), mit Schlüssel 50 (ca. 30 s).
const BATCH_NO_KEY: usize = 10;
const BATCH_WITH_KEY: usize = 50;
/// Pause zwischen zwei Anfragen: 5 je 30 s (6 s) ohne, 50 je 30 s (0,6 s) mit Schlüssel.
const PAUSE_NO_KEY: Duration = Duration::from_millis(6_000);
const PAUSE_WITH_KEY: Duration = Duration::from_millis(600);
const MAX_BYTES: u64 = 5 * 1024 * 1024;

pub struct Nvd {
    base: String,
    client: Option<reqwest::Client>,
    key: Option<String>,
    lim: Limits,
    pause: Duration,
}

impl Nvd {
    pub fn new(
        c: &CveConfig,
        base: Option<String>,
        client: Option<reqwest::Client>,
        key: Option<String>,
    ) -> Self {
        // Der Schlüssel geht im Header `apiKey` raus; reqwest entfernt nur Authorization/Cookie bei einem Redirect auf
        // einen anderen Host, nicht diesen Header. Daher kein Redirect, wenn ein Schlüssel im Spiel ist (der
        // übergebene Spiegel-Client ist bereits ohne Redirect).
        let client = client.or_else(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(20))
                .user_agent(concat!("patchwatch-server/", env!("CARGO_PKG_VERSION")))
                .build()
                .ok()
        });
        let pause = if key.is_some() {
            PAUSE_WITH_KEY
        } else {
            PAUSE_NO_KEY
        };
        Self {
            base: base.unwrap_or_else(|| c.nvd_url.trim_end_matches('/').to_owned()),
            client,
            key,
            lim: Limits {
                max_bytes: MAX_BYTES,
                timeout: Duration::from_secs(c.request_timeout_secs),
                attempts: 1,
                base_delay: Duration::from_millis(c.retry_base_delay_ms),
            },
            // Tests setzen eine winzige Retry-Basis und brauchen keine Pausen; in Betrieb gilt immer die Rate-Limit-Pause.
            pause: if c.retry_base_delay_ms < 100 {
                Duration::ZERO
            } else {
                pause
            },
        }
    }

    fn batch(&self) -> usize {
        if self.key.is_some() {
            BATCH_WITH_KEY
        } else {
            BATCH_NO_KEY
        }
    }
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>().ok().or_else(|| {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
            .ok()
            .map(|n| n.and_utc())
    })
}

/// Antwort einer `?cveId=`-Abfrage in einen Record übersetzen. Unbekannte CVE: leere Anreicherung als Markierung.
pub fn parse_response(id: &str, body: &Value) -> Result<Record, FeedError> {
    let vulns = body
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| FeedError::Format("vulnerabilities fehlt".into()))?;
    let cve = vulns
        .iter()
        .filter_map(|v| v.get("cve"))
        .find(|c| c.get("id").and_then(Value::as_str) == Some(id));
    let mut rec = Record {
        cve_id: id.to_owned(),
        ..Record::default()
    };
    let mut raw = json!({ "found": cve.is_some() });
    if let Some(c) = cve {
        rec.description = c
            .get("descriptions")
            .and_then(Value::as_array)
            .and_then(|d| {
                d.iter()
                    .find(|x| x.get("lang").and_then(Value::as_str) == Some("en"))
            })
            .and_then(|d| d.get("value"))
            .and_then(Value::as_str)
            .map(|d| truncate(d, 2000));
        rec.published_at = c
            .get("published")
            .and_then(Value::as_str)
            .and_then(parse_time);
        rec.updated_at = c
            .get("lastModified")
            .and_then(Value::as_str)
            .and_then(parse_time);
        // CVSS: v3.1 vor v3.0 vor v2; bei mehreren Einträgen der erste (Primary).
        let metric = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
            .iter()
            .find_map(|k| c.pointer(&format!("/metrics/{k}/0")));
        if let Some(m) = metric {
            let data = &m["cvssData"];
            let sev = data
                .get("baseSeverity")
                .or_else(|| m.get("baseSeverity"))
                .and_then(Value::as_str);
            rec.priority = sev.map(|s| truncate(&s.to_ascii_lowercase(), 20));
            raw["cvss_score"] = data.get("baseScore").cloned().unwrap_or(Value::Null);
            raw["severity"] = json!(sev);
        }
    }
    rec.entries.push(Entry {
        release: "*".into(),
        package: "nvd".into(),
        status: SourceStatus::Unknown,
        fix_version: None,
        raw,
    });
    Ok(rec)
}

#[async_trait]
impl CveSource for Nvd {
    fn name(&self) -> &'static str {
        "nvd"
    }

    async fn fetch(
        &self,
        shared: &reqwest::Client,
        state: &FeedState,
        ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError> {
        // Nie der gemeinsame Client (folgt Redirects): mit Schlüssel lieber Fehler als Schlüssel-Leck.
        let client = match (&self.client, &self.key) {
            (Some(c), _) => c,
            (None, None) => shared,
            (None, Some(_)) => return Err(FeedError::Network("HTTP-Client nicht baubar".into())),
        };
        let todo: Vec<&String> = ctx
            .enrich
            .iter()
            .filter(|c| is_cve_id(c))
            .take(self.batch())
            .collect();
        if todo.is_empty() {
            return Ok(FetchOutcome::NotModified);
        }
        let mut records = Vec::new();
        for (i, id) in todo.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(self.pause).await;
            }
            let url = format!("{}?cveId={id}", self.base);
            let key = self.key.as_deref();
            let fetched = http::execute(
                || {
                    let r = client.get(&url);
                    match key {
                        Some(k) => r.header("apiKey", k),
                        None => r,
                    }
                },
                self.lim,
            )
            .await;
            let parsed = fetched.and_then(|f| {
                serde_json::from_slice::<Value>(&f.body)
                    .map_err(|e| FeedError::Format(format!("kein JSON: {e}")))
                    .and_then(|v| parse_response(id, &v))
            });
            match parsed {
                Ok(r) => records.push(r),
                // Schon etwas geholt (z. B. dann 403/429): Teilergebnis behalten, der Rest folgt im nächsten Lauf.
                Err(_) if !records.is_empty() => break,
                Err(e) => return Err(e),
            }
        }
        Ok(FetchOutcome::Records {
            records,
            state: state.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_description_severity_and_dates() {
        let body = json!({"vulnerabilities": [{"cve": {
            "id": "CVE-2024-1086", "published": "2024-01-31T11:15:08.230",
            "lastModified": "2024-06-10T17:16:43.500",
            "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Use after free in netfilter"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}]}
        }}]});
        let r = parse_response("CVE-2024-1086", &body).unwrap();
        assert_eq!(
            r.description.as_deref(),
            Some("Use after free in netfilter")
        );
        assert_eq!(r.priority.as_deref(), Some("high"));
        assert!(r.published_at.is_some() && r.updated_at.is_some());
        assert_eq!(r.entries[0].package, "nvd");
        assert_eq!(r.entries[0].status, SourceStatus::Unknown);
        assert_eq!(r.entries[0].raw["cvss_score"], 7.8);
    }

    #[test]
    fn unknown_cve_still_gets_a_marker_and_wrong_shape_fails() {
        let r = parse_response("CVE-2099-0001", &json!({"vulnerabilities": []})).unwrap();
        assert_eq!(r.entries[0].raw["found"], false);
        assert!(r.description.is_none());
        assert!(parse_response("CVE-2099-0001", &json!({"nope": 1})).is_err());
        // Eine Antwort zu einer anderen CVE zählt nicht.
        let other = json!({"vulnerabilities": [{"cve": {"id": "CVE-2000-0001"}}]});
        assert_eq!(
            parse_response("CVE-2099-0001", &other).unwrap().entries[0].raw["found"],
            false
        );
    }

    #[test]
    fn batch_and_pause_respect_rate_limits() {
        let c = CveConfig::default();
        let n = Nvd::new(&c, None, None, None);
        let k = Nvd::new(&c, None, None, Some("k".into()));
        // 5 Anfragen je 30 s => mindestens 6 s Abstand; 50 je 30 s => mindestens 0,6 s.
        assert!(n.pause >= Duration::from_secs(6) && n.batch() == 10);
        assert!(k.pause >= Duration::from_millis(600) && k.batch() == 50);
    }
}
