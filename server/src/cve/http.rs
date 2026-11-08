use super::FeedError;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder, StatusCode};
use std::time::Duration;

pub struct Fetched {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub max_bytes: u64,
    pub timeout: Duration,
    pub attempts: u32,
    pub base_delay: Duration,
    /// Obergrenze für eine Wartezeit aus `Retry-After` (und für jede einzelne Backoff-Pause).
    pub retry_after_cap: Duration,
}

/// Standard-Obergrenze für `Retry-After`: 15 Minuten.
pub const RETRY_AFTER_CAP: Duration = Duration::from_secs(15 * 60);

/// Liest `Retry-After` (Sekunden oder HTTP-Datum) und deckelt den Wert. Unlesbares oder Vergangenes ergibt `None`
/// bzw. 0 s; die Obergrenze verhindert, dass eine Quelle uns beliebig lange blockiert.
pub fn parse_retry_after(
    value: &str,
    now: chrono::DateTime<chrono::Utc>,
    cap: Duration,
) -> Option<Duration> {
    let v = value.trim();
    let d = if let Ok(secs) = v.parse::<u64>() {
        Duration::from_secs(secs)
    } else {
        let at = chrono::DateTime::parse_from_rfc2822(v).ok()?;
        (at.with_timezone(&chrono::Utc) - now)
            .to_std()
            .unwrap_or(Duration::ZERO)
    };
    Some(d.min(cap))
}

/// Kleiner Zufallsanteil ohne zusätzliche Abhängigkeit (Jitter für Backoff und Scheduler).
pub fn jitter(max_ms: u64) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    Duration::from_millis(if max_ms == 0 { 0 } else { h.finish() % max_ms })
}

/// Wartezeit vor Versuch `n` (0-basiert): Basis · 2ⁿ plus Jitter.
pub fn backoff(base: Duration, n: u32) -> Duration {
    base * 2u32.saturating_pow(n.min(8)) + jitter(base.as_millis() as u64)
}

fn retryable(e: &FeedError) -> bool {
    matches!(e, FeedError::Network(_) | FeedError::Throttled { .. })
}

async fn once(req: RequestBuilder, lim: Limits) -> Result<Fetched, FeedError> {
    use crate::cve::runs::{report_bytes, report_phase, report_request, Phase};
    report_phase(Phase::Connect);
    let started = std::time::Instant::now();
    let mut resp = match req.timeout(lim.timeout).send().await {
        Ok(r) => r,
        Err(e) => {
            report_request(0, 0, started);
            return Err(FeedError::Network(e.without_url().to_string()));
        }
    };
    let status = resp.status();
    if status == StatusCode::NOT_MODIFIED {
        report_request(304, 0, started);
        return Ok(Fetched {
            status: 304,
            headers: resp.headers().clone(),
            body: Vec::new(),
        });
    }
    if !status.is_success() {
        let code = status.as_u16();
        report_request(code, 0, started);
        if code == 429 || code >= 500 {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parse_retry_after(v, chrono::Utc::now(), lim.retry_after_cap));
            return Err(FeedError::Throttled {
                status: code,
                retry_after,
            });
        }
        return Err(FeedError::Http(code));
    }
    if resp.content_length().is_some_and(|n| n > lim.max_bytes) {
        return Err(FeedError::TooLarge(lim.max_bytes));
    }
    let headers = resp.headers().clone();
    report_phase(Phase::Download);
    let mut body = Vec::new();
    let mut got: u64 = 0;
    // Chunkweise lesen und hart begrenzen (auch nach dem Entpacken von gzip).
    loop {
        let chunk = match resp.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                report_request(0, got, started);
                return Err(FeedError::Network(e.without_url().to_string()));
            }
        };
        if body.len() as u64 + chunk.len() as u64 > lim.max_bytes {
            report_request(status.as_u16(), got, started);
            return Err(FeedError::TooLarge(lim.max_bytes));
        }
        got += chunk.len() as u64;
        report_bytes(chunk.len() as u64);
        // reqwest entpackt gzip selbst: gezählt wird, was der Parser sieht; die Übertragungsmenge ist hier nicht messbar.
        crate::cve::runs::report_unpacked(chunk.len() as u64);
        crate::cve::runs::report_wire_unknown();
        body.extend_from_slice(&chunk);
    }
    report_request(status.as_u16(), got, started);
    // Ab hier wird ausgewertet, bis der Adapter seine Records liefert.
    report_phase(Phase::Parse);
    Ok(Fetched {
        status: status.as_u16(),
        headers,
        body,
    })
}

/// Führt die Anfrage mit Retry (Backoff + Jitter) bei Netzwerkfehlern, 429 und 5xx aus.
pub async fn execute(make: impl Fn() -> RequestBuilder, lim: Limits) -> Result<Fetched, FeedError> {
    let mut last = FeedError::Network("kein Versuch".into());
    for attempt in 0..lim.attempts.max(1) {
        if attempt > 0 {
            // Die Gegenseite bestimmt die Pause, wenn sie eine nennt; sonst exponentiell mit Jitter. Beides gedeckelt.
            let wait = match &last {
                FeedError::Throttled {
                    retry_after: Some(d),
                    ..
                } => *d,
                _ => backoff(lim.base_delay, attempt - 1),
            };
            crate::cve::runs::report_retry();
            crate::cve::runs::wait(wait.min(lim.retry_after_cap)).await;
        }
        match once(make(), lim).await {
            Ok(f) => return Ok(f),
            Err(e) if retryable(&e) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

pub async fn get(
    client: &Client,
    url: &str,
    extra: &[(&str, &str)],
    lim: Limits,
) -> Result<Fetched, FeedError> {
    execute(
        || {
            let mut r = client.get(url);
            for (k, v) in extra {
                if let Ok(v) = HeaderValue::from_str(v) {
                    r = r.header(*k, v);
                }
            }
            r
        },
        lim,
    )
    .await
}

pub async fn post_json(
    client: &Client,
    url: &str,
    body: &serde_json::Value,
    lim: Limits,
) -> Result<Fetched, FeedError> {
    execute(|| client.post(url).json(body), lim).await
}

pub fn header_str(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles() {
        let base = Duration::from_millis(100);
        assert!(backoff(base, 0) >= Duration::from_millis(100));
        assert!(backoff(base, 3) >= Duration::from_millis(800));
        assert!(backoff(base, 30) < Duration::from_secs(60));
    }

    #[test]
    fn retry_classification() {
        assert!(retryable(&FeedError::Network("x".into())));
        assert!(!retryable(&FeedError::Http(404)));
        assert!(retryable(&FeedError::Throttled {
            status: 503,
            retry_after: None
        }));
        assert!(!retryable(&FeedError::TooLarge(1)));
    }

    #[test]
    fn retry_after_seconds_date_garbage_and_cap() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-06T17:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cap = RETRY_AFTER_CAP;
        assert_eq!(
            parse_retry_after("120", now, cap),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after(" 7 ", now, cap),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            parse_retry_after("Fri, 06 Nov 2026 17:05:00 GMT", now, cap),
            Some(Duration::from_secs(300))
        );
        // Datum in der Vergangenheit: sofort wieder erlaubt.
        assert_eq!(
            parse_retry_after("Fri, 06 Nov 2026 16:00:00 GMT", now, cap),
            Some(Duration::ZERO)
        );
        // Deckel bei 15 Minuten, auch bei absurden Werten.
        assert_eq!(parse_retry_after("86400", now, cap), Some(cap));
        assert_eq!(
            parse_retry_after("Sat, 07 Nov 2026 17:00:00 GMT", now, cap),
            Some(cap)
        );
        assert_eq!(parse_retry_after("bald", now, cap), None);
        assert_eq!(parse_retry_after("", now, cap), None);
        assert_eq!(parse_retry_after("-5", now, cap), None);
    }
}
