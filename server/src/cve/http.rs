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
    matches!(e, FeedError::Network(_)) || matches!(e, FeedError::Http(c) if *c == 429 || *c >= 500)
}

async fn once(req: RequestBuilder, lim: Limits) -> Result<Fetched, FeedError> {
    let mut resp = req
        .timeout(lim.timeout)
        .send()
        .await
        .map_err(|e| FeedError::Network(e.without_url().to_string()))?;
    let status = resp.status();
    if status == StatusCode::NOT_MODIFIED {
        return Ok(Fetched {
            status: 304,
            headers: resp.headers().clone(),
            body: Vec::new(),
        });
    }
    if !status.is_success() {
        return Err(FeedError::Http(status.as_u16()));
    }
    if resp.content_length().is_some_and(|n| n > lim.max_bytes) {
        return Err(FeedError::TooLarge(lim.max_bytes));
    }
    let headers = resp.headers().clone();
    let mut body = Vec::new();
    // Chunkweise lesen und hart begrenzen (auch nach dem Entpacken von gzip).
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FeedError::Network(e.without_url().to_string()))?
    {
        if body.len() as u64 + chunk.len() as u64 > lim.max_bytes {
            return Err(FeedError::TooLarge(lim.max_bytes));
        }
        body.extend_from_slice(&chunk);
    }
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
            tokio::time::sleep(backoff(lim.base_delay, attempt - 1)).await;
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
        assert!(retryable(&FeedError::Http(503)));
        assert!(retryable(&FeedError::Http(429)));
        assert!(!retryable(&FeedError::Http(404)));
        assert!(!retryable(&FeedError::TooLarge(1)));
    }
}
