use crate::config::Config;
use crate::ratelimit::RateLimiter;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub cfg: Arc<Config>,
    pub limiter: Arc<RateLimiter>,
    pub http: reqwest::Client,
    /// Verhindert parallele Feed-Läufe (Scheduler und manueller Abruf).
    pub refresh_lock: Arc<tokio::sync::Mutex<()>>,
    /// Live-Ereignisse (JSON-Text) aus Postgres NOTIFY an alle WebSocket-Verbindungen.
    pub live: tokio::sync::broadcast::Sender<Arc<str>>,
    /// Begrenzt gleichzeitige WebSocket-Verbindungen.
    pub live_slots: Arc<tokio::sync::Semaphore>,
    /// Offene Check-in-Long-Polls: höchstens ein wartender Aufruf je Host (neuer ersetzt alten) ...
    pub checkin_waiters: Arc<std::sync::Mutex<std::collections::HashMap<i64, u64>>>,
    /// ... und höchstens `MAX_OPEN_CHECKINS` gleichzeitig; weitere Aufrufe werden sofort beantwortet.
    pub checkin_slots: Arc<tokio::sync::Semaphore>,
}

/// Globale Obergrenze offener Check-in-Long-Polls.
pub const MAX_OPEN_CHECKINS: usize = 256;

impl AppState {
    pub fn new(pool: PgPool, cfg: Config) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(concat!("patchwatch-server/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            pool,
            cfg: Arc::new(cfg),
            limiter: Arc::new(RateLimiter::default()),
            http,
            refresh_lock: Arc::default(),
            live: tokio::sync::broadcast::channel(256).0,
            live_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            checkin_waiters: Arc::default(),
            checkin_slots: Arc::new(tokio::sync::Semaphore::new(MAX_OPEN_CHECKINS)),
        })
    }
}
