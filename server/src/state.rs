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
}

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
        })
    }
}
