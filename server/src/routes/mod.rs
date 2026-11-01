mod agent;
mod auth;
pub mod cves;
mod feeds;
mod health;
pub mod hosts;
mod live;
mod matrix;
mod notifications;
mod report;
pub mod settings;

use crate::extract::ClientIp;
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::Router;
use std::time::Duration;
use tower_http::trace::TraceLayer;

use crate::error::ApiError;
pub use cves::valid_cve_id;

/// Allgemeines Limit je Client-IP für die ganze API.
async fn api_rate_limit(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    st.limiter
        .check(&format!("api:{ip}"), 600, Duration::from_secs(60))
        .map_err(|wait| ApiError::TooManyRequests {
            retry_after_secs: wait.as_secs().max(1),
        })?;
    Ok(next.run(req).await)
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route(
            "/report",
            post(report::post_report).layer(axum::extract::DefaultBodyLimit::max(report::MAX_BODY)),
        )
        .route("/agent/checkin", post(agent::checkin))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/password", post(auth::change_password))
        .route("/hosts", get(hosts::list).post(hosts::create))
        .route("/hosts/request-report", post(hosts::request_report_all))
        .route("/hosts/{id}", get(hosts::detail).delete(hosts::remove))
        .route("/hosts/{id}/request-report", post(hosts::request_report))
        .route("/hosts/{id}/rotate-token", post(hosts::rotate_token))
        .route("/hosts/{id}/history", get(hosts::history))
        .route("/hosts/{id}/cves", get(hosts::cves))
        .route("/hosts/{id}/updates", get(hosts::updates))
        .route(
            "/hosts/{id}/cves/{cve}/review",
            put(hosts::review).delete(hosts::unreview),
        )
        .route("/cves", get(cves::list))
        .route("/cves/{id}", get(cves::detail))
        .route("/watchlist", get(cves::watchlist))
        .route("/watchlist/{id}", put(cves::watch).delete(cves::unwatch))
        .route("/matrix", get(matrix::matrix))
        .route("/notifications", get(notifications::list))
        .route(
            "/notifications/{kind}",
            get(notifications::get_one).put(notifications::put),
        )
        .route("/notifications/{kind}/test", post(notifications::test))
        .route("/settings", get(settings::get).put(settings::put))
        .route("/live", get(live::live))
        .route("/feeds", get(feeds::list).post(feeds::create))
        .route("/feeds/refresh", post(feeds::refresh))
        .route(
            "/feeds/{name}",
            axum::routing::put(feeds::update).delete(feeds::delete),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_rate_limit,
        ));

    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .nest("/api/v1", api)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
