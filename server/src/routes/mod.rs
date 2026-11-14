mod agent;
mod auth;
pub mod cves;
mod feeds;
mod health;
pub mod hosts;
mod live;
mod matrix;
mod notifications;
mod oidc;
mod report;
pub mod settings;
mod users;

use crate::extract::ClientIp;
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::Router;
use std::time::Duration;
use tower_http::catch_panic::CatchPanicLayer;
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
        .route("/auth/providers", get(oidc::providers))
        .route("/auth/oidc/login", get(oidc::login))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/profile", axum::routing::put(auth::profile_put))
        .route(
            "/auth/avatar",
            get(auth::avatar_get)
                .put(auth::avatar_put)
                .delete(auth::avatar_delete)
                .layer(axum::extract::DefaultBodyLimit::max(
                    crate::avatar::MAX_BYTES + 1024,
                )),
        )
        .route("/hosts", get(hosts::list).post(hosts::create))
        .route("/hosts/request-report", post(hosts::request_report_all))
        .route("/hosts/{id}", get(hosts::detail).delete(hosts::remove))
        .route("/hosts/{id}/request-report", post(hosts::request_report))
        .route("/hosts/{id}/rotate-token", post(hosts::rotate_token))
        .route("/hosts/{id}/history", get(hosts::history))
        .route("/hosts/{id}/cves", get(hosts::cves))
        .route("/hosts/{id}/cves/groups", get(hosts::cve_groups))
        .route("/hosts/{id}/updates", get(hosts::updates))
        .route(
            "/hosts/{id}/cves/{cve}/review",
            put(hosts::review).delete(hosts::unreview),
        )
        .route("/cves", get(cves::list))
        .route("/cves/scope-count", get(cves::scope_count))
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
        .route(
            "/settings/oidc",
            get(oidc::settings_get).put(oidc::settings_put),
        )
        .route("/settings/oidc/test", post(oidc::settings_test))
        .route("/live", get(live::live))
        .route("/roles", get(users::roles))
        .route("/users", get(users::list).post(users::create))
        .route(
            "/users/{id}",
            axum::routing::patch(users::update).delete(users::remove),
        )
        .route("/users/{id}/lock", post(users::lock))
        .route("/users/{id}/unlock", post(users::unlock))
        .route("/users/{id}/approve", post(users::approve))
        .route("/users/{id}/reset-password", post(users::reset_password))
        .route("/audit", get(users::audit_list))
        .route("/feeds", get(feeds::list).post(feeds::create))
        .route("/feeds/refresh", post(feeds::refresh))
        .route("/feeds/runs", get(feeds::runs_list))
        .route("/feeds/{name}/run", post(feeds::run_source))
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
        .layer(middleware::from_fn(reject_nul_in_uri))
        .layer(TraceLayer::new_for_http())
        // Äußerste Schicht: ein Panic in irgendeinem Handler oder einer Middleware wird zu einem 500.
        .layer(CatchPanicLayer::custom(panic_response))
        .with_state(state)
}

/// Antwort auf einen abgefangenen Panic. Weder Meldung noch Eingabe werden ausgegeben oder protokolliert (die
/// Panic-Meldung kann Nutzereingaben enthalten); der Ort steht im Panic-Hook (`install_panic_hook`).
pub fn panic_response(_payload: Box<dyn std::any::Any + Send + 'static>) -> Response {
    use axum::response::IntoResponse;
    ApiError::Internal(anyhow::anyhow!("Panic abgefangen")).into_response()
}

/// Panic-Hook ohne Nutzereingaben: protokolliert nur Datei und Zeile, nie die Panic-Meldung.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map_or_else(
            || "unbekannt".to_owned(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        tracing::error!(location = %loc, "Panic in einer Anfrage abgefangen oder aufgetreten");
    }));
}

/// Enthält ein Text aus dem JSON-Body ein NUL (`\u0000`)? Postgres kann es weder in `text` noch in `jsonb` speichern
/// oder vergleichen (sonst 500); Textfelder aus dem Body werden damit vor der Datenbank mit 400 abgelehnt.
pub(crate) fn has_nul(s: &str) -> bool {
    s.contains('\0')
}

/// Pfad oder Query mit kodiertem NUL (`%00`) ist immer ungültig: Postgres-Text kann kein NUL enthalten, die Abfrage
/// würde mit einem Datenbankfehler (500) scheitern. Gilt für alle Routen, auch künftige.
async fn reject_nul_in_uri(req: Request, next: Next) -> Result<Response, ApiError> {
    let has_nul = req
        .uri()
        .path_and_query()
        .is_some_and(|pq| pq.as_str().to_ascii_lowercase().contains("%00"));
    if has_nul {
        return Err(ApiError::BadRequest(
            "ungültige Zeichen in der Adresse".into(),
        ));
    }
    Ok(next.run(req).await)
}
