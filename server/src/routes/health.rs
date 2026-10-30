use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn readyz(State(st): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&st.pool).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
