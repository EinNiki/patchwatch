use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden(&'static str),
    /// Das Konto muss zuerst sein Passwort ändern (bekanntes oder erzeugtes Start-Passwort).
    PasswordChangeRequired,
    NotFound,
    Conflict(String),
    TooManyRequests {
        retry_after_secs: u64,
    },
    Internal(anyhow::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self::Internal(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "nicht angemeldet".to_owned()),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, (*m).to_owned()),
            Self::PasswordChangeRequired => (
                StatusCode::FORBIDDEN,
                "Das Passwort muss zuerst geändert werden".to_owned(),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "nicht gefunden".to_owned()),
            Self::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            Self::TooManyRequests { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "zu viele Anfragen".to_owned(),
            ),
            Self::Internal(e) => {
                // Details nur ins Log, nie an den Client.
                tracing::error!(error = %e, "interner Fehler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "interner Fehler".to_owned(),
                )
            }
        };
        let body = if matches!(self, Self::PasswordChangeRequired) {
            json!({ "error": msg, "code": "password_change_required" })
        } else {
            json!({ "error": msg })
        };
        let mut resp = (status, Json(body)).into_response();
        if let Self::TooManyRequests { retry_after_secs } = self {
            if let Ok(v) = retry_after_secs.to_string().parse() {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}
