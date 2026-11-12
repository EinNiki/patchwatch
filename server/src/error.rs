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

/// Sekunden, nach denen ein Client es bei nicht erreichbarer Datenbank erneut versuchen soll (`Retry-After`).
const DB_RETRY_AFTER_SECS: u64 = 5;

/// Die Datenbank ist (vorübergehend) nicht erreichbar: kein Fehler der Anfrage, sondern des Betriebs. Erkennt
/// Pool-Zeitüberschreitung, geschlossenen Pool, Netz-/E/A-Fehler sowie die SQLSTATE-Klassen 08 (Verbindung) und
/// 57P (Server fährt herunter oder startet gerade).
pub fn is_db_unavailable(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => true,
        sqlx::Error::Database(d) => d
            .code()
            .is_some_and(|c| c.starts_with("08") || c.starts_with("57P")),
        _ => false,
    }
}

/// Wie [`is_db_unavailable`], für beliebig verpackte Fehler (`anyhow` mit Kontext).
fn chain_db_unavailable(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<sqlx::Error>()
            .is_some_and(is_db_unavailable)
    })
}

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
            Self::Internal(e) if chain_db_unavailable(e) => {
                // Betriebszustand, kein Programmfehler: Warnung statt Fehler im Log, Details nie an den Client.
                tracing::warn!(error = %e, "Datenbank nicht erreichbar");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Die Datenbank ist gerade nicht erreichbar. Bitte in einigen Sekunden erneut versuchen."
                        .to_owned(),
                )
            }
            Self::Internal(e) => {
                // Details nur ins Log, nie an den Client.
                tracing::error!(error = %e, "interner Fehler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "interner Fehler".to_owned(),
                )
            }
        };
        let unavailable = status == StatusCode::SERVICE_UNAVAILABLE;
        let body = if matches!(self, Self::PasswordChangeRequired) {
            json!({ "error": msg, "code": "password_change_required" })
        } else if unavailable {
            json!({ "error": msg, "code": "db_unavailable" })
        } else {
            json!({ "error": msg })
        };
        let mut resp = (status, Json(body)).into_response();
        let retry_after = match self {
            Self::TooManyRequests { retry_after_secs } => Some(retry_after_secs),
            _ if unavailable => Some(DB_RETRY_AFTER_SECS),
            _ => None,
        };
        if let Some(secs) = retry_after {
            if let Ok(v) = secs.to_string().parse() {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}
