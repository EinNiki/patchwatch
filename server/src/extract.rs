use crate::error::ApiError;
use crate::security::{self, SESSION_COOKIE};
use crate::state::AppState;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method};
use std::net::SocketAddr;

/// Angemeldeter Admin (gültige Session).
pub struct Admin {
    pub username: String,
    pub csrf_token: String,
    pub session_hash: Vec<u8>,
    /// Bekanntes oder erzeugtes Start-Passwort: nur Passwortwechsel und Abmelden erlaubt.
    pub must_change_password: bool,
}

/// Wie [`Admin`], aber auch für Konten, die ihr Passwort noch ändern müssen. Nur für `me`, Abmelden und den
/// Passwortwechsel selbst; alle anderen Endpunkte nehmen `Admin` und lehnen solche Konten ab.
pub struct PendingAdmin(pub Admin);

/// [`PendingAdmin`] mit CSRF-Prüfung.
pub struct PendingCsrfAdmin(pub Admin);

async fn load_admin(parts: &Parts, state: &AppState) -> Result<Admin, ApiError> {
    {
        let cookie = parts
            .headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|c| security::cookie_value(c, SESSION_COOKIE))
            .ok_or(ApiError::Unauthorized)?;
        let hash = security::sha256(cookie);
        let row: Option<(String, String, bool)> = sqlx::query_as(
            "SELECT a.username, s.csrf_token, a.must_change_password FROM sessions s JOIN admin_users a ON a.id = s.admin_id \
             WHERE s.id_hash = $1 AND s.expires_at > now()",
        )
        .bind(&hash)
        .fetch_optional(&state.pool)
        .await?;
        let (username, csrf_token, must_change_password) = row.ok_or(ApiError::Unauthorized)?;
        Ok(Admin {
            username,
            csrf_token,
            session_hash: hash,
            must_change_password,
        })
    }
}

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let admin = load_admin(parts, state).await?;
        if admin.must_change_password {
            return Err(ApiError::PasswordChangeRequired);
        }
        Ok(admin)
    }
}

impl FromRequestParts<AppState> for PendingAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        Ok(PendingAdmin(load_admin(parts, state).await?))
    }
}

fn check_csrf(parts: &Parts, admin: &Admin) -> Result<(), ApiError> {
    if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
        let sent = parts
            .headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !security::ct_eq(sent, &admin.csrf_token) {
            return Err(ApiError::Forbidden("CSRF-Token fehlt oder ist ungültig"));
        }
    }
    Ok(())
}

impl FromRequestParts<AppState> for PendingCsrfAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let admin = load_admin(parts, state).await?;
        check_csrf(parts, &admin)?;
        Ok(PendingCsrfAdmin(admin))
    }
}

/// Admin mit CSRF-Prüfung; für alle verändernden Endpunkte.
pub struct CsrfAdmin(pub Admin);

impl FromRequestParts<AppState> for CsrfAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let admin = Admin::from_request_parts(parts, state).await?;
        check_csrf(parts, &admin)?;
        Ok(CsrfAdmin(admin))
    }
}

/// Client-IP für Rate-Limits; hinter Proxy der letzte `X-Forwarded-For`-Eintrag.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return ip.to_owned();
        }
    }
    peer.map_or_else(|| "unknown".to_owned(), |p| p.ip().to_string())
}

pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        Ok(ClientIp(client_ip(
            &parts.headers,
            peer,
            state.cfg.trust_proxy,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_header_only_when_trusted() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 10.0.0.7".parse().unwrap());
        let peer: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        assert_eq!(client_ip(&h, Some(peer), false), "192.0.2.1");
        assert_eq!(client_ip(&h, Some(peer), true), "10.0.0.7");
        assert_eq!(client_ip(&HeaderMap::new(), None, true), "unknown");
    }
}
