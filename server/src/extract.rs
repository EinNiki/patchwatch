use crate::authz::{Perm, Permission, Role};
use crate::error::ApiError;
use crate::security::{self, SESSION_COOKIE};
use crate::state::AppState;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method};
use std::marker::PhantomData;
use std::net::SocketAddr;

/// Angemeldeter, aktiver Benutzer (gültige Session). Rolle und Status werden bei jeder Anfrage aus der Datenbank gelesen.
pub struct Admin {
    pub id: i64,
    pub username: String,
    pub role: Role,
    /// Wirksame Rechte (Vorlage der Rolle oder eigene Auswahl), bei jeder Anfrage aus der Datenbank gelesen.
    pub permissions: Vec<Permission>,
    pub csrf_token: String,
    pub session_hash: Vec<u8>,
    /// Beginn der Sitzung (für "frische Anmeldung" bei OIDC-Konten).
    pub session_created: chrono::DateTime<chrono::Utc>,
    pub auth_kind: String,
    /// Bekanntes oder erzeugtes Start-Passwort: nur Passwortwechsel und Abmelden erlaubt.
    pub must_change_password: bool,
}

impl Admin {
    pub fn can(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }
}

/// Wie [`Admin`], aber auch für Konten, die ihr Passwort noch ändern müssen. Nur für `me`, Abmelden und den
/// Passwortwechsel selbst; alle anderen Endpunkte nehmen `Authed<P>` und lehnen solche Konten ab.
pub struct PendingAdmin(pub Admin);

/// [`PendingAdmin`] mit CSRF-Prüfung.
pub struct PendingCsrfAdmin(pub Admin);

/// Angemeldet mit dem Recht `P` (Lesen). Der einzige Weg zu Datenrouten: ohne Recht 403, ohne Anmeldung 401.
pub struct Authed<P: Perm>(pub Admin, pub PhantomData<P>);

/// Wie [`Authed`] mit CSRF-Prüfung für verändernde Aufrufe.
pub struct CsrfAuthed<P: Perm>(pub Admin, pub PhantomData<P>);

/// Angemeldet, nur das eigene Konto betreffend (Profilbild): kein weiteres Recht nötig, aber aktiv und Passwort geändert.
pub struct SelfAdmin(pub Admin);

/// [`SelfAdmin`] mit CSRF-Prüfung.
pub struct SelfCsrfAdmin(pub Admin);

/// Spalten der Sitzungsabfrage (siehe `load_admin`).
type SessionRow = (
    i64,
    String,
    String,
    String,
    chrono::DateTime<chrono::Utc>,
    String,
    bool,
    Option<Vec<String>>,
);

async fn load_admin(parts: &Parts, state: &AppState) -> Result<Admin, ApiError> {
    let cookie = parts
        .headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| security::cookie_value(c, SESSION_COOKIE))
        .ok_or(ApiError::Unauthorized)?;
    let hash = security::sha256(cookie);
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT a.id, a.username, a.role, s.csrf_token, s.created_at, a.auth_kind, a.must_change_password, a.permissions \
         FROM sessions s JOIN admin_users a ON a.id = s.admin_id \
         WHERE s.id_hash = $1 AND s.expires_at > now() AND a.status = 'active' AND a.deleted_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(&state.pool)
    .await?;
    let (id, username, role, csrf_token, session_created, auth_kind, must_change_password, stored) =
        row.ok_or(ApiError::Unauthorized)?;
    // Unbekannte Rolle (kann die Prüfregel der Datenbank nicht liefern) gilt als nicht angemeldet.
    let role = Role::parse(&role).ok_or(ApiError::Unauthorized)?;
    let permissions = crate::authz::effective(role, stored.as_deref());
    Ok(Admin {
        id,
        username,
        role,
        permissions,
        csrf_token,
        session_hash: hash,
        session_created,
        auth_kind,
        must_change_password,
    })
}

async fn active(parts: &Parts, state: &AppState) -> Result<Admin, ApiError> {
    let admin = load_admin(parts, state).await?;
    if admin.must_change_password {
        return Err(ApiError::PasswordChangeRequired);
    }
    Ok(admin)
}

fn require(admin: &Admin, p: Permission) -> Result<(), ApiError> {
    if admin.can(p) {
        Ok(())
    } else {
        Err(ApiError::Forbidden("Dafür fehlt dir die Berechtigung"))
    }
}

impl<P: Perm> FromRequestParts<AppState> for Authed<P> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let admin = active(parts, state).await?;
        require(&admin, P::PERMISSION)?;
        Ok(Self(admin, PhantomData))
    }
}

impl<P: Perm> FromRequestParts<AppState> for CsrfAuthed<P> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let admin = active(parts, state).await?;
        check_csrf(parts, &admin)?;
        require(&admin, P::PERMISSION)?;
        Ok(Self(admin, PhantomData))
    }
}

impl FromRequestParts<AppState> for SelfAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        Ok(Self(active(parts, state).await?))
    }
}

impl FromRequestParts<AppState> for SelfCsrfAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let admin = active(parts, state).await?;
        check_csrf(parts, &admin)?;
        Ok(Self(admin))
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
