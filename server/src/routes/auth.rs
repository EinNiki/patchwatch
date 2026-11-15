use crate::audit::{self, Outcome};
use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, ClientIp, PendingAdmin, PendingCsrfAdmin, SelfAdmin, SelfCsrfAdmin};
use crate::security;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

#[derive(Deserialize)]
pub struct Login {
    username: String,
    password: String,
}

pub async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: axum::http::HeaderMap,
    Json(body): Json<Login>,
) -> ApiResult<Response> {
    if body.username.len() > 64 || body.password.len() > 256 || body.username.is_empty() {
        return Err(ApiError::BadRequest("ungültige Eingabe".into()));
    }
    // Zwei Limits: je IP und je Benutzername (gegen verteilte Versuche).
    let window = Duration::from_secs(600);
    for key in [
        format!("login-ip:{ip}"),
        format!("login-user:{}", body.username.to_lowercase()),
    ] {
        st.limiter
            .check(&key, 10, window)
            .map_err(|w| ApiError::TooManyRequests {
                retry_after_secs: w.as_secs().max(1),
            })?;
    }

    // Nach dem Rate-Limit: auch Versuche mit NUL werden gezählt. Gleiche Antwort für jeden Namen (verrät kein Konto).
    if super::has_nul(&body.username) {
        return Err(ApiError::BadRequest("ungültige Eingabe".into()));
    }
    // Nur aktive lokale Konten mit Passwort können sich so anmelden; gesperrte, ausstehende, gelöschte und OIDC-Konten
    // verhalten sich wie ein unbekannter Name (gleiche Antwort, gleiche Rechenzeit durch den Dummy-Hash). Wer die
    // Anmeldung per Passwort für sich ausgeschaltet hat (nur Passkey), zählt hier ebenfalls als unbekannt.
    let user: Option<(i64, String, bool)> = sqlx::query_as(
        "SELECT id, password_hash, must_change_password FROM admin_users \
         WHERE username = $1 AND status = 'active' AND auth_kind = 'local' AND deleted_at IS NULL AND password_hash IS NOT NULL \
           AND NOT password_login_disabled",
    )
    .bind(&body.username)
    .fetch_optional(&st.pool)
    .await?;
    let (admin_id, hash) = match &user {
        Some((id, h, _)) => (Some(*id), h.clone()),
        None => (None, security::dummy_hash().to_owned()),
    };
    let password = body.password.clone();
    let ok = tokio::task::spawn_blocking(move || security::verify_password(&hash, &password))
        .await
        .map_err(anyhow::Error::from)?;
    let mut admin_id = admin_id.filter(|_| ok);
    // Kein lokaler Treffer: LDAP versuchen (falls eingerichtet). Ein lokales Konto mit diesem Namen hat immer Vorrang.
    let mut via_ldap = false;
    if admin_id.is_none() {
        admin_id = super::ldap::try_login(&st, &body.username, &body.password, &ip).await?;
        via_ldap = admin_id.is_some();
    }
    let Some(admin_id) = admin_id else {
        audit::record(
            &st.pool,
            None,
            &body.username,
            "login",
            None,
            Outcome::Failed,
            &ip,
        )
        .await;
        return Err(ApiError::Unauthorized);
    };
    let method = if via_ldap { "ldap" } else { "password" };
    // Zwei-Faktor aktiv: noch keine Sitzung, erst der zweite Schritt (Code) legt sie an.
    if super::mfa::enabled(&st, admin_id).await? {
        let token = super::mfa::start_pending(admin_id, method)?;
        return Ok(Json(json!({ "mfa_required": true, "mfa_token": token })).into_response());
    }
    super::mfa::finish_login(&st, admin_id, &ip, &headers, method).await
}

pub async fn logout(
    State(st): State<AppState>,
    PendingCsrfAdmin(admin): PendingCsrfAdmin,
) -> ApiResult<Response> {
    sqlx::query("DELETE FROM sessions WHERE id_hash = $1")
        .bind(&admin.session_hash)
        .execute(&st.pool)
        .await?;
    let cookie = security::session_cookie("", 0, st.cfg.cookie_secure);
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(anyhow::Error::from)?,
    );
    Ok(resp)
}

#[derive(Deserialize)]
pub struct ChangePassword {
    current_password: String,
    new_password: String,
}

/// Ändert das eigene Passwort. Alle anderen Sessions des Benutzers werden beendet.
pub async fn change_password(
    State(st): State<AppState>,
    PendingCsrfAdmin(admin): PendingCsrfAdmin,
    ClientIp(ip): ClientIp,
    Json(body): Json<ChangePassword>,
) -> ApiResult<StatusCode> {
    st.limiter
        .check(
            &format!("pwchange:{}", admin.username.to_lowercase()),
            5,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    if body.current_password.len() > 256 || body.new_password.len() > 256 {
        return Err(ApiError::BadRequest("ungültige Eingabe".into()));
    }
    if body.new_password.chars().count() < crate::admin::MIN_PASSWORD_CHARS {
        return Err(ApiError::BadRequest(
            "Neues Passwort: mindestens 12 Zeichen".into(),
        ));
    }
    // Bekannte Standardpasswörter sind nie erlaubt (auch nicht als neues Passwort).
    if crate::admin::KNOWN_DEFAULT_PASSWORDS.contains(&body.new_password.as_str()) {
        return Err(ApiError::BadRequest(
            "Neues Passwort: dieser Wert ist ein bekanntes Standardpasswort".into(),
        ));
    }
    if body.new_password == body.current_password {
        return Err(ApiError::BadRequest(
            "Neues Passwort muss sich vom aktuellen unterscheiden".into(),
        ));
    }
    let (id, hash): (i64, Option<String>) =
        sqlx::query_as("SELECT id, password_hash FROM admin_users WHERE id = $1")
            .bind(admin.id)
            .fetch_one(&st.pool)
            .await?;
    let Some(hash) = hash else {
        return Err(ApiError::Forbidden(
            "Dieses Konto hat kein Passwort (Anmeldung über OIDC)",
        ));
    };
    let current = body.current_password;
    let ok = tokio::task::spawn_blocking(move || security::verify_password(&hash, &current))
        .await
        .map_err(anyhow::Error::from)?;
    if !ok {
        return Err(ApiError::Forbidden("Aktuelles Passwort ist falsch"));
    }
    let new = body.new_password;
    let new_hash = tokio::task::spawn_blocking(move || security::hash_password(&new))
        .await
        .map_err(anyhow::Error::from)??;
    let mut tx = st.pool.begin().await?;
    sqlx::query(
        "UPDATE admin_users SET password_hash = $2, must_change_password = false WHERE id = $1",
    )
    .bind(id)
    .bind(new_hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1 AND id_hash <> $2")
        .bind(id)
        .bind(&admin.session_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::record(
        &st.pool,
        Some(id),
        &admin.username,
        "password.changed",
        Some(&admin.username),
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn me(
    State(st): State<AppState>,
    PendingAdmin(admin): PendingAdmin,
) -> ApiResult<Json<serde_json::Value>> {
    // Zeitstempel des Profilbilds (Sekunden) dient der Oberfläche als Cache-Schlüssel; `null` = kein eigenes Bild.
    let avatar: Option<i64> = sqlx::query_scalar(
        "SELECT extract(epoch FROM avatar_updated_at)::bigint FROM admin_users WHERE id = $1 AND avatar IS NOT NULL",
    )
    .bind(admin.id)
    .fetch_optional(&st.pool)
    .await?
    .flatten();
    let display: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM admin_users WHERE id = $1")
            .bind(admin.id)
            .fetch_optional(&st.pool)
            .await?;
    Ok(Json(json!({
        "username": admin.username,
        "display_name": display,
        "role": admin.role.key(),
        "role_title": admin.role.title(),
        "permissions": admin.permissions.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "auth_kind": admin.auth_kind,
        "csrf_token": admin.csrf_token,
        "must_change_password": admin.must_change_password,
        "avatar": avatar,
        "totp_enabled": super::mfa::enabled(&st, admin.id).await?,
    })))
}

/// Antwort mit festen Schutz-Headern: das Bild wird nie als Teil einer Seite eingebettet oder umgedeutet.
fn avatar_response(kind: &'static str, data: Vec<u8>) -> Response {
    let mut r = (StatusCode::OK, data).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=300"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline; filename=\"avatar\""),
    );
    h.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    r
}

/// Eigenes Profilbild (nur für angemeldete Admins; 404, wenn keines gesetzt ist).
pub async fn avatar_get(
    State(st): State<AppState>,
    SelfAdmin(Admin { username, .. }): SelfAdmin,
) -> ApiResult<Response> {
    let row: Option<(Option<Vec<u8>>, Option<String>)> =
        sqlx::query_as("SELECT avatar, avatar_type FROM admin_users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&st.pool)
            .await?;
    match row {
        Some((Some(data), Some(kind))) => {
            // Der Typ kommt aus der Datenbank, wird aber nur aus der festen Liste ausgeliefert.
            let kind = if kind == "image/webp" {
                "image/webp"
            } else {
                "image/png"
            };
            Ok(avatar_response(kind, data))
        }
        _ => Err(ApiError::NotFound),
    }
}

/// Setzt das Profilbild. Erwartet das im Browser neu kodierte Bild (PNG oder WebP, 128×128, höchstens 64 KB) als Rohdaten.
pub async fn avatar_put(
    State(st): State<AppState>,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    st.limiter
        .check(
            &format!("avatar:{}", admin.username.to_lowercase()),
            10,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let kind = crate::avatar::validate(&body).map_err(|m| ApiError::BadRequest(m.into()))?;
    // Der angegebene Typ muss zum Inhalt passen (kein „image/png“ über WebP-Daten und umgekehrt).
    let declared = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        });
    if declared.as_deref() != Some(kind) {
        return Err(ApiError::BadRequest(
            "Dateityp und Inhalt passen nicht zusammen".into(),
        ));
    }
    sqlx::query("UPDATE admin_users SET avatar = $2, avatar_type = $3, avatar_updated_at = now() WHERE username = $1")
        .bind(&admin.username)
        .bind(body.as_ref())
        .bind(kind)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Entfernt das Profilbild (danach gilt wieder der Kreis mit Initialen).
pub async fn avatar_delete(
    State(st): State<AppState>,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
) -> ApiResult<StatusCode> {
    sqlx::query("UPDATE admin_users SET avatar = NULL, avatar_type = NULL, avatar_updated_at = NULL WHERE username = $1")
        .bind(&admin.username)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ProfileBody {
    display_name: String,
}

/// Eigenen Anzeigenamen ändern (z. B. bei OIDC, wo der Anbieter den Namen vorgibt). Nur das eigene Konto; der Anmeldename bleibt.
pub async fn profile_put(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
    Json(body): Json<ProfileBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let name = super::users::check_name(&body.display_name)?;
    let res = sqlx::query("UPDATE admin_users SET display_name = $2 WHERE id = $1")
        .bind(admin.id)
        .bind(&name)
        .execute(&st.pool)
        .await;
    match res {
        Ok(_) => {}
        // Eindeutiger Index auf lower(display_name): der Name wird schon von einem anderen Konto verwendet.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::Conflict(
                "Dieser Anzeigename ist schon vergeben".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    }
    audit::record(
        &st.pool,
        Some(admin.id),
        &admin.username,
        "profile.updated",
        Some(&admin.username),
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(Json(json!({ "display_name": name })))
}

/// Gültigkeit einer Anmeldung in Stunden: Wert aus den Einstellungen (UI), sonst die Konfiguration.
pub async fn session_ttl_hours(st: &AppState) -> i64 {
    sqlx::query_scalar::<_, serde_json::Value>("SELECT value FROM settings WHERE key = $1")
        .bind(SESSION_TTL_KEY)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.as_i64())
        .filter(|h| SESSION_TTL_RANGE.contains(h))
        .unwrap_or(st.cfg.session_ttl_hours)
}

pub const SESSION_TTL_KEY: &str = "session_ttl_hours";
/// 1 Stunde bis 90 Tage.
pub const SESSION_TTL_RANGE: std::ops::RangeInclusive<i64> = 1..=2160;

/// Kurzer, bereinigter Gerätetext aus dem User-Agent (höchstens 200 Zeichen, keine Steuerzeichen).
pub fn clean_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    let v = headers.get(header::USER_AGENT)?.to_str().ok()?;
    let v: String = v.chars().filter(|c| !c.is_control()).take(200).collect();
    (!v.is_empty()).then_some(v)
}

/// Neue Sitzung für ein Konto anlegen (nie eine vorhandene ID wiederverwenden). Gibt (Wert für `Set-Cookie`, CSRF-Token) zurück.
/// `method`: wie angemeldet wurde (password, password+totp, passkey, oidc, ldap), nur zur Anzeige.
pub async fn create_session(
    st: &AppState,
    admin_id: i64,
    ip: &str,
    agent: Option<&str>,
    method: &str,
) -> ApiResult<(String, String)> {
    let session_id = security::new_session_id();
    let csrf = security::new_csrf_token();
    let ttl = session_ttl_hours(st).await * 3600;
    sqlx::query(
        "INSERT INTO sessions (id_hash, admin_id, csrf_token, expires_at, ip, user_agent, method) \
         VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5, $6, $7)",
    )
    .bind(security::sha256(&session_id))
    .bind(admin_id)
    .bind(&csrf)
    .bind(ttl as f64)
    .bind(ip)
    .bind(agent)
    .bind(method)
    .execute(&st.pool)
    .await?;
    Ok((
        security::session_cookie(&session_id, ttl, st.cfg.cookie_secure),
        csrf,
    ))
}
