//! Zwei-Faktor-Anmeldung (TOTP) und Übersicht der eigenen Sitzungen.
//!
//! Ablauf der Anmeldung: Passwort (oder LDAP) richtig und Zwei-Faktor aktiv -> es entsteht noch keine Sitzung, sondern ein
//! kurzlebiger, einmal verwendbarer Zwischenschritt (5 Minuten, höchstens 5 Versuche). Erst der richtige Code (oder ein
//! Wiederherstellungscode) legt die Sitzung an. Passkeys und OIDC gelten selbst als zweiter Faktor bzw. liegen beim Anbieter.
//! Das Geheimnis liegt verschlüsselt in der Datenbank, wenn `PATCHWATCH_SECRET_KEY` gesetzt ist, sonst unverschlüsselt (siehe Hinweis in der UI).
//! Ein Code gilt nur einmal (Zeitschritt wird gemerkt), Wiederherstellungscodes liegen nur als Hash vor.

use crate::audit::{self, Outcome};
use crate::authz;
use crate::error::{ApiError, ApiResult};
use crate::extract::{ClientIp, CsrfAuthed, SelfAdmin, SelfCsrfAdmin};
use crate::security;
use crate::state::AppState;
use crate::totp;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PENDING_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 2_000;
const MAX_ATTEMPTS: u8 = 5;
const SECRET_AAD: &str = "totp-secret";
const RECOVERY_CODES: usize = 10;

struct PendingLogin {
    at: Instant,
    admin_id: i64,
    method: &'static str,
    attempts: u8,
}

static PENDING: LazyLock<Mutex<HashMap<String, PendingLogin>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Ist für das Konto Zwei-Faktor eingeschaltet?
pub async fn enabled(st: &AppState, admin_id: i64) -> ApiResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT totp_enabled FROM admin_users WHERE id = $1")
            .bind(admin_id)
            .fetch_optional(&st.pool)
            .await?
            .unwrap_or(false),
    )
}

/// Zwischenschritt nach richtigem Passwort: gibt das Token für den zweiten Schritt zurück.
pub fn start_pending(admin_id: i64, method: &'static str) -> ApiResult<String> {
    let mut m = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    m.retain(|_, p| now.duration_since(p.at) < PENDING_TTL);
    if m.len() >= MAX_PENDING {
        return Err(ApiError::TooManyRequests {
            retry_after_secs: 30,
        });
    }
    let token = security::new_session_id();
    m.insert(
        token.clone(),
        PendingLogin {
            at: now,
            admin_id,
            method,
            attempts: 0,
        },
    );
    Ok(token)
}

/// Schließt die Anmeldung ab: Zeitstempel, Protokoll, Sitzung und Antwort mit Cookie.
pub async fn finish_login(
    st: &AppState,
    admin_id: i64,
    ip: &str,
    headers: &HeaderMap,
    method: &str,
) -> ApiResult<Response> {
    let (username, must_change): (String, bool) =
        sqlx::query_as("SELECT username, must_change_password FROM admin_users WHERE id = $1")
            .bind(admin_id)
            .fetch_one(&st.pool)
            .await?;
    sqlx::query("UPDATE admin_users SET last_login_at = now() WHERE id = $1")
        .bind(admin_id)
        .execute(&st.pool)
        .await?;
    audit::record(
        &st.pool,
        Some(admin_id),
        &username,
        "login",
        Some(method),
        Outcome::Ok,
        ip,
    )
    .await;
    let (cookie, csrf) = super::auth::create_session(
        st,
        admin_id,
        ip,
        super::auth::clean_agent(headers).as_deref(),
        method,
    )
    .await?;
    let mut resp = Json(json!({
        "username": username,
        "csrf_token": csrf,
        "must_change_password": must_change,
    }))
    .into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(anyhow::Error::from)?,
    );
    Ok(resp)
}

// ---------- Geheimnis und Codes ----------

fn seal(st: &AppState, b32: &str) -> ApiResult<String> {
    match &st.cfg.secret_key {
        Some(k) => {
            let blob = crate::notify::crypto::encrypt(k.bytes(), SECRET_AAD, b32)?;
            Ok(format!("enc:{}", URL_SAFE_NO_PAD.encode(blob)))
        }
        None => Ok(format!("plain:{b32}")),
    }
}

fn open(st: &AppState, stored: &str) -> Option<Vec<u8>> {
    let b32 = if let Some(rest) = stored.strip_prefix("enc:") {
        let key = st.cfg.secret_key.as_ref()?;
        let blob = URL_SAFE_NO_PAD.decode(rest).ok()?;
        crate::notify::crypto::decrypt(key.bytes(), SECRET_AAD, &blob).ok()?
    } else {
        stored.strip_prefix("plain:")?.to_owned()
    };
    totp::base32_decode(&b32)
}

/// Wiederherstellungscode vereinheitlichen (Groß-/Kleinschreibung, Bindestrich und Leerzeichen egal).
fn norm_recovery(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn new_recovery_code() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 10];
    SystemRandom::new().fill(&mut b).expect("Zufallsquelle");
    let s: String = b
        .iter()
        .map(|x| totp::base32_encode(&[*x]).to_ascii_lowercase())
        .map(|s| s.chars().next().unwrap_or('a'))
        .collect();
    format!("{}-{}", &s[..5], &s[5..])
}

enum Used {
    Totp,
    Recovery,
}

/// Prüft Code oder Wiederherstellungscode. Ein Zeitschritt bzw. ein Wiederherstellungscode gilt nur einmal (atomar in der Datenbank).
async fn check_code(st: &AppState, admin_id: i64, input: &str) -> ApiResult<Option<Used>> {
    let row: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT totp_secret, totp_last_step FROM admin_users WHERE id = $1 AND totp_enabled",
    )
    .bind(admin_id)
    .fetch_optional(&st.pool)
    .await?;
    let Some((Some(stored), last)) = row else {
        return Ok(None);
    };
    if input.chars().count() > 32 {
        return Ok(None);
    }
    if let Some(secret) = open(st, &stored) {
        if let Some(step) = totp::verify(&secret, input, now_secs(), last) {
            let n = sqlx::query(
                "UPDATE admin_users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
            )
            .bind(admin_id)
            .bind(step)
            .execute(&st.pool)
            .await?
            .rows_affected();
            if n == 1 {
                return Ok(Some(Used::Totp));
            }
        }
    }
    let norm = norm_recovery(input);
    if norm.len() == 10 {
        let n = sqlx::query(
            "UPDATE totp_recovery_codes SET used_at = now() WHERE admin_id = $1 AND code_hash = $2 AND used_at IS NULL",
        )
        .bind(admin_id)
        .bind(security::sha256(&norm))
        .execute(&st.pool)
        .await?
        .rows_affected();
        if n == 1 {
            return Ok(Some(Used::Recovery));
        }
    }
    Ok(None)
}

// ---------- Anmeldung: zweiter Schritt ----------

#[derive(Deserialize)]
pub struct LoginMfa {
    mfa_token: String,
    code: String,
}

pub async fn login_mfa(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(b): Json<LoginMfa>,
) -> ApiResult<Response> {
    st.limiter
        .check(&format!("mfa-ip:{ip}"), 30, Duration::from_secs(600))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    if b.code.len() > 64 || b.mfa_token.len() > 200 {
        return Err(ApiError::BadRequest("ungültige Eingabe".into()));
    }
    let (admin_id, method) = {
        let m = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        match m.get(&b.mfa_token) {
            Some(p) if Instant::now().duration_since(p.at) < PENDING_TTL => (p.admin_id, p.method),
            _ => return Err(ApiError::Unauthorized),
        }
    };
    st.limiter
        .check(
            &format!("mfa-user:{admin_id}"),
            10,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let used = check_code(&st, admin_id, &b.code).await?;
    let Some(used) = used else {
        {
            let mut m = PENDING.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = m.get_mut(&b.mfa_token) {
                p.attempts += 1;
                if p.attempts >= MAX_ATTEMPTS {
                    m.remove(&b.mfa_token);
                }
            }
        }
        let name: Option<String> =
            sqlx::query_scalar("SELECT username FROM admin_users WHERE id = $1")
                .bind(admin_id)
                .fetch_optional(&st.pool)
                .await?;
        audit::record(
            &st.pool,
            Some(admin_id),
            name.as_deref().unwrap_or("?"),
            "login.mfa",
            None,
            Outcome::Failed,
            &ip,
        )
        .await;
        return Err(ApiError::Unauthorized);
    };
    PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&b.mfa_token);
    let how = match (used, method) {
        (Used::Recovery, _) => "password+recovery",
        (Used::Totp, "ldap") => "ldap+totp",
        (Used::Totp, _) => "password+totp",
    };
    finish_login(&st, admin_id, &ip, &headers, how).await
}

// ---------- eigenes Konto: Zwei-Faktor einrichten ----------

pub async fn status(
    State(st): State<AppState>,
    SelfAdmin(admin): SelfAdmin,
) -> ApiResult<Json<Value>> {
    let on = enabled(&st, admin.id).await?;
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM totp_recovery_codes WHERE admin_id = $1 AND used_at IS NULL",
    )
    .bind(admin.id)
    .fetch_one(&st.pool)
    .await?;
    Ok(Json(json!({
        "enabled": on,
        "recovery_codes_left": if on { left } else { 0 },
        // Ohne PATCHWATCH_SECRET_KEY liegt das Geheimnis unverschlüsselt in der Datenbank.
        "secret_encrypted": st.cfg.secret_key.is_some(),
    })))
}

/// Neues Geheimnis erzeugen (noch nicht aktiv, bis der erste Code bestätigt ist).
pub async fn setup(
    State(st): State<AppState>,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
) -> ApiResult<Json<Value>> {
    st.limiter
        .check(
            &format!("mfa-manage:{}", admin.id),
            20,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    if enabled(&st, admin.id).await? {
        return Err(ApiError::Conflict(
            "Zwei-Faktor ist schon eingeschaltet".into(),
        ));
    }
    let b32 = totp::base32_encode(&totp::new_secret());
    let stored = seal(&st, &b32)?;
    sqlx::query("UPDATE admin_users SET totp_secret = $2, totp_last_step = NULL WHERE id = $1")
        .bind(admin.id)
        .bind(stored)
        .execute(&st.pool)
        .await?;
    Ok(Json(json!({
        "secret": b32,
        "otpauth_uri": totp::otpauth_uri(&b32, &admin.username),
    })))
}

#[derive(Deserialize)]
pub struct CodeBody {
    code: String,
}

/// Erster Code bestätigt die Einrichtung: Zwei-Faktor wird aktiv, die Wiederherstellungscodes werden einmalig angezeigt.
pub async fn enable(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
    Json(b): Json<CodeBody>,
) -> ApiResult<Json<Value>> {
    st.limiter
        .check(
            &format!("mfa-manage:{}", admin.id),
            20,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let row: Option<(Option<String>, bool)> =
        sqlx::query_as("SELECT totp_secret, totp_enabled FROM admin_users WHERE id = $1")
            .bind(admin.id)
            .fetch_optional(&st.pool)
            .await?;
    let Some((Some(stored), false)) = row else {
        return Err(ApiError::Conflict(
            "Erst die Einrichtung starten (oder Zwei-Faktor ist schon an)".into(),
        ));
    };
    let secret = open(&st, &stored)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Zwei-Faktor-Geheimnis nicht lesbar")))?;
    let Some(step) = totp::verify(&secret, &b.code, now_secs(), None) else {
        return Err(ApiError::BadRequest(
            "Der Code stimmt nicht. Prüfe die Uhrzeit des Geräts und versuche es mit dem neuen Code.".into(),
        ));
    };
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
    let mut tx = st.pool.begin().await?;
    sqlx::query("UPDATE admin_users SET totp_enabled = true, totp_last_step = $2 WHERE id = $1")
        .bind(admin.id)
        .bind(step)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM totp_recovery_codes WHERE admin_id = $1")
        .bind(admin.id)
        .execute(&mut *tx)
        .await?;
    for c in &codes {
        sqlx::query("INSERT INTO totp_recovery_codes (admin_id, code_hash) VALUES ($1, $2)")
            .bind(admin.id)
            .bind(security::sha256(&norm_recovery(c)))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit::record(
        &st.pool,
        Some(admin.id),
        &admin.username,
        "mfa.enabled",
        None,
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[derive(Deserialize)]
pub struct DisableBody {
    code: String,
    password: Option<String>,
}

/// Ausschalten: braucht einen gültigen Code (oder Wiederherstellungscode) und bei Konten mit Passwort zusätzlich das Passwort.
pub async fn disable(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
    Json(b): Json<DisableBody>,
) -> ApiResult<StatusCode> {
    st.limiter
        .check(
            &format!("mfa-manage:{}", admin.id),
            20,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM admin_users WHERE id = $1")
            .bind(admin.id)
            .fetch_one(&st.pool)
            .await?;
    if let Some(hash) = hash {
        let pw = b.password.unwrap_or_default();
        if pw.len() > 256 {
            return Err(ApiError::BadRequest("ungültige Eingabe".into()));
        }
        let ok = tokio::task::spawn_blocking(move || security::verify_password(&hash, &pw))
            .await
            .map_err(anyhow::Error::from)?;
        if !ok {
            return Err(ApiError::Forbidden("Passwort ist falsch"));
        }
    }
    if check_code(&st, admin.id, &b.code).await?.is_none() {
        return Err(ApiError::Forbidden("Der Code stimmt nicht"));
    }
    reset(&st, admin.id).await?;
    audit::record(
        &st.pool,
        Some(admin.id),
        &admin.username,
        "mfa.disabled",
        None,
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn reset(st: &AppState, admin_id: i64) -> ApiResult<()> {
    let mut tx = st.pool.begin().await?;
    sqlx::query(
        "UPDATE admin_users SET totp_enabled = false, totp_secret = NULL, totp_last_step = NULL WHERE id = $1",
    )
    .bind(admin_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM totp_recovery_codes WHERE admin_id = $1")
        .bind(admin_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Verwalter setzt Zwei-Faktor eines anderen Kontos zurück (Gerät verloren). Beendet dessen Sitzungen.
pub async fn admin_reset(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    if id == me.id {
        return Err(ApiError::Forbidden(
            "Dein eigenes Zwei-Faktor schaltest du unter Konto aus",
        ));
    }
    let mut tx = st.pool.begin().await?;
    let t = super::users::target(&mut tx, id).await?;
    super::users::require_covers(&me, &t)?;
    tx.commit().await?;
    reset(&st, id).await?;
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1")
        .bind(id)
        .execute(&st.pool)
        .await?;
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "user.mfa_reset",
        Some(&t.display_name),
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- eigene Sitzungen ----------

type SessionListRow = (
    String,
    Option<String>,
    Option<String>,
    String,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
    bool,
);

pub async fn sessions(
    State(st): State<AppState>,
    SelfAdmin(admin): SelfAdmin,
) -> ApiResult<Json<Value>> {
    let rows: Vec<SessionListRow> = sqlx::query_as(
        "SELECT public_id::text, ip, user_agent, method, created_at, last_seen_at, expires_at, (id_hash = $2) \
         FROM sessions WHERE admin_id = $1 AND expires_at > now() ORDER BY created_at DESC",
    )
    .bind(admin.id)
    .bind(&admin.session_hash)
    .fetch_all(&st.pool)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(id, ip, ua, method, created, seen, expires, current)| {
            json!({
                "id": id, "ip": ip, "user_agent": ua, "method": method,
                "created_at": created, "last_seen_at": seen, "expires_at": expires, "current": current,
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": items })))
}

fn clear_cookie(st: &AppState, mut resp: Response) -> ApiResult<Response> {
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&security::session_cookie("", 0, st.cfg.cookie_secure))
            .map_err(anyhow::Error::from)?,
    );
    Ok(resp)
}

/// Eine eigene Sitzung beenden (auch die aktuelle: dann wird der Cookie gelöscht).
pub async fn revoke(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = uuid::Uuid::parse_str(&id).map_err(|_| ApiError::NotFound)?;
    let gone: Option<bool> = sqlx::query_scalar(
        "DELETE FROM sessions WHERE admin_id = $1 AND public_id = $2::uuid RETURNING (id_hash = $3)",
    )
    .bind(admin.id)
    .bind(id.to_string())
    .bind(&admin.session_hash)
    .fetch_optional(&st.pool)
    .await?;
    let Some(was_current) = gone else {
        return Err(ApiError::NotFound);
    };
    audit::record(
        &st.pool,
        Some(admin.id),
        &admin.username,
        "session.revoked",
        None,
        Outcome::Ok,
        &ip,
    )
    .await;
    let resp = StatusCode::NO_CONTENT.into_response();
    if was_current {
        clear_cookie(&st, resp)
    } else {
        Ok(resp)
    }
}

#[derive(Deserialize)]
pub struct RevokeAll {
    /// true: auch dieses Gerät abmelden.
    #[serde(default)]
    include_current: bool,
}

/// Alle Geräte abmelden (standardmäßig außer diesem).
pub async fn revoke_all(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(admin): SelfCsrfAdmin,
    Json(b): Json<RevokeAll>,
) -> ApiResult<Response> {
    let n = if b.include_current {
        sqlx::query("DELETE FROM sessions WHERE admin_id = $1")
            .bind(admin.id)
            .execute(&st.pool)
            .await?
    } else {
        sqlx::query("DELETE FROM sessions WHERE admin_id = $1 AND id_hash <> $2")
            .bind(admin.id)
            .bind(&admin.session_hash)
            .execute(&st.pool)
            .await?
    }
    .rows_affected();
    audit::record(
        &st.pool,
        Some(admin.id),
        &admin.username,
        "session.revoked_all",
        None,
        Outcome::Ok,
        &ip,
    )
    .await;
    let resp = Json(json!({ "revoked": n })).into_response();
    if b.include_current {
        clear_cookie(&st, resp)
    } else {
        Ok(resp)
    }
}
