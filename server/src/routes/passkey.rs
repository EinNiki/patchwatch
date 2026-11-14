//! Passkeys (WebAuthn): Anmeldung ohne Passwort und eigene Verwaltung je Benutzer.
//!
//! Ablauf je Vorgang (Zeremonie): `start` liefert Optionen für den Browser und merkt sich den Zustand kurz im Speicher
//! (5 Minuten, einmal verwendbar, an Benutzer und Zweck gebunden); `finish` prüft die Antwort des Geräts. Der private Schlüssel
//! verlässt das Gerät nie, gespeichert wird nur der öffentliche Teil. Anmeldung braucht Nutzerverifikation (PIN/Biometrie).
//! Unbekannte Namen, Konten ohne Passkey und gesperrte Konten bekommen dieselbe Antwortform (Scheinaufforderung), damit
//! die Anmeldung kein Konto verrät.

use crate::audit::{self, Outcome};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ClientIp, SelfAdmin, SelfCsrfAdmin};
use crate::security;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

const TTL: Duration = Duration::from_secs(300);
const MAX_PER_USER: i64 = 10;
const MAX_PENDING: usize = 2_000;

enum Pending {
    Register {
        admin_id: i64,
        state: Box<PasskeyRegistration>,
    },
    Login {
        admin_id: i64,
        state: Box<PasskeyAuthentication>,
    },
    /// Anmeldung ohne Namenseingabe: das Gerät nennt das Konto selbst (sichtbarer Schlüssel).
    Discoverable {
        state: Box<DiscoverableAuthentication>,
    },
    /// Scheinvorgang für unbekannte Namen: schlägt in `finish` immer fehl.
    Decoy,
}

static CEREMONIES: LazyLock<Mutex<HashMap<String, (Instant, Pending)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Zufallswert pro Serverstart: macht die Schein-Credential-IDs je Name stabil, aber nicht vorhersagbar.
static DECOY_SALT: LazyLock<String> = LazyLock::new(security::new_session_id);

fn put(p: Pending) -> ApiResult<String> {
    let mut m = CEREMONIES.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    m.retain(|_, (t, _)| now.duration_since(*t) < TTL);
    if m.len() >= MAX_PENDING {
        return Err(ApiError::TooManyRequests {
            retry_after_secs: 30,
        });
    }
    let id = security::new_session_id();
    m.insert(id.clone(), (now, p));
    Ok(id)
}

/// Einmal verwendbar: wird beim Abholen entfernt.
fn take(id: &str) -> Option<Pending> {
    let mut m = CEREMONIES.lock().unwrap_or_else(|e| e.into_inner());
    let (t, p) = m.remove(id)?;
    (Instant::now().duration_since(t) < TTL).then_some(p)
}

/// Webauthn-Instanz aus `PATCHWATCH_PUBLIC_URL` (Relying-Party-ID = Host, Origin = Schema + Host + Port).
fn webauthn(st: &AppState) -> ApiResult<Webauthn> {
    let Some(public) = st.cfg.public_url.as_deref() else {
        return Err(ApiError::BadRequest(
            "Passkeys brauchen PATCHWATCH_PUBLIC_URL (die Adresse, unter der du patchwatch im Browser öffnest)".into(),
        ));
    };
    let url = Url::parse(public)
        .map_err(|_| ApiError::BadRequest("PATCHWATCH_PUBLIC_URL ist ungültig".into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("PATCHWATCH_PUBLIC_URL ohne Host".into()))?
        .to_owned();
    WebauthnBuilder::new(&host, &url)
        .map_err(|_| {
            ApiError::BadRequest(
                "PATCHWATCH_PUBLIC_URL passt nicht als WebAuthn-Adresse (Host oder IP?)".into(),
            )
        })?
        .rp_name("patchwatch")
        .build()
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("webauthn: {e}")))
}

/// Wirft `Internal`, die Antwort verrät nur „Passkey abgelehnt“.
fn refused() -> ApiError {
    ApiError::Unauthorized
}

fn clean_name(raw: &str) -> ApiResult<String> {
    let n = raw.trim();
    let len = n.chars().count();
    if len == 0 || len > 60 || n.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "Name des Passkeys: 1 bis 60 Zeichen, keine Steuerzeichen".into(),
        ));
    }
    Ok(n.to_owned())
}

// ---------- eigene Passkeys verwalten ----------

/// (id, Name, angelegt, zuletzt benutzt)
type PasskeyRow = (
    i64,
    String,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
);

pub async fn list(State(st): State<AppState>, SelfAdmin(me): SelfAdmin) -> ApiResult<Json<Value>> {
    let rows: Vec<PasskeyRow> = sqlx::query_as(
        "SELECT id, name, created_at, last_used_at FROM passkeys WHERE admin_id = $1 ORDER BY id",
    )
    .bind(me.id)
    .fetch_all(&st.pool)
    .await?;
    let disabled: bool =
        sqlx::query_scalar("SELECT password_login_disabled FROM admin_users WHERE id = $1")
            .bind(me.id)
            .fetch_one(&st.pool)
            .await?;
    Ok(Json(json!({
        "available": webauthn(&st).is_ok(),
        "password_login_disabled": disabled,
        "passkeys": rows.iter().map(|(id, name, c, l)| json!({"id": id, "name": name, "created_at": c, "last_used_at": l})).collect::<Vec<_>>(),
    })))
}

pub async fn register_start(
    State(st): State<AppState>,
    SelfCsrfAdmin(me): SelfCsrfAdmin,
) -> ApiResult<Json<Value>> {
    let w = webauthn(&st)?;
    let (handle, display): (String, String) =
        sqlx::query_as("SELECT webauthn_handle::text, display_name FROM admin_users WHERE id = $1")
            .bind(me.id)
            .fetch_one(&st.pool)
            .await?;
    let handle = Uuid::parse_str(&handle).map_err(anyhow::Error::from)?;
    let existing: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT credential_id FROM passkeys WHERE admin_id = $1")
            .bind(me.id)
            .fetch_all(&st.pool)
            .await?;
    if existing.len() as i64 >= MAX_PER_USER {
        return Err(ApiError::Conflict(format!(
            "Höchstens {MAX_PER_USER} Passkeys je Konto"
        )));
    }
    let exclude = existing.into_iter().map(Into::into).collect::<Vec<_>>();
    let (options, state) = w
        .start_passkey_registration(handle, &me.username, &display, Some(exclude))
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("webauthn: {e}")))?;
    let ceremony = put(Pending::Register {
        admin_id: me.id,
        state: Box::new(state),
    })?;
    Ok(Json(json!({"ceremony": ceremony, "options": options})))
}

#[derive(Deserialize)]
pub struct RegisterFinish {
    ceremony: String,
    name: String,
    credential: RegisterPublicKeyCredential,
}

pub async fn register_finish(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(me): SelfCsrfAdmin,
    Json(b): Json<RegisterFinish>,
) -> ApiResult<Json<Value>> {
    let w = webauthn(&st)?;
    let name = clean_name(&b.name)?;
    let Some(Pending::Register { admin_id, state }) = take(&b.ceremony) else {
        return Err(ApiError::BadRequest(
            "Der Vorgang ist abgelaufen. Bitte neu starten.".into(),
        ));
    };
    if admin_id != me.id {
        return Err(refused());
    }
    let key = w
        .finish_passkey_registration(&b.credential, &state)
        .map_err(|_| ApiError::BadRequest("Das Gerät hat den Passkey nicht bestätigt".into()))?;
    let cred_id: Vec<u8> = key.cred_id().as_ref().to_vec();
    let json = serde_json::to_value(&key).map_err(anyhow::Error::from)?;
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO passkeys (admin_id, credential_id, credential, name) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (credential_id) DO NOTHING RETURNING id",
    )
    .bind(me.id)
    .bind(&cred_id)
    .bind(json)
    .bind(&name)
    .fetch_optional(&st.pool)
    .await?;
    let Some(id) = id else {
        return Err(ApiError::Conflict(
            "Dieser Passkey ist schon registriert".into(),
        ));
    };
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "passkey.added",
        Some(&name),
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(Json(json!({"id": id, "name": name})))
}

pub async fn remove(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(me): SelfCsrfAdmin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let mut tx = st.pool.begin().await?;
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM passkeys WHERE id = $1 AND admin_id = $2 RETURNING name")
            .bind(id)
            .bind(me.id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(name) = name else {
        return Err(ApiError::NotFound);
    };
    // Ohne Passkey darf die Anmeldung per Passwort nicht ausgeschaltet bleiben (sonst Aussperrung).
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM passkeys WHERE admin_id = $1")
        .bind(me.id)
        .fetch_one(&mut *tx)
        .await?;
    if left == 0 {
        sqlx::query("UPDATE admin_users SET password_login_disabled = false WHERE id = $1")
            .bind(me.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "passkey.removed",
        Some(&name),
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PasswordLogin {
    disabled: bool,
}

/// Anmeldung per Passwort für das eigene Konto ein- oder ausschalten. Aus nur mit mindestens einem Passkey.
pub async fn set_password_login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    SelfCsrfAdmin(me): SelfCsrfAdmin,
    Json(b): Json<PasswordLogin>,
) -> ApiResult<Json<Value>> {
    let mut tx = st.pool.begin().await?;
    // Zeilensperre: ein gleichzeitiges Löschen des letzten Passkeys kann das Ausschalten nicht unterlaufen.
    sqlx::query("SELECT id FROM admin_users WHERE id = $1 FOR UPDATE")
        .bind(me.id)
        .fetch_one(&mut *tx)
        .await?;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM passkeys WHERE admin_id = $1")
        .bind(me.id)
        .fetch_one(&mut *tx)
        .await?;
    if b.disabled && n == 0 {
        return Err(ApiError::Conflict(
            "Lege zuerst einen Passkey an, sonst sperrst du dich aus".into(),
        ));
    }
    sqlx::query("UPDATE admin_users SET password_login_disabled = $2 WHERE id = $1")
        .bind(me.id)
        .bind(b.disabled)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        if b.disabled {
            "password_login.disabled"
        } else {
            "password_login.enabled"
        },
        None,
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(Json(json!({"password_login_disabled": b.disabled})))
}

// ---------- Anmeldung ----------

#[derive(Deserialize)]
pub struct LoginStart {
    /// Leer oder fehlend: Anmeldung ohne Namen (das Gerät wählt das Konto).
    #[serde(default)]
    username: String,
}

pub async fn login_start(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(b): Json<LoginStart>,
) -> ApiResult<Json<Value>> {
    if b.username.len() > 64 || super::has_nul(&b.username) {
        return Err(ApiError::BadRequest("ungültige Eingabe".into()));
    }
    if b.username.is_empty() {
        st.limiter
            .check(&format!("passkey-ip:{ip}"), 20, Duration::from_secs(600))
            .map_err(|w| ApiError::TooManyRequests {
                retry_after_secs: w.as_secs().max(1),
            })?;
        let (options, state) = webauthn(&st)?
            .start_discoverable_authentication()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("webauthn: {e}")))?;
        let ceremony = put(Pending::Discoverable {
            state: Box::new(state),
        })?;
        let mut options = serde_json::to_value(options).map_err(anyhow::Error::from)?;
        // Der Browser soll die Auswahl sofort zeigen (nicht erst als stilles Autofill).
        if let Some(o) = options.as_object_mut() {
            o.remove("mediation");
        }
        return Ok(Json(json!({"ceremony": ceremony, "options": options})));
    }
    for key in [
        format!("passkey-ip:{ip}"),
        format!("passkey-user:{}", b.username.to_lowercase()),
    ] {
        st.limiter
            .check(&key, 20, Duration::from_secs(600))
            .map_err(|w| ApiError::TooManyRequests {
                retry_after_secs: w.as_secs().max(1),
            })?;
    }
    let w = webauthn(&st)?;
    let acct: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM admin_users WHERE status = 'active' AND deleted_at IS NULL AND username = $1",
    )
    .bind(&b.username)
    .fetch_optional(&st.pool)
    .await?;
    let keys: Vec<(Vec<u8>, Value)> = match acct {
        Some(id) => {
            sqlx::query_as("SELECT credential_id, credential FROM passkeys WHERE admin_id = $1")
                .bind(id)
                .fetch_all(&st.pool)
                .await?
        }
        None => vec![],
    };
    let passkeys: Vec<Passkey> = keys
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_value(v).ok())
        .collect();
    if let (Some(admin_id), false) = (acct, passkeys.is_empty()) {
        let (options, state) = w
            .start_passkey_authentication(&passkeys)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("webauthn: {e}")))?;
        let ceremony = put(Pending::Login {
            admin_id,
            state: Box::new(state),
        })?;
        return Ok(Json(json!({"ceremony": ceremony, "options": options})));
    }
    // Scheinaufforderung: gleiche Form, stabile Schein-ID je Name.
    let fake = URL_SAFE_NO_PAD
        .encode(&security::sha256(&format!("{}|{}", *DECOY_SALT, b.username.to_lowercase()))[..32]);
    let challenge = URL_SAFE_NO_PAD.encode(security::new_session_id().as_bytes());
    let rp_id = st
        .cfg
        .public_url
        .as_deref()
        .and_then(|u| Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    let ceremony = put(Pending::Decoy)?;
    audit::record(
        &st.pool,
        None,
        &b.username,
        "login.passkey_start",
        None,
        Outcome::Failed,
        &ip,
    )
    .await;
    Ok(Json(json!({
        "ceremony": ceremony,
        "options": {"publicKey": {
            "challenge": challenge,
            "timeout": 300000,
            "rpId": rp_id,
            "allowCredentials": [{"type": "public-key", "id": fake}],
            "userVerification": "required",
        }},
    })))
}

#[derive(Deserialize)]
pub struct LoginFinish {
    ceremony: String,
    credential: PublicKeyCredential,
}

pub async fn login_finish(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(b): Json<LoginFinish>,
) -> ApiResult<Response> {
    st.limiter
        .check(&format!("passkey-fin:{ip}"), 20, Duration::from_secs(600))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let w = webauthn(&st)?;
    // Beide Wege liefern Konto, Ergebnis und die gespeicherte Zeile des benutzten Passkeys.
    let (admin_id, result, row) = match take(&b.ceremony) {
        Some(Pending::Login { admin_id, state }) => {
            let r = w.finish_passkey_authentication(&b.credential, &state);
            (admin_id, r, None)
        }
        Some(Pending::Discoverable { state }) => {
            // Konto und Schlüssel aus Benutzerkennung und Credential-ID der Antwort bestimmen.
            let Ok((handle, cred_id)) = w.identify_discoverable_authentication(&b.credential)
            else {
                return Err(refused());
            };
            let found: Option<(i64, i64, Value)> = sqlx::query_as(
                "SELECT u.id, k.id, k.credential FROM passkeys k JOIN admin_users u ON u.id = k.admin_id \
                 WHERE u.webauthn_handle::text = $1 AND k.credential_id = $2 \
                   AND u.status = 'active' AND u.deleted_at IS NULL",
            )
            .bind(handle.to_string())
            .bind(cred_id)
            .fetch_optional(&st.pool)
            .await?;
            let Some((admin_id, pk_id, stored)) = found else {
                return Err(refused());
            };
            let Ok(key) = serde_json::from_value::<Passkey>(stored.clone()) else {
                return Err(refused());
            };
            let r = w.finish_discoverable_authentication(
                &b.credential,
                *state,
                &[DiscoverableKey::from(&key)],
            );
            (admin_id, r, Some((pk_id, stored)))
        }
        _ => return Err(refused()),
    };
    let result = result.map_err(|_| refused());
    let result = match result {
        Ok(r) => r,
        Err(e) => {
            audit::record(
                &st.pool,
                Some(admin_id),
                "passkey",
                "login",
                None,
                Outcome::Failed,
                &ip,
            )
            .await;
            return Err(e);
        }
    };
    // Gespeicherten Zähler und Sicherungsstatus nachziehen (Klon-Erkennung).
    let cred_id: Vec<u8> = result.cred_id().as_ref().to_vec();
    let row: Option<(i64, Value)> =
        match row {
            Some(r) => Some(r),
            None => sqlx::query_as(
                "SELECT id, credential FROM passkeys WHERE credential_id = $1 AND admin_id = $2",
            )
            .bind(&cred_id)
            .bind(admin_id)
            .fetch_optional(&st.pool)
            .await?,
        };
    let Some((pk_id, stored)) = row else {
        return Err(refused());
    };
    if let Ok(mut key) = serde_json::from_value::<Passkey>(stored) {
        if key.update_credential(&result).unwrap_or(false) {
            sqlx::query("UPDATE passkeys SET credential = $2 WHERE id = $1")
                .bind(pk_id)
                .bind(serde_json::to_value(&key).map_err(anyhow::Error::from)?)
                .execute(&st.pool)
                .await?;
        }
    }
    // Konto noch aktiv? (zwischen Start und Ende kann es gesperrt worden sein)
    let who: Option<(String, bool)> = sqlx::query_as(
        "SELECT username, must_change_password FROM admin_users WHERE id = $1 AND status = 'active' AND deleted_at IS NULL",
    )
    .bind(admin_id)
    .fetch_optional(&st.pool)
    .await?;
    let Some((username, must_change)) = who else {
        return Err(refused());
    };
    sqlx::query("UPDATE passkeys SET last_used_at = now() WHERE id = $1")
        .bind(pk_id)
        .execute(&st.pool)
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
        Some("passkey"),
        Outcome::Ok,
        &ip,
    )
    .await;
    let (cookie, csrf) = super::auth::issue_session(&st, admin_id).await?;
    let mut resp = Json(
        json!({"username": username, "csrf_token": csrf, "must_change_password": must_change}),
    )
    .into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(anyhow::Error::from)?,
    );
    Ok(resp)
}
