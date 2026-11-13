//! OpenID Connect: Authorization-Code-Flow mit PKCE (S256), Client-Secret, state im Cookie und in der Datenbank, nonce.
//!
//! Der ID-Token kommt direkt vom Token-Endpunkt über TLS; die Signatur wird deshalb nicht geprüft (OIDC Core 3.1.3.7,
//! Punkt 6), wohl aber Aussteller, Zielgruppe, Ablauf und nonce. Angemeldet wird nur, wer in `OIDC_ALLOWED_EMAILS`
//! oder `OIDC_ALLOWED_DOMAINS` steht und dessen E-Mail-Adresse nicht als unverifiziert gemeldet wird.
use crate::authz;
use crate::error::{ApiError, ApiResult};
use crate::extract::{Authed, ClientIp, CsrfAuthed};
use crate::security;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

const STATE_COOKIE: &str = "pw_oidc";
const COOKIE_PATH: &str = "/api/v1/auth/oidc";

const SETTING_KEY: &str = "oidc";
/// Zusatzdaten der Verschlüsselung des Client-Secrets in der Datenbank.
const SECRET_AAD: &str = "oidc-client-secret";

/// In der UI gepflegte Einstellung (Tabelle `settings`); hat Vorrang vor den Umgebungsvariablen.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Stored {
    enabled: bool,
    issuer: String,
    client_id: String,
    redirect_url: String,
    name: String,
    scopes: String,
    allowed_emails: Vec<String>,
    allowed_domains: Vec<String>,
    /// Client-Secret, verschlüsselt (XChaCha20-Poly1305, Base64).
    secret: Option<String>,
}

/// Wirksame Konfiguration (UI oder Umgebung).
pub struct Resolved {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    name: String,
    scopes: String,
    allowed_emails: Vec<String>,
    allowed_domains: Vec<String>,
}

impl Resolved {
    /// Darf sich diese (verifizierte) E-Mail-Adresse anmelden?
    fn allows(&self, email: &str) -> bool {
        let email = email.to_ascii_lowercase();
        self.allowed_emails.contains(&email)
            || email
                .rsplit_once('@')
                .is_some_and(|(_, d)| self.allowed_domains.iter().any(|a| a == d))
    }
}

async fn load_stored(st: &AppState) -> Option<Stored> {
    let v: Option<Value> = sqlx::query_scalar("SELECT value FROM settings WHERE key = $1")
        .bind(SETTING_KEY)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten();
    v.and_then(|v| serde_json::from_value(v).ok())
}

fn decrypt_secret(st: &AppState, stored: &Stored) -> Option<String> {
    let key = st.cfg.secret_key.as_ref()?;
    let blob = URL_SAFE_NO_PAD.decode(stored.secret.as_deref()?).ok()?;
    crate::notify::crypto::decrypt(key.bytes(), SECRET_AAD, &blob).ok()
}

/// UI-Einstellung vor Umgebungsvariablen; `None` = Anmeldung per OIDC ist aus.
pub async fn resolve(st: &AppState) -> Option<Resolved> {
    if let Some(s) = load_stored(st).await {
        if !s.enabled {
            return None;
        }
        let client_secret = decrypt_secret(st, &s)?;
        return Some(Resolved {
            issuer: s.issuer,
            client_id: s.client_id,
            client_secret,
            redirect_url: s.redirect_url,
            name: s.name,
            scopes: s.scopes,
            allowed_emails: s.allowed_emails,
            allowed_domains: s.allowed_domains,
        });
    }
    let o = &st.cfg.oidc;
    if !o.enabled() {
        return None;
    }
    Some(Resolved {
        issuer: o.issuer.clone()?,
        client_id: o.client_id.clone()?,
        client_secret: o.client_secret.as_ref()?.expose().to_owned(),
        redirect_url: o.redirect_url.clone()?,
        name: o.name.clone().unwrap_or_default(),
        scopes: o.scopes.clone().unwrap_or_default(),
        allowed_emails: o.allowed_emails.clone(),
        allowed_domains: o.allowed_domains.clone(),
    })
}

fn label(o: &Resolved) -> &str {
    if o.name.is_empty() {
        "Single Sign-On"
    } else {
        &o.name
    }
}

/// Öffentlich: welche Anmeldearten gibt es (für die Anmeldeseite)?
pub async fn providers(State(st): State<AppState>) -> Json<Value> {
    let o = resolve(&st).await;
    Json(
        json!({ "oidc": { "enabled": o.is_some(), "name": o.as_ref().map(label).unwrap_or("Single Sign-On") } }),
    )
}

/// Einstellungen für die UI; das Client-Secret wird nie ausgegeben.
pub async fn settings_get(
    _: Authed<authz::p::OidcManage>,
    State(st): State<AppState>,
) -> ApiResult<Json<Value>> {
    Ok(Json(settings_view(&st).await))
}

async fn settings_view(st: &AppState) -> Value {
    let stored = load_stored(st).await;
    let (source, s) = match stored {
        Some(s) => ("ui", s),
        None if st.cfg.oidc.enabled() => {
            let o = &st.cfg.oidc;
            (
                "env",
                Stored {
                    enabled: true,
                    issuer: o.issuer.clone().unwrap_or_default(),
                    client_id: o.client_id.clone().unwrap_or_default(),
                    redirect_url: o.redirect_url.clone().unwrap_or_default(),
                    name: o.name.clone().unwrap_or_default(),
                    scopes: o.scopes.clone().unwrap_or_default(),
                    allowed_emails: o.allowed_emails.clone(),
                    allowed_domains: o.allowed_domains.clone(),
                    secret: Some(String::new()),
                },
            )
        }
        None => ("none", Stored::default()),
    };
    json!({
        "source": source,
        "enabled": s.enabled,
        "issuer": s.issuer,
        "client_id": s.client_id,
        "redirect_url": s.redirect_url,
        "name": s.name,
        "scopes": s.scopes,
        "allowed_emails": s.allowed_emails,
        "allowed_domains": s.allowed_domains,
        "secret_set": s.secret.is_some(),
        "secret_storage": st.cfg.secret_key.is_some(),
    })
}

#[derive(Deserialize)]
pub struct SettingsBody {
    enabled: bool,
    issuer: String,
    client_id: String,
    redirect_url: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    scopes: String,
    #[serde(default)]
    allowed_emails: Vec<String>,
    #[serde(default)]
    allowed_domains: Vec<String>,
    /// Neues Client-Secret; fehlt es, bleibt das gespeicherte.
    client_secret: Option<String>,
}

fn clean_list(v: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in v {
        let x = x.trim().to_ascii_lowercase();
        if !x.is_empty() && !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// Speichert die OIDC-Einstellungen. Wer sich anmelden darf, muss festgelegt sein (E-Mails oder Domains).
pub async fn settings_put(
    CsrfAuthed(_, _): CsrfAuthed<authz::p::OidcManage>,
    State(st): State<AppState>,
    Json(b): Json<SettingsBody>,
) -> ApiResult<Json<Value>> {
    let bad = |m: &str| ApiError::BadRequest(m.to_owned());
    // Die Werte landen in einem jsonb-Wert; NUL würde dort einen Datenbankfehler (500) auslösen.
    let has_nul = [&b.issuer, &b.client_id, &b.redirect_url, &b.name, &b.scopes]
        .into_iter()
        .chain(&b.allowed_emails)
        .chain(&b.allowed_domains)
        .any(|s| super::has_nul(s));
    if has_nul {
        return Err(bad("ungültige Zeichen in den Einstellungen"));
    }
    let issuer = b.issuer.trim().trim_end_matches('/').to_owned();
    let allowed_emails = clean_list(&b.allowed_emails);
    let allowed_domains = clean_list(&b.allowed_domains);
    let existing = load_stored(&st).await;
    let mut secret = existing.as_ref().and_then(|e| e.secret.clone());
    if let Some(cs) = b.client_secret.as_deref().filter(|s| !s.is_empty()) {
        if cs.len() > 2048 || cs.chars().any(char::is_control) {
            return Err(bad("Client-Secret: 1–2048 Zeichen ohne Steuerzeichen"));
        }
        let key = st.cfg.secret_key.as_ref().ok_or_else(|| {
            bad("PATCHWATCH_SECRET_KEY ist nicht gesetzt: das Client-Secret kann nicht gespeichert werden")
        })?;
        let blob = crate::notify::crypto::encrypt(key.bytes(), SECRET_AAD, cs)?;
        secret = Some(URL_SAFE_NO_PAD.encode(blob));
    }
    if b.enabled {
        let local =
            issuer.starts_with("http://localhost") || issuer.starts_with("http://127.0.0.1");
        if !(issuer.starts_with("https://") || local) {
            return Err(bad("Issuer muss mit https:// beginnen"));
        }
        if b.client_id.trim().is_empty() || secret.is_none() {
            return Err(bad("Client-ID und Client-Secret sind nötig"));
        }
        if !(b.redirect_url.starts_with("https://") || b.redirect_url.starts_with("http://")) {
            return Err(bad("Redirect-URL muss mit http(s):// beginnen"));
        }
        if allowed_emails.is_empty() && allowed_domains.is_empty() {
            return Err(bad(
                "Lege fest, wer sich anmelden darf (E-Mail-Adressen oder Domains)",
            ));
        }
    }
    let stored = Stored {
        enabled: b.enabled,
        issuer,
        client_id: b.client_id.trim().to_owned(),
        redirect_url: b.redirect_url.trim().to_owned(),
        name: b.name.trim().chars().take(40).collect(),
        scopes: b.scopes.trim().to_owned(),
        allowed_emails,
        allowed_domains,
        secret,
    };
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(SETTING_KEY)
    .bind(serde_json::to_value(&stored).map_err(anyhow::Error::from)?)
    .execute(&st.pool)
    .await?;
    Ok(Json(settings_view(&st).await))
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

async fn discover(st: &AppState, issuer: &str) -> ApiResult<Discovery> {
    let d: Discovery = st
        .http
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if d.issuer.trim_end_matches('/') != issuer {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "OIDC: Aussteller in der Discovery stimmt nicht überein"
        )));
    }
    Ok(d)
}

fn secure_attr(st: &AppState) -> &'static str {
    if st.cfg.cookie_secure {
        "; Secure"
    } else {
        ""
    }
}

fn state_cookie(st: &AppState, value: &str, max_age: i64) -> String {
    // Lax: Der Callback ist eine seitenübergreifende Navigation vom Provider; Strict würde das Cookie nicht senden.
    format!(
        "{STATE_COOKIE}={value}; HttpOnly; SameSite=Lax; Path={COOKIE_PATH}; Max-Age={max_age}{}",
        secure_attr(st)
    )
}

/// Startet die Anmeldung: legt state/nonce/PKCE an und leitet zum Provider.
pub async fn login(State(st): State<AppState>, ClientIp(ip): ClientIp) -> ApiResult<Response> {
    let o = resolve(&st).await.ok_or(ApiError::NotFound)?;
    st.limiter
        .check(&format!("oidc-start:{ip}"), 20, Duration::from_secs(600))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let d = discover(&st, &o.issuer).await?;
    let state = security::new_session_id();
    let nonce = security::new_session_id();
    let verifier = security::new_session_id();
    let challenge = URL_SAFE_NO_PAD.encode(security::sha256(&verifier));
    sqlx::query("DELETE FROM oidc_states WHERE expires_at < now()")
        .execute(&st.pool)
        .await?;
    sqlx::query("INSERT INTO oidc_states (state_hash, nonce, verifier, expires_at) VALUES ($1, $2, $3, now() + interval '10 minutes')")
        .bind(security::sha256(&state))
        .bind(&nonce)
        .bind(&verifier)
        .execute(&st.pool)
        .await?;
    let mut url = reqwest::Url::parse(&d.authorization_endpoint).map_err(anyhow::Error::from)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &o.client_id)
        .append_pair("redirect_uri", &o.redirect_url)
        .append_pair(
            "scope",
            if o.scopes.is_empty() {
                "openid email profile"
            } else {
                &o.scopes
            },
        )
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let mut resp = Redirect::to(url.as_str()).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&state_cookie(&st, &state, 600)).map_err(anyhow::Error::from)?,
    );
    Ok(resp)
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn fail(st: &AppState, why: &str) -> Response {
    tracing::warn!(grund = why, "OIDC-Anmeldung abgelehnt");
    let mut resp = Redirect::to("/login?error=oidc").into_response();
    if let Ok(v) = HeaderValue::from_str(&state_cookie(st, "", 0)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// Rückkehr vom Provider: Code gegen Token tauschen, prüfen, Sitzung anlegen.
pub async fn callback(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> ApiResult<Response> {
    let o = resolve(&st).await.ok_or(ApiError::NotFound)?;
    st.limiter
        .check(&format!("oidc-cb:{ip}"), 20, Duration::from_secs(600))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    if let Some(e) = q.error {
        return Ok(fail(&st, &format!("Provider meldet {e}")));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return Ok(fail(&st, "code oder state fehlt"));
    };
    // Login-CSRF: Der state muss zu dem Browser gehören, der die Anmeldung gestartet hat.
    let cookie_state = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| security::cookie_value(c, STATE_COOKIE));
    if !cookie_state.is_some_and(|c| security::ct_eq(c, &state)) {
        return Ok(fail(&st, "state-Cookie passt nicht"));
    }
    let stored: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM oidc_states WHERE state_hash = $1 AND expires_at > now() RETURNING nonce, verifier",
    )
    .bind(security::sha256(&state))
    .fetch_optional(&st.pool)
    .await?;
    let Some((nonce, verifier)) = stored else {
        return Ok(fail(&st, "state unbekannt oder abgelaufen"));
    };

    match exchange(&st, &o, &code, &nonce, &verifier).await {
        Ok(email) => {
            if !o.allows(&email) {
                return Ok(fail(&st, &format!("{email} ist nicht freigegeben")));
            }
            let admin_id = upsert_admin(&st, &email).await?;
            let session_id = security::new_session_id();
            let ttl = st.cfg.session_ttl_hours * 3600;
            sqlx::query("INSERT INTO sessions (id_hash, admin_id, csrf_token, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))")
                .bind(security::sha256(&session_id))
                .bind(admin_id)
                .bind(security::new_csrf_token())
                .bind(ttl as f64)
                .execute(&st.pool)
                .await?;
            let mut resp = Redirect::to("/").into_response();
            for c in [
                security::session_cookie(&session_id, ttl, st.cfg.cookie_secure),
                state_cookie(&st, "", 0),
            ] {
                resp.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&c).map_err(anyhow::Error::from)?,
                );
            }
            Ok(resp)
        }
        Err(e) => Ok(fail(&st, &e.to_string())),
    }
}

fn claims(jwt: &str) -> anyhow::Result<Value> {
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("id_token ist kein JWT"))?;
    Ok(serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(payload.trim_end_matches('='))?,
    )?)
}

/// Tauscht den Code, prüft den ID-Token und liefert die verifizierte E-Mail-Adresse (klein geschrieben).
async fn exchange(
    st: &AppState,
    o: &Resolved,
    code: &str,
    nonce: &str,
    verifier: &str,
) -> anyhow::Result<String> {
    let (client_id, secret) = (o.client_id.as_str(), o.client_secret.as_str());
    let d = discover(st, &o.issuer)
        .await
        .map_err(|_| anyhow::anyhow!("Discovery fehlgeschlagen"))?;
    let basic = d
        .token_endpoint_auth_methods_supported
        .as_ref()
        .is_some_and(|m| {
            !m.iter().any(|x| x == "client_secret_post")
                && m.iter().any(|x| x == "client_secret_basic")
        });
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", o.redirect_url.as_str()),
        ("code_verifier", verifier),
    ];
    let mut req = st.http.post(&d.token_endpoint);
    if basic {
        req = req.basic_auth(client_id, Some(secret));
    } else {
        form.push(("client_id", client_id));
        form.push(("client_secret", secret));
    }
    let resp = req.form(&form).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Token-Endpunkt antwortet {}", resp.status());
    }
    let tok: Value = resp.json().await?;
    let id_token = tok["id_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("kein id_token"))?;
    let c = claims(id_token)?;

    let issuer = o.issuer.as_str();
    if c["iss"].as_str().map(|i| i.trim_end_matches('/')) != Some(issuer) {
        anyhow::bail!("iss stimmt nicht");
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == client_id,
        Value::Array(a) => a.iter().any(|x| x.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        anyhow::bail!("aud stimmt nicht");
    }
    if c["exp"]
        .as_i64()
        .is_none_or(|e| e < chrono::Utc::now().timestamp())
    {
        anyhow::bail!("id_token abgelaufen");
    }
    if c["nonce"].as_str() != Some(nonce) {
        anyhow::bail!("nonce stimmt nicht");
    }
    let sub = c["sub"].to_owned();
    let sub = sub.as_str().ok_or_else(|| anyhow::anyhow!("sub fehlt"))?;

    // E-Mail aus dem ID-Token, sonst vom UserInfo-Endpunkt (dessen sub muss übereinstimmen).
    let mut profile = c;
    if profile["email"].as_str().is_none() {
        if let (Some(url), Some(at)) = (&d.userinfo_endpoint, tok["access_token"].as_str()) {
            let u: Value = st
                .http
                .get(url)
                .bearer_auth(at)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if u["sub"].as_str() != Some(sub) {
                anyhow::bail!("userinfo-sub stimmt nicht");
            }
            profile = u;
        }
    }
    let email = profile["email"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("keine E-Mail-Adresse geliefert"))?;
    // Manche Provider senden email_verified als Text.
    let unverified = matches!(&profile["email_verified"], Value::Bool(false))
        || profile["email_verified"].as_str() == Some("false");
    if unverified {
        anyhow::bail!("E-Mail-Adresse nicht verifiziert");
    }
    Ok(email.to_ascii_lowercase())
}

/// Legt den Benutzer `oidc:<email>` an (mit unbenutzbarem Zufallspasswort; Passwort-Anmeldung ist damit ausgeschlossen).
async fn upsert_admin(st: &AppState, email: &str) -> ApiResult<i64> {
    let username = format!("oidc:{email}");
    if let Some(id) = sqlx::query_scalar::<_, i64>("SELECT id FROM admin_users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&st.pool)
        .await?
    {
        return Ok(id);
    }
    let random = security::new_session_id();
    let hash = tokio::task::spawn_blocking(move || security::hash_password(&random))
        .await
        .map_err(anyhow::Error::from)??;
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO admin_users (username, password_hash) VALUES ($1, $2) \
         ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username RETURNING id",
    )
    .bind(&username)
    .bind(hash)
    .fetch_one(&st.pool)
    .await?;
    Ok(id)
}
