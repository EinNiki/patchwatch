//! OpenID Connect: Authorization-Code-Flow mit PKCE (S256), Client-Secret, state im Cookie und in der Datenbank, nonce.
//!
//! Der ID-Token kommt direkt vom Token-Endpunkt über TLS; die Signatur wird deshalb nicht geprüft (OIDC Core 3.1.3.7,
//! Punkt 6), wohl aber Aussteller, Zielgruppe, Ablauf und nonce. Angemeldet wird nur, wer in `OIDC_ALLOWED_EMAILS`
//! oder `OIDC_ALLOWED_DOMAINS` steht und dessen E-Mail-Adresse nicht als unverifiziert gemeldet wird.
use crate::error::{ApiError, ApiResult};
use crate::extract::ClientIp;
use crate::security;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const STATE_COOKIE: &str = "pw_oidc";
const COOKIE_PATH: &str = "/api/v1/auth/oidc";

/// Öffentlich: welche Anmeldearten gibt es (für die Anmeldeseite)?
pub async fn providers(State(st): State<AppState>) -> Json<Value> {
    let o = &st.cfg.oidc;
    Json(
        json!({ "oidc": { "enabled": o.enabled(), "name": o.name.as_deref().unwrap_or("Single Sign-On") } }),
    )
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

async fn discover(st: &AppState) -> ApiResult<Discovery> {
    let issuer = st.cfg.oidc.issuer.as_deref().ok_or(ApiError::NotFound)?;
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
    let o = &st.cfg.oidc;
    if !o.enabled() {
        return Err(ApiError::NotFound);
    }
    st.limiter
        .check(&format!("oidc-start:{ip}"), 20, Duration::from_secs(600))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let d = discover(&st).await?;
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
        .append_pair("client_id", o.client_id.as_deref().unwrap_or_default())
        .append_pair(
            "redirect_uri",
            o.redirect_url.as_deref().unwrap_or_default(),
        )
        .append_pair(
            "scope",
            o.scopes.as_deref().unwrap_or("openid email profile"),
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
    if !st.cfg.oidc.enabled() {
        return Err(ApiError::NotFound);
    }
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

    match exchange(&st, &code, &nonce, &verifier).await {
        Ok(email) => {
            if !st.cfg.oidc.allows(&email) {
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
    code: &str,
    nonce: &str,
    verifier: &str,
) -> anyhow::Result<String> {
    let o = &st.cfg.oidc;
    let (client_id, secret) = (
        o.client_id.as_deref().unwrap_or_default(),
        o.client_secret
            .as_ref()
            .map(|s| s.expose())
            .unwrap_or_default(),
    );
    let d = discover(st)
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
        (
            "redirect_uri",
            o.redirect_url.as_deref().unwrap_or_default(),
        ),
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

    let issuer = o.issuer.as_deref().unwrap_or_default();
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
