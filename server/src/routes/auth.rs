use crate::error::{ApiError, ApiResult};
use crate::extract::{ClientIp, PendingAdmin, PendingCsrfAdmin};
use crate::security;
use crate::state::AppState;
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

    let user: Option<(i64, String, bool)> = sqlx::query_as(
        "SELECT id, password_hash, must_change_password FROM admin_users WHERE username = $1",
    )
    .bind(&body.username)
    .fetch_optional(&st.pool)
    .await?;
    let must_change = user.as_ref().is_some_and(|u| u.2);
    let (admin_id, hash) = match &user {
        Some((id, h, _)) => (Some(*id), h.clone()),
        None => (None, security::dummy_hash().to_owned()),
    };
    let password = body.password;
    let ok = tokio::task::spawn_blocking(move || security::verify_password(&hash, &password))
        .await
        .map_err(anyhow::Error::from)?;
    let Some(admin_id) = admin_id.filter(|_| ok) else {
        return Err(ApiError::Unauthorized);
    };

    let session_id = security::new_session_id();
    let csrf = security::new_csrf_token();
    let ttl = st.cfg.session_ttl_hours * 3600;
    sqlx::query(
        "INSERT INTO sessions (id_hash, admin_id, csrf_token, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
    )
    .bind(security::sha256(&session_id))
    .bind(admin_id)
    .bind(&csrf)
    .bind(ttl as f64)
    .execute(&st.pool)
    .await?;

    let cookie = security::session_cookie(&session_id, ttl, st.cfg.cookie_secure);
    let mut resp = Json(json!({
        "username": body.username,
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
    let (id, hash): (i64, String) =
        sqlx::query_as("SELECT id, password_hash FROM admin_users WHERE username = $1")
            .bind(&admin.username)
            .fetch_one(&st.pool)
            .await?;
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
    Ok(StatusCode::NO_CONTENT)
}

pub async fn me(PendingAdmin(admin): PendingAdmin) -> Json<serde_json::Value> {
    Json(json!({
        "username": admin.username,
        "csrf_token": admin.csrf_token,
        "must_change_password": admin.must_change_password,
    }))
}
