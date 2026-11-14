//! LDAP-Anmeldung mit festem Bind-Muster (z. B. `uid={username},ou=people,dc=firma,dc=de`).
//!
//! Der Server verbindet sich per LDAPS oder StartTLS (Zertifikat wird immer geprüft, kein Klartext) und versucht einen
//! Bind mit dem Muster. Der Benutzername wird vor dem Einsetzen nach RFC 4514 maskiert (keine DN-Injektion), leere
//! Passwörter werden nie gesendet (ein leerer Bind wäre bei vielen Servern anonym und „erfolgreich“). Konten werden nur
//! über den Namen zugeordnet und nur, wenn kein anderes Konto (lokal, OIDC) denselben Namen trägt. Neue Konten starten
//! standardmäßig „ausstehend“ und ohne Rechte; ein Administrator gibt sie frei.

use crate::audit::{self, Outcome};
use crate::authz;
use crate::error::{ApiError, ApiResult};
use crate::extract::{Authed, ClientIp, CsrfAuthed};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use ldap3::{dn_escape, LdapConnAsync, LdapConnSettings};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

const SETTING_KEY: &str = "ldap";
const TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Stored {
    pub enabled: bool,
    /// `ldaps` (TLS von Anfang an, Port 636) oder `starttls` (Port 389, dann TLS).
    pub security: String,
    /// `host` oder `host:port`, ohne Schema.
    pub server: String,
    /// Muster mit `{username}`, z. B. `uid={username},ou=people,dc=firma,dc=de`.
    pub bind_pattern: String,
    pub name: String,
    /// `pending` (Standard), `viewer` oder `reject`.
    pub new_account: String,
}

pub async fn load(st: &AppState) -> Option<Stored> {
    let v: Option<Value> = sqlx::query_scalar("SELECT value FROM settings WHERE key = $1")
        .bind(SETTING_KEY)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten();
    v.and_then(|v| serde_json::from_value(v).ok())
}

fn url_of(s: &Stored) -> String {
    let scheme = if s.security == "starttls" {
        "ldap"
    } else {
        "ldaps"
    };
    format!("{scheme}://{}", s.server)
}

/// Host (ohne Port) und optional Port prüfen: nur Buchstaben, Ziffern, Punkt, Bindestrich; IPv6 in `[...]`.
fn valid_server(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !s.starts_with('[') || h.ends_with(']') => (h, Some(p)),
        _ => (s, None),
    };
    if let Some(p) = port {
        if p.parse::<u16>().map_or(true, |n| n == 0) {
            return false;
        }
    }
    let inner = host.trim_start_matches('[').trim_end_matches(']');
    !inner.is_empty()
        && inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

fn valid_pattern(p: &str) -> bool {
    p.len() <= 300
        && p.matches("{username}").count() == 1
        && !p.chars().any(char::is_control)
        && p.contains('=')
}

/// Bind-DN aus dem Muster; Benutzername maskiert (RFC 4514).
pub fn dn_for(pattern: &str, username: &str) -> String {
    pattern.replace("{username}", &dn_escape(username))
}

async fn connect(s: &Stored) -> Result<(LdapConnAsync, ldap3::Ldap), String> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(TIMEOUT)
        .set_starttls(s.security == "starttls");
    LdapConnAsync::with_settings(settings, &url_of(s))
        .await
        .map_err(|e| format!("Verbindung fehlgeschlagen: {}", short(&e.to_string())))
}

/// Fehlertext ohne Zugangsdaten kürzen.
fn short(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(160).collect()
}

/// Bind mit den Zugangsdaten des Benutzers. `Ok(true)` = Passwort stimmt.
async fn bind(s: &Stored, username: &str, password: &str) -> Result<bool, String> {
    let (conn, mut ldap) = connect(s).await?;
    ldap3::drive!(conn);
    let res = tokio::time::timeout(
        TIMEOUT,
        ldap.simple_bind(&dn_for(&s.bind_pattern, username), password),
    )
    .await
    .map_err(|_| "Zeitüberschreitung".to_owned())?
    .map_err(|e| short(&e.to_string()))?;
    let _ = ldap.unbind().await;
    // 49 = invalidCredentials: normaler Fehlschlag. Alles andere Nicht-Erfolgreiche ist ein Serverproblem.
    match res.rc {
        0 => Ok(true),
        49 => Ok(false),
        rc => Err(format!("LDAP-Antwort {rc}")),
    }
}

/// Wird von der Anmeldung nach dem lokalen Versuch gerufen. `Ok(Some(id))` = angemeldet.
pub async fn try_login(
    st: &AppState,
    username: &str,
    password: &str,
    ip: &str,
) -> ApiResult<Option<i64>> {
    let Some(cfg) = load(st).await.filter(|c| c.enabled) else {
        return Ok(None);
    };
    // Leere Passwörter nie senden; Namen mit Steuerzeichen sind kein gültiger LDAP-Benutzername.
    if password.is_empty() || username.is_empty() || username.chars().any(char::is_control) {
        return Ok(None);
    }
    // Ein anderes Konto (lokal, OIDC) mit diesem Namen hat Vorrang: LDAP kann es nie übernehmen.
    let existing: Option<(i64, String, String, bool)> = sqlx::query_as(
        "SELECT id, auth_kind, status, password_login_disabled FROM admin_users WHERE username = $1 AND deleted_at IS NULL",
    )
    .bind(username)
    .fetch_optional(&st.pool)
    .await?;
    if let Some((_, kind, _, _)) = &existing {
        if kind != "ldap" {
            return Ok(None);
        }
    }
    if existing.as_ref().is_some_and(|e| e.3) {
        return Ok(None);
    }
    let ok = match bind(&cfg, username, password).await {
        Ok(v) => v,
        Err(why) => {
            tracing::warn!("LDAP: {why}");
            audit::record(
                &st.pool,
                None,
                username,
                "login.ldap_error",
                None,
                Outcome::Failed,
                ip,
            )
            .await;
            return Ok(None);
        }
    };
    if !ok {
        return Ok(None);
    }
    if let Some((id, _, status, _)) = existing {
        return match status.as_str() {
            "active" => Ok(Some(id)),
            "pending" => Err(ApiError::Forbidden(
                "Dein Konto wartet auf die Freigabe durch einen Administrator",
            )),
            _ => Ok(None),
        };
    }
    if cfg.new_account == "reject" {
        return Err(ApiError::Forbidden(
            "Für dich wird kein neues Konto angelegt",
        ));
    }
    let status = if cfg.new_account == "viewer" {
        "active"
    } else {
        "pending"
    };
    let name: String = username.chars().take(60).collect();
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO admin_users (username, display_name, auth_kind, role, status) VALUES ($1, $2, 'ldap', 'viewer', $3) \
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(username)
    .bind(&name)
    .bind(status)
    .fetch_optional(&st.pool)
    .await?;
    let Some(id) = id else {
        return Ok(None);
    };
    audit::record(
        &st.pool,
        Some(id),
        "ldap",
        "user.created_by_ldap",
        Some(&name),
        Outcome::Ok,
        ip,
    )
    .await;
    if status == "active" {
        Ok(Some(id))
    } else {
        Err(ApiError::Forbidden(
            "Dein Konto wurde angelegt und wartet auf die Freigabe durch einen Administrator",
        ))
    }
}

fn view(s: &Stored) -> Value {
    json!({
        "enabled": s.enabled,
        "security": if s.security == "starttls" { "starttls" } else { "ldaps" },
        "server": s.server,
        "bind_pattern": s.bind_pattern,
        "name": s.name,
        "new_account": match s.new_account.as_str() { "viewer" => "viewer", "reject" => "reject", _ => "pending" },
    })
}

pub async fn settings_get(
    _: Authed<authz::p::OidcManage>,
    State(st): State<AppState>,
) -> ApiResult<Json<Value>> {
    Ok(Json(view(&load(&st).await.unwrap_or_default())))
}

#[derive(Deserialize)]
pub struct Body {
    enabled: bool,
    security: String,
    server: String,
    bind_pattern: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    new_account: String,
}

pub async fn settings_put(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::OidcManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(b): Json<Body>,
) -> ApiResult<Json<Value>> {
    let bad = |m: &str| ApiError::BadRequest(m.to_owned());
    let server = b.server.trim().to_owned();
    let pattern = b.bind_pattern.trim().to_owned();
    if b.enabled || !server.is_empty() {
        if !valid_server(&server) {
            return Err(bad("Server: Host oder Host:Port, ohne ldap://"));
        }
        if !valid_pattern(&pattern) {
            return Err(bad("Muster: muss genau einmal {username} enthalten, z. B. uid={username},ou=people,dc=firma,dc=de"));
        }
    }
    let name: String = b
        .name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    let stored = Stored {
        enabled: b.enabled,
        security: if b.security == "starttls" {
            "starttls".into()
        } else {
            "ldaps".into()
        },
        server,
        bind_pattern: pattern,
        name,
        new_account: match b.new_account.as_str() {
            "viewer" | "reject" => b.new_account.clone(),
            _ => "pending".into(),
        },
    };
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(SETTING_KEY)
    .bind(serde_json::to_value(&stored).map_err(anyhow::Error::from)?)
    .execute(&st.pool)
    .await?;
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "ldap.settings_changed",
        None,
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(Json(view(&stored)))
}

/// Verbindungstest: Verbindung und TLS-Zertifikat prüfen. Es wird kein Benutzer gebunden.
pub async fn settings_test(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::OidcManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
) -> ApiResult<Json<Value>> {
    st.limiter
        .check(
            &format!("ldap-test:{}", me.id),
            10,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let Some(cfg) = load(&st).await.filter(|c| !c.server.is_empty()) else {
        return Err(ApiError::BadRequest(
            "LDAP ist nicht eingerichtet (zuerst speichern)".into(),
        ));
    };
    let result = match connect(&cfg).await {
        Ok((conn, mut ldap)) => {
            ldap3::drive!(conn);
            let _ = ldap.unbind().await;
            Ok(())
        }
        Err(e) => Err(e),
    };
    let (outcome, body) = match result {
        Ok(()) => (Outcome::Ok, json!({"ok": true, "url": url_of(&cfg)})),
        Err(m) => (Outcome::Failed, json!({"ok": false, "message": m})),
    };
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "ldap.test",
        None,
        outcome,
        &ip,
    )
    .await;
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_is_escaped_in_the_dn() {
        let p = "uid={username},ou=people,dc=firma,dc=de";
        assert_eq!(dn_for(p, "alice"), "uid=alice,ou=people,dc=firma,dc=de");
        // Kein Ausbrechen aus dem RDN: Komma, Gleichheitszeichen, Plus, Backslash werden maskiert.
        let evil = dn_for(p, "x,ou=admins,dc=evil");
        // ldap3 maskiert als hex (\2c, \3d ...); entscheidend: im Wert bleibt weder Komma noch Gleichheitszeichen.
        let value = evil
            .strip_suffix(",ou=people,dc=firma,dc=de")
            .unwrap()
            .strip_prefix("uid=")
            .unwrap();
        assert!(!value.contains(',') && !value.contains('='), "{evil}");
    }

    #[test]
    fn server_and_pattern_validation() {
        for ok in [
            "ldap.firma.de",
            "ldap.firma.de:636",
            "10.0.0.5:389",
            "[::1]:636",
        ] {
            assert!(valid_server(ok), "{ok}");
        }
        for bad in ["", "ldap://x", "a b", "x:0", "x:99999", "x/y", "x?y"] {
            assert!(!valid_server(bad), "{bad}");
        }
        assert!(valid_pattern("uid={username},dc=a"));
        assert!(!valid_pattern("uid=bob,dc=a"));
        assert!(!valid_pattern("uid={username},cn={username}"));
        assert!(!valid_pattern("{username}"));
    }
}
