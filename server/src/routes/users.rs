//! Benutzerverwaltung (Recht `users.manage`) und Aktivitätsprotokoll (`audit.read`).
//!
//! Schutzregeln (alle serverseitig, in einer Transaktion mit Zeilensperre auf die aktiven Administratoren):
//! * der letzte aktive Administrator und der letzte aktive LOKALE Administrator bleiben erhalten,
//! * niemand ändert die eigene Rolle, sperrt oder löscht sich selbst über die Verwaltung,
//! * Administratorrechte vergeben oder entziehen verlangt das eigene Passwort (bei OIDC-Konten eine frische Anmeldung),
//! * Rollenwechsel, Sperren, Löschen und Passwort-Zurücksetzen beenden alle Sitzungen des Benutzers sofort.
//!
//! Das Einmalpasswort steht nur in der Antwort auf Anlegen/Zurücksetzen und wird nie gespeichert oder geloggt.

use crate::audit::{self, Outcome};
use crate::authz::{self, Permission, Role, ROLES};
use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, Authed, ClientIp, CsrfAuthed};
use crate::security;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use std::time::Duration;

const MAX_NAME_CHARS: usize = 60;
/// Frische Anmeldung für OIDC-Konten bei sensiblen Aktionen.
const FRESH_LOGIN_SECS: i64 = 300;

#[derive(Serialize, sqlx::FromRow)]
struct UserRow {
    id: i64,
    username: String,
    display_name: String,
    email: Option<String>,
    auth_kind: String,
    role: String,
    status: String,
    created_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
    has_avatar: bool,
    oidc_linked: bool,
    /// Vom OIDC-Anbieter gewünschte Rolle, die ein Administrator noch bestätigen muss.
    requested_role: Option<String>,
    /// Eigene Rechteauswahl (NULL = folgt der Rolle). Ausgegeben wird nur die wirksame Menge (`view`).
    #[serde(skip)]
    permissions: Option<Vec<String>>,
}

const SELECT_USER: &str = "SELECT id, username, display_name, email, auth_kind, role, status, created_at, last_login_at, \
    (avatar IS NOT NULL) AS has_avatar, (oidc_subject IS NOT NULL OR auth_kind = 'ldap') AS oidc_linked, requested_role, permissions FROM admin_users";

fn view(u: &UserRow, me: i64) -> Value {
    let mut v = serde_json::to_value(u).unwrap_or(Value::Null);
    v["is_self"] = json!(u.id == me);
    v["role_title"] = json!(Role::parse(&u.role).map(Role::title));
    v["permissions"] = json!(eff_of(u).iter().map(|p| p.name()).collect::<Vec<_>>());
    v["custom_permissions"] = json!(u.permissions.is_some());
    v
}

/// Wirksame Rechte eines Kontos (unbekannte Rolle = keine Rechte).
fn eff_of(u: &UserRow) -> Vec<Permission> {
    Role::parse(&u.role).map_or_else(Vec::new, |r| authz::effective(r, u.permissions.as_deref()))
}

/// Alle Rollen mit ihren Rechten, gruppiert für die Rechtevorschau der Oberfläche. Quelle der Wahrheit ist der Server.
pub async fn roles(_: Authed<authz::p::UsersManage>) -> Json<Value> {
    use Permission::*;
    // (Gruppe, [(Recht, Beschriftung, Erklärung)]): Quelle der Wahrheit für die Oberfläche (Schalter und Vorlagen).
    type Entry = (Permission, &'static str, &'static str);
    let groups: [(&str, &[Entry]); 6] = [
        (
            "Hosts",
            &[
                (HostsRead, "Hosts ansehen", "Hostliste, Details und Verlauf lesen."),
                (HostsWrite, "Hosts anlegen und ändern", "Neue Hosts anlegen."),
                (HostsDelete, "Hosts löschen", "Einen Host samt Verlauf dauerhaft entfernen."),
                (HostsRun, "Daten jetzt abrufen", "Agents bitten, sofort neue Daten zu senden."),
            ],
        ),
        (
            "Agents",
            &[(AgentsTokens, "Agent-Token erneuern", "Das Token eines Agents ersetzen; das alte gilt sofort nicht mehr.")],
        ),
        (
            "CVEs und Quellen",
            &[
                (CvesRead, "CVEs ansehen", "CVE-Liste und Details lesen."),
                (CvesWatch, "Beobachten und manuell prüfen", "CVEs auf die Beobachtungsliste setzen und manuell prüfen."),
                (SourcesRead, "Quellen-Zustand ansehen", "Zustand und Läufe der CVE-Quellen lesen."),
                (SourcesWrite, "Quellen anlegen und ändern", "Quellen anlegen, ein- und ausschalten, ändern, löschen."),
                (SourcesRun, "Quellen abrufen", "Einen Abruf einer Quelle starten."),
                (SourcesSecrets, "Quellen-Schlüssel setzen", "API-Schlüssel einer Quelle setzen oder löschen (lesen kann sie niemand)."),
            ],
        ),
        (
            "Benachrichtigungen",
            &[
                (ChannelsRead, "Kanäle ansehen", "Zustand der Benachrichtigungskanäle lesen."),
                (ChannelsWrite, "Kanäle ändern", "Kanäle ein- und ausschalten und konfigurieren."),
                (ChannelsTest, "Testnachricht senden", "Eine Testnachricht über einen Kanal senden."),
                (ChannelsSecrets, "Kanal-Geheimnisse setzen", "Tokens und Webhooks eines Kanals setzen oder löschen (lesen kann sie niemand)."),
            ],
        ),
        (
            "Einstellungen",
            &[
                (SettingsRead, "Einstellungen ansehen", "Einstellungen und Zeitpläne lesen."),
                (SettingsWrite, "Einstellungen und Zeitpläne ändern", "Einstellungen und Zeitpläne ändern."),
            ],
        ),
        (
            "Benutzer",
            &[
                (UsersManage, "Benutzer verwalten", "Benutzer anlegen, ändern, sperren, löschen und Rechte vergeben, aber nur bis zu den eigenen Rechten."),
                (OidcManage, "OIDC-Anmeldung einrichten", "Anbieter, Zugangsdaten und Rollenzuordnung für OIDC."),
                (AuditRead, "Aktivitätsprotokoll lesen", "Das Aktivitätsprotokoll einsehen."),
            ],
        ),
    ];
    Json(json!({
        "roles": ROLES.iter().map(|r| json!({
            "key": r.key(), "title": r.title(),
            "permissions": authz::close(&r.permissions()).iter().map(|p| p.name()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "groups": groups.iter().map(|(g, ps)| json!({
            "title": g,
            "permissions": ps.iter().map(|(p, label, desc)| json!({
                "name": p.name(), "label": label, "description": desc,
                "requires": p.requires().iter().map(|r| r.name()).collect::<Vec<_>>(),
                "sensitive": p.is_sensitive(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    }))
}

pub async fn list(
    Authed(me, _): Authed<authz::p::UsersManage>,
    State(st): State<AppState>,
) -> ApiResult<Json<Value>> {
    let rows: Vec<UserRow> = sqlx::query_as(&format!(
        "{SELECT_USER} WHERE deleted_at IS NULL ORDER BY lower(display_name)"
    ))
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(json!({
        "users": rows.iter().map(|u| view(u, me.id)).collect::<Vec<_>>(),
        "pending": pending_count(&st.pool).await?,
    })))
}

pub(super) fn check_name(raw: &str) -> ApiResult<String> {
    let n = raw.trim();
    let len = n.chars().count();
    if len == 0 || len > MAX_NAME_CHARS {
        return Err(ApiError::BadRequest(format!(
            "Name: 1 bis {MAX_NAME_CHARS} Zeichen"
        )));
    }
    if n.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "Name: keine Steuerzeichen oder Zeilenumbrüche".into(),
        ));
    }
    Ok(n.to_owned())
}

fn check_email(raw: &str) -> ApiResult<Option<String>> {
    let e = raw.trim();
    if e.is_empty() {
        return Ok(None);
    }
    if e.len() > 254 || e.chars().any(|c| c.is_control() || c.is_whitespace()) || !e.contains('@') {
        return Err(ApiError::BadRequest("E-Mail: ungültige Adresse".into()));
    }
    Ok(Some(e.to_owned()))
}

fn role_of(raw: &str) -> ApiResult<Role> {
    Role::parse(raw).ok_or_else(|| ApiError::BadRequest("Unbekannte Rolle".into()))
}

/// Eigenes Passwort bzw. frische Anmeldung (OIDC) für Administratorrechte verlangen.
pub(super) async fn reauth(st: &AppState, me: &Admin, password: Option<&str>) -> ApiResult<()> {
    st.limiter
        .check(&format!("reauth:{}", me.id), 5, Duration::from_secs(600))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    if matches!(me.auth_kind.as_str(), "oidc" | "ldap") {
        if (Utc::now() - me.session_created).num_seconds() > FRESH_LOGIN_SECS {
            return Err(ApiError::Forbidden(
                "Bitte melde dich neu an (höchstens 5 Minuten alt)",
            ));
        }
        return Ok(());
    }
    let Some(pw) = password.filter(|p| !p.is_empty() && p.len() <= 256) else {
        return Err(ApiError::Forbidden(
            "Für Administratorrechte wird dein Passwort benötigt",
        ));
    };
    let hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM admin_users WHERE id = $1")
            .bind(me.id)
            .fetch_one(&st.pool)
            .await?;
    let pw = pw.to_owned();
    let ok = match hash {
        Some(h) => tokio::task::spawn_blocking(move || security::verify_password(&h, &pw))
            .await
            .map_err(anyhow::Error::from)?,
        None => false,
    };
    if ok {
        Ok(())
    } else {
        Err(ApiError::Forbidden("Passwort ist falsch"))
    }
}

/// Sperrt die aktiven Benutzer mit dem Recht `users.manage` (Reihenfolge nach ID, damit gleichzeitige Anfragen sich nicht
/// verklemmen) und liefert (id, Anmeldeart). Wer verwalten darf, hängt von den wirksamen Rechten ab, nicht von der Rolle.
async fn lock_admins(tx: &mut PgConnection) -> sqlx::Result<Vec<(i64, String)>> {
    let rows: Vec<(i64, String, String, Option<Vec<String>>)> = sqlx::query_as(
        "SELECT id, auth_kind, role, permissions FROM admin_users WHERE status = 'active' AND deleted_at IS NULL ORDER BY id FOR UPDATE",
    )
    .fetch_all(tx)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, _, role, perms)| {
            Role::parse(role).is_some_and(|r| {
                authz::effective(r, perms.as_deref()).contains(&Permission::UsersManage)
            })
        })
        .map(|(id, kind, _, _)| (id, kind))
        .collect())
}

/// Nach der Änderung muss mindestens ein aktiver Benutzer mit `users.manage` und davon mindestens einer lokal bleiben.
fn keeps_admins(admins: &[(i64, String)], target: i64) -> bool {
    let rest: Vec<_> = admins.iter().filter(|a| a.0 != target).collect();
    !rest.is_empty() && rest.iter().any(|a| a.1 == "local")
}

/// Ist das Konto ein aktiver Verwalter (hat `users.manage`)?
fn is_manager(admins: &[(i64, String)], id: i64) -> bool {
    admins.iter().any(|a| a.0 == id)
}

/// Rechteausweitung verhindern: wer ein Konto ändert, sperrt, löscht, freigibt oder dessen Passwort zurücksetzt, muss
/// alle Rechte dieses Kontos selbst haben (sonst könnte ein Verwalter einen stärkeren Benutzer übernehmen).
fn require_covers(me: &Admin, t: &UserRow) -> ApiResult<()> {
    let missing: Vec<&str> = eff_of(t)
        .iter()
        .filter(|p| !me.permissions.contains(p))
        .map(|p| p.name())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "Dieses Konto hat Rechte, die du selbst nicht hast; du darfst es nicht verwalten",
        ))
    }
}

/// Ergebnis einer Rechtevergabe: was gespeichert wird (`None` = folgt der Rolle) und die wirksame Menge.
struct Grant {
    stored: Option<Vec<String>>,
    effective: Vec<Permission>,
}

/// Prüft eine Vergabe: bekannte Namen, Voraussetzungen erfüllt (Schreiben setzt Lesen voraus) und nur Rechte, die der
/// Vergebende selbst hat. Ohne `custom` gilt die Vorlage der Rolle.
fn resolve_grant(me: &Admin, role: Role, custom: Option<&[String]>) -> ApiResult<Grant> {
    let grant = match custom {
        None => Grant {
            stored: None,
            effective: authz::effective(role, None),
        },
        Some(names) => {
            let mut parsed = Vec::new();
            for n in names {
                let p = Permission::parse(n)
                    .ok_or_else(|| ApiError::BadRequest(format!("Unbekanntes Recht: {n}")))?;
                if !parsed.contains(&p) {
                    parsed.push(p);
                }
            }
            for p in &parsed {
                if let Some(r) = p.requires().iter().find(|r| !parsed.contains(r)) {
                    return Err(ApiError::BadRequest(format!(
                        "Das Recht {} setzt {} voraus",
                        p.name(),
                        r.name()
                    )));
                }
            }
            let effective = authz::close(&parsed);
            Grant {
                stored: Some(effective.iter().map(|p| p.name().to_owned()).collect()),
                effective,
            }
        }
    };
    if !authz::is_subset(&grant.effective, &me.permissions) {
        return Err(ApiError::Forbidden(
            "Du kannst nur Rechte vergeben, die du selbst hast",
        ));
    }
    Ok(grant)
}

/// Mindestens eines der Rechte, deren Vergabe das eigene Passwort verlangt, ist in `a` aber nicht in `b`.
fn gains_sensitive(a: &[Permission], b: &[Permission]) -> bool {
    a.iter().any(|p| p.is_sensitive() && !b.contains(p))
}

async fn target(tx: &mut PgConnection, id: i64) -> ApiResult<UserRow> {
    sqlx::query_as::<_, UserRow>(&format!(
        "{SELECT_USER} WHERE id = $1 AND deleted_at IS NULL FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(tx)
    .await?
    .ok_or(ApiError::NotFound)
}

async fn end_sessions(tx: &mut PgConnection, id: i64) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1")
        .bind(id)
        .execute(tx)
        .await?;
    Ok(())
}

fn map_unique(e: sqlx::Error) -> ApiError {
    if e.as_database_error()
        .and_then(|d| d.constraint())
        .is_some_and(|c| {
            c.starts_with("admin_display_name")
                || c.contains("username")
                || c.contains("oidc_identity")
        })
    {
        return ApiError::Conflict(
            "Dieser Name oder diese OIDC-Identität ist schon vergeben".into(),
        );
    }
    ApiError::from(e)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBody {
    display_name: String,
    /// `local` oder `oidc`.
    auth_kind: String,
    email: Option<String>,
    role: String,
    /// Eigene Rechteauswahl statt der Vorlage der Rolle; nie mehr, als der Vergebende selbst hat.
    permissions: Option<Vec<String>>,
    /// Nur OIDC: `sub` des Anbieters (Verknüpfung nur ausdrücklich durch einen Administrator, nie per E-Mail).
    oidc_subject: Option<String>,
    /// Eigenes Passwort, nötig bei der Rolle Administrator.
    confirm_password: Option<String>,
}

pub async fn create(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(b): Json<CreateBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let name = check_name(&b.display_name)?;
    let email = match &b.email {
        Some(e) => check_email(e)?,
        None => None,
    };
    let role = role_of(&b.role)?;
    if super::has_nul(&name) {
        return Err(ApiError::BadRequest("ungültige Eingabe".into()));
    }
    let grant = resolve_grant(&me, role, b.permissions.as_deref())?;
    if grant.effective.iter().any(|p| p.is_sensitive()) {
        reauth(&st, &me, b.confirm_password.as_deref()).await?;
    }
    let (id, initial) = match b.auth_kind.as_str() {
        "local" => {
            let pw = crate::admin::random_password();
            let p2 = pw.clone();
            let hash = tokio::task::spawn_blocking(move || security::hash_password(&p2))
                .await
                .map_err(anyhow::Error::from)??;
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO admin_users (username, display_name, email, auth_kind, role, status, password_hash, must_change_password, created_by, permissions) \
                 VALUES ($1, $1, $2, 'local', $3, 'active', $4, true, $5, $6) RETURNING id",
            )
            .bind(&name)
            .bind(&email)
            .bind(role.key())
            .bind(hash)
            .bind(me.id)
            .bind(&grant.stored)
            .fetch_one(&st.pool)
            .await
            .map_err(map_unique)?;
            (id, Some(pw))
        }
        "oidc" => {
            let issuer = crate::routes::oidc::configured_issuer(&st)
                .await
                .ok_or_else(|| ApiError::BadRequest("OIDC ist nicht eingerichtet".into()))?;
            let sub =
                b.oidc_subject.as_deref().map(str::trim).filter(|s| {
                    !s.is_empty() && s.len() <= 255 && !s.chars().any(char::is_control)
                });
            let Some(sub) = sub else {
                return Err(ApiError::BadRequest(
                    "OIDC-Subject (sub) des Anbieters angeben".into(),
                ));
            };
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO admin_users (username, display_name, email, auth_kind, role, status, oidc_issuer, oidc_subject, created_by, permissions) \
                 VALUES ($1, $1, $2, 'oidc', $3, 'active', $4, $5, $6, $7) RETURNING id",
            )
            .bind(&name)
            .bind(&email)
            .bind(role.key())
            .bind(issuer)
            .bind(sub)
            .bind(me.id)
            .bind(&grant.stored)
            .fetch_one(&st.pool)
            .await
            .map_err(map_unique)?;
            (id, None)
        }
        _ => return Err(ApiError::BadRequest("Anmeldeart: lokal oder OIDC".into())),
    };
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "user.created",
        Some(&name),
        Outcome::Ok,
        &ip,
    )
    .await;
    let row: UserRow = sqlx::query_as(&format!("{SELECT_USER} WHERE id = $1"))
        .bind(id)
        .fetch_one(&st.pool)
        .await?;
    let mut out = json!({ "user": view(&row, me.id) });
    if let Some(pw) = initial {
        // Einmalig: nur in dieser Antwort.
        out["initial_password"] = json!(pw);
    }
    Ok((StatusCode::CREATED, Json(out)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateBody {
    display_name: Option<String>,
    email: Option<String>,
    role: Option<String>,
    /// Eigene Rechteauswahl (ersetzt die Vorlage); `use_template = true` kehrt zur Vorlage der Rolle zurück.
    permissions: Option<Vec<String>>,
    use_template: Option<bool>,
    /// Name des Benutzers zur Bestätigung einer Rollenänderung.
    confirm_name: Option<String>,
    confirm_password: Option<String>,
}

pub async fn update(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
    Json(b): Json<UpdateBody>,
) -> ApiResult<Json<Value>> {
    let name = match &b.display_name {
        Some(n) => Some(check_name(n)?),
        None => None,
    };
    let email = match &b.email {
        Some(e) => Some(check_email(e)?),
        None => None,
    };
    let new_role = match &b.role {
        Some(r) => Some(role_of(r)?),
        None => None,
    };
    let mut tx = st.pool.begin().await?;
    let admins = lock_admins(&mut tx).await?;
    let t = target(&mut tx, id).await?;
    require_covers(&me, &t)?;
    let old_role = Role::parse(&t.role).ok_or(ApiError::NotFound)?;
    let old_eff = eff_of(&t);
    let role_changes = new_role.is_some_and(|r| r != old_role);
    // Rechte ändern sich bei Rollenwechsel (zurück auf die Vorlage), eigener Auswahl oder ausdrücklich "Vorlage".
    let wants_rights = role_changes || b.permissions.is_some() || b.use_template == Some(true);
    let grant = if wants_rights {
        Some(resolve_grant(
            &me,
            new_role.unwrap_or(old_role),
            b.permissions.as_deref(),
        )?)
    } else {
        None
    };
    if let Some(g) = &grant {
        if t.id == me.id {
            return Err(ApiError::Forbidden(
                "Du kannst deine eigene Rolle und deine Rechte nicht ändern",
            ));
        }
        if b.confirm_name.as_deref().map(str::trim) != Some(t.display_name.as_str()) {
            return Err(ApiError::BadRequest(
                "Zur Bestätigung den Namen des Benutzers eingeben".into(),
            ));
        }
        if is_manager(&admins, t.id)
            && !g.effective.contains(&Permission::UsersManage)
            && !keeps_admins(&admins, t.id)
        {
            return Err(ApiError::Conflict(
                "Der letzte (lokale) Administrator kann nicht herabgestuft werden".into(),
            ));
        }
        // Rollenwechsel und jede Vergabe oder jeder Entzug sensibler Rechte verlangen Passwort bzw. frische Anmeldung.
        if role_changes
            || gains_sensitive(&g.effective, &old_eff)
            || gains_sensitive(&old_eff, &g.effective)
        {
            // Passwortprüfung außerhalb der Sperre wäre sauberer, ist aber kurz; die Sperre verhindert Rennen.
            reauth(&st, &me, b.confirm_password.as_deref()).await?;
        }
    }
    if let Some(n) = &name {
        sqlx::query("UPDATE admin_users SET display_name = $2 WHERE id = $1")
            .bind(id)
            .bind(n)
            .execute(&mut *tx)
            .await
            .map_err(map_unique)?;
    }
    if let Some(e) = &email {
        sqlx::query("UPDATE admin_users SET email = $2 WHERE id = $1")
            .bind(id)
            .bind(e)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(g) = &grant {
        let r = new_role.unwrap_or(old_role);
        sqlx::query("UPDATE admin_users SET role = $2, permissions = $3 WHERE id = $1")
            .bind(id)
            .bind(r.key())
            .bind(&g.stored)
            .execute(&mut *tx)
            .await?;
        end_sessions(&mut tx, id).await?;
    }
    tx.commit().await?;
    let action = if role_changes {
        "user.role_changed"
    } else if grant.is_some() {
        "user.permissions_changed"
    } else {
        "user.updated"
    };
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        action,
        Some(&t.display_name),
        Outcome::Ok,
        &ip,
    )
    .await;
    let row: UserRow = sqlx::query_as(&format!("{SELECT_USER} WHERE id = $1"))
        .bind(id)
        .fetch_one(&st.pool)
        .await?;
    Ok(Json(view(&row, me.id)))
}

/// Sperren (`lock = true`) oder entsperren.
async fn set_locked(
    st: &AppState,
    me: &Admin,
    ip: &str,
    id: i64,
    lock: bool,
) -> ApiResult<Json<Value>> {
    if lock && id == me.id {
        return Err(ApiError::Forbidden("Du kannst dich nicht selbst sperren"));
    }
    let mut tx = st.pool.begin().await?;
    let admins = lock_admins(&mut tx).await?;
    let t = target(&mut tx, id).await?;
    require_covers(me, &t)?;
    if lock {
        if is_manager(&admins, t.id) && t.status == "active" && !keeps_admins(&admins, t.id) {
            return Err(ApiError::Conflict(
                "Der letzte (lokale) Administrator kann nicht gesperrt werden".into(),
            ));
        }
        sqlx::query("UPDATE admin_users SET status = 'locked' WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        end_sessions(&mut tx, id).await?;
    } else {
        if t.status != "locked" {
            return Err(ApiError::Conflict(
                "Nur gesperrte Konten lassen sich entsperren (ausstehende werden freigegeben)"
                    .into(),
            ));
        }
        sqlx::query("UPDATE admin_users SET status = 'active' WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let action = if lock { "user.locked" } else { "user.unlocked" };
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        action,
        Some(&t.display_name),
        Outcome::Ok,
        ip,
    )
    .await;
    let row: UserRow = sqlx::query_as(&format!("{SELECT_USER} WHERE id = $1"))
        .bind(id)
        .fetch_one(&st.pool)
        .await?;
    Ok(Json(view(&row, me.id)))
}

pub async fn lock(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    set_locked(&st, &me, &ip, id, true).await
}

pub async fn unlock(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    set_locked(&st, &me, &ip, id, false).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    role: String,
    permissions: Option<Vec<String>>,
    confirm_password: Option<String>,
}

/// Gibt ein ausstehendes (OIDC-)Konto frei und legt die Rolle fest. Ein Konto ohne (Issuer, Subject) bleibt unverknüpft und
/// kann nicht freigegeben werden (die E-Mail-Adresse ist kein Schlüssel).
pub async fn approve(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
    Json(b): Json<ApproveBody>,
) -> ApiResult<Json<Value>> {
    let role = role_of(&b.role)?;
    let grant = resolve_grant(&me, role, b.permissions.as_deref())?;
    if grant.effective.iter().any(|p| p.is_sensitive()) {
        reauth(&st, &me, b.confirm_password.as_deref()).await?;
    }
    let mut tx = st.pool.begin().await?;
    let t = target(&mut tx, id).await?;
    require_covers(&me, &t)?;
    if t.status != "pending" {
        return Err(ApiError::Conflict(
            "Das Konto wartet nicht auf Freigabe".into(),
        ));
    }
    if !t.oidc_linked {
        return Err(ApiError::Conflict(
            "Das Konto ist nicht mit OIDC oder LDAP verknüpft und kann nicht freigegeben werden"
                .into(),
        ));
    }
    sqlx::query(
        "UPDATE admin_users SET status = 'active', role = $2, permissions = $3 WHERE id = $1",
    )
    .bind(id)
    .bind(role.key())
    .bind(&grant.stored)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "user.approved",
        Some(&t.display_name),
        Outcome::Ok,
        &ip,
    )
    .await;
    let row: UserRow = sqlx::query_as(&format!("{SELECT_USER} WHERE id = $1"))
        .bind(id)
        .fetch_one(&st.pool)
        .await?;
    Ok(Json(view(&row, me.id)))
}

/// Neues Einmalpasswort für ein lokales Konto; alle Sitzungen des Benutzers enden.
pub async fn reset_password(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    if id == me.id {
        return Err(ApiError::Forbidden(
            "Dein eigenes Passwort änderst du unter Konto",
        ));
    }
    let mut tx = st.pool.begin().await?;
    let t = target(&mut tx, id).await?;
    require_covers(&me, &t)?;
    if t.auth_kind != "local" {
        return Err(ApiError::Conflict(
            "Nur lokale Konten haben ein Passwort".into(),
        ));
    }
    let pw = crate::admin::random_password();
    let p2 = pw.clone();
    let hash = tokio::task::spawn_blocking(move || security::hash_password(&p2))
        .await
        .map_err(anyhow::Error::from)??;
    sqlx::query(
        "UPDATE admin_users SET password_hash = $2, must_change_password = true WHERE id = $1",
    )
    .bind(id)
    .bind(hash)
    .execute(&mut *tx)
    .await?;
    end_sessions(&mut tx, id).await?;
    tx.commit().await?;
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "user.password_reset",
        Some(&t.display_name),
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(Json(json!({ "initial_password": pw })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteBody {
    confirm_name: String,
    confirm_password: Option<String>,
}

/// Weiches Löschen: das Konto wird gesperrt und anonymisiert (Name, E-Mail, OIDC-Identität, Passwort, Profilbild entfernt),
/// damit das Aktivitätsprotokoll gültige Verweise behält und Namen/Identitäten wieder vergeben werden können.
pub async fn remove(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::UsersManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<i64>,
    Json(b): Json<DeleteBody>,
) -> ApiResult<StatusCode> {
    if id == me.id {
        return Err(ApiError::Forbidden("Du kannst dich nicht selbst löschen"));
    }
    let mut tx = st.pool.begin().await?;
    let admins = lock_admins(&mut tx).await?;
    let t = target(&mut tx, id).await?;
    if b.confirm_name.trim() != t.display_name {
        return Err(ApiError::BadRequest(
            "Zur Bestätigung den Namen des Benutzers eingeben".into(),
        ));
    }
    require_covers(&me, &t)?;
    if eff_of(&t).iter().any(|p| p.is_sensitive()) {
        reauth(&st, &me, b.confirm_password.as_deref()).await?;
    }
    if is_manager(&admins, t.id) && t.status == "active" && !keeps_admins(&admins, t.id) {
        return Err(ApiError::Conflict(
            "Der letzte (lokale) Administrator kann nicht gelöscht werden".into(),
        ));
    }
    sqlx::query(
        "UPDATE admin_users SET deleted_at = now(), status = 'locked', role = 'viewer', permissions = NULL, username = 'geloescht-' || id::text, \
         display_name = 'gelöscht-' || id::text, email = NULL, oidc_issuer = NULL, oidc_subject = NULL, \
         password_hash = NULL, must_change_password = false, avatar = NULL, avatar_type = NULL, avatar_updated_at = NULL WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    end_sessions(&mut tx, id).await?;
    tx.commit().await?;
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "user.deleted",
        Some(&t.display_name),
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    action: Option<String>,
    actor: Option<String>,
    result: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct AuditRow {
    id: i64,
    at: DateTime<Utc>,
    actor_name: String,
    action: String,
    target: Option<String>,
    result: String,
    ip: Option<String>,
}

pub async fn audit_list(
    _: Authed<authz::p::AuditRead>,
    State(st): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let like = |s: &Option<String>| {
        s.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{}%", s.replace(['%', '_', '\\'], "")))
    };
    if q.result
        .as_deref()
        .is_some_and(|r| !["ok", "denied", "failed"].contains(&r))
    {
        return Err(ApiError::BadRequest(
            "result: ok, denied oder failed".into(),
        ));
    }
    let (action, actor) = (like(&q.action), like(&q.actor));
    let where_sql = "WHERE ($1::text IS NULL OR action ILIKE $1) AND ($2::text IS NULL OR actor_name ILIKE $2) AND ($3::text IS NULL OR result = $3)";
    let rows: Vec<AuditRow> = sqlx::query_as(&format!(
        "SELECT id, at, actor_name, action, target, result, ip FROM audit_log {where_sql} ORDER BY at DESC, id DESC LIMIT $4 OFFSET $5"
    ))
    .bind(&action)
    .bind(&actor)
    .bind(&q.result)
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.pool)
    .await?;
    let total: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM audit_log {where_sql}"))
        .bind(&action)
        .bind(&actor)
        .bind(&q.result)
        .fetch_one(&st.pool)
        .await?;
    Ok(Json(json!({ "entries": rows, "total": total })))
}

/// Anzahl der Konten, die auf Freigabe warten (Hinweis in der Benutzerliste).
pub async fn pending_count(pool: &PgPool) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "SELECT count(*) FROM admin_users WHERE status = 'pending' AND deleted_at IS NULL",
    )
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_admin_rules() {
        let a = |id, k: &str| (id, k.to_owned());
        assert!(!keeps_admins(&[a(1, "local")], 1), "einziger Administrator");
        assert!(keeps_admins(&[a(1, "local"), a(2, "local")], 1));
        assert!(
            !keeps_admins(&[a(1, "local"), a(2, "oidc")], 1),
            "es muss ein lokaler bleiben"
        );
        assert!(keeps_admins(&[a(1, "local"), a(2, "oidc")], 2));
        assert!(!keeps_admins(&[], 9));
    }

    #[test]
    fn names_and_emails_are_validated() {
        assert!(check_name("  Anna ").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name(&"x".repeat(61)).is_err());
        assert!(check_name("a\nb").is_err());
        assert!(check_email("").unwrap().is_none());
        assert!(check_email("a@b.example").unwrap().is_some());
        assert!(check_email("kein mail").is_err());
    }
}
