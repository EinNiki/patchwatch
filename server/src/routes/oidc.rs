//! OpenID Connect: Authorization-Code-Flow mit PKCE (S256), state (Cookie + Datenbank), nonce, Signaturprüfung des
//! ID-Tokens über das JWKS des Anbieters (siehe `crate::oidc`).
//!
//! Konten werden **nur** über (Issuer, `sub`) zugeordnet, nie über E-Mail-Adresse oder Namen. Ein unbekanntes Paar
//! ergibt standardmäßig ein Konto im Status "ausstehend" ohne Rechte; Administratorrechte vergibt der Anbieter nie
//! von allein: eine Hochstufung (Gruppen → Rolle) wartet auf die Bestätigung eines Administrators, eine
//! Herabstufung gilt sofort. Der Browser sieht bei jedem Fehler nur eine allgemeine Meldung; die Ursache (ein fester
//! Code, nie Tokens oder Geheimnisse) steht im Aktivitätsprotokoll.
use crate::audit::{self, Outcome};
use crate::authz::{self, Role};
use crate::error::{ApiError, ApiResult};
use crate::extract::{Authed, ClientIp, CsrfAuthed};
use crate::oidc::{self, Fail, Identity};
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
const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";

const SETTING_KEY: &str = "oidc";
/// Zusatzdaten der Verschlüsselung des Client-Secrets in der Datenbank.
const SECRET_AAD: &str = "oidc-client-secret";
/// Erlaubte Zielseiten nach der Anmeldung (erstes Pfadsegment).
const RETURN_SEGMENTS: [&str; 6] = [
    "hosts",
    "cves",
    "agents",
    "notifications",
    "settings",
    "users",
];

#[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct GroupRole {
    pub group: String,
    pub role: String,
}

/// In der UI gepflegte Einstellung (Tabelle `settings`); hat Vorrang vor den Umgebungsvariablen.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Stored {
    enabled: bool,
    issuer: String,
    client_id: String,
    /// Nur Altbestand/Ersatz, wenn `PATCHWATCH_PUBLIC_URL` fehlt.
    redirect_url: String,
    name: String,
    scopes: String,
    allowed_emails: Vec<String>,
    allowed_domains: Vec<String>,
    /// Client-Secret, verschlüsselt (XChaCha20-Poly1305, Base64).
    secret: Option<String>,
    group_claim: String,
    group_roles: Vec<GroupRole>,
    /// `pending` (Standard), `viewer` oder `reject`.
    new_account: String,
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
    group_claim: String,
    group_roles: Vec<GroupRole>,
    new_account: String,
}

fn rank(r: Role) -> u8 {
    match r {
        Role::Viewer => 0,
        Role::Operator => 1,
        Role::Admin => 2,
    }
}

impl Resolved {
    /// Höchste Rolle, die der Anbieter über Gruppen zuweist. Ist eine Zuordnung eingerichtet, gilt sie als maßgeblich:
    /// ohne passende Gruppe bleibt "Nur Lesen". Ohne Zuordnung: `None` (keine Änderung durch den Anbieter).
    fn mapped_role(&self, groups: &[String]) -> Option<Role> {
        if self.group_roles.is_empty() {
            return None;
        }
        let best = self
            .group_roles
            .iter()
            .filter(|g| groups.contains(&g.group))
            .filter_map(|g| Role::parse(&g.role))
            .max_by_key(|r| rank(*r));
        Some(best.unwrap_or(Role::Viewer))
    }

    /// Nur für die Policy "Nur Lesen vergeben": verifizierte E-Mail-Adresse in erlaubter Liste/Domäne.
    fn email_allowed(&self, id: &Identity) -> bool {
        let Some(email) = id.email.as_deref().filter(|_| id.email_verified) else {
            return false;
        };
        self.allowed_emails.iter().any(|e| e == email)
            || email
                .rsplit_once('@')
                .is_some_and(|(_, d)| self.allowed_domains.iter().any(|a| a == d))
    }

    fn group_claim(&self) -> &str {
        &self.group_claim
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

/// Redirect-URI: aus der öffentlichen Adresse, sonst der gespeicherte/konfigurierte Wert.
fn redirect_for(st: &AppState, fallback: &str) -> String {
    match &st.cfg.public_url {
        Some(p) => format!("{p}{CALLBACK_PATH}"),
        None => fallback.to_owned(),
    }
}

fn norm_claim(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() { "groups" } else { s }.to_owned()
}

fn norm_policy(s: &str) -> String {
    match s {
        "viewer" | "reject" => s.to_owned(),
        _ => "pending".to_owned(),
    }
}

/// Der konfigurierte Issuer (für ausdrücklich angelegte OIDC-Konten); `None`, wenn OIDC aus ist.
pub async fn configured_issuer(st: &AppState) -> Option<String> {
    resolve(st).await.map(|r| r.issuer)
}

/// Konfiguration auch im ausgeschalteten Zustand (für den Verbindungstest).
async fn resolve_any(st: &AppState) -> Option<Resolved> {
    if let Some(s) = load_stored(st).await {
        let client_secret = decrypt_secret(st, &s)?;
        return Some(Resolved {
            redirect_url: redirect_for(st, &s.redirect_url),
            issuer: s.issuer,
            client_id: s.client_id,
            client_secret,
            name: s.name,
            scopes: s.scopes,
            allowed_emails: s.allowed_emails,
            allowed_domains: s.allowed_domains,
            group_claim: norm_claim(&s.group_claim),
            group_roles: s.group_roles,
            new_account: norm_policy(&s.new_account),
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
        redirect_url: redirect_for(st, o.redirect_url.as_deref().unwrap_or_default()),
        name: o.name.clone().unwrap_or_default(),
        scopes: o.scopes.clone().unwrap_or_default(),
        allowed_emails: o.allowed_emails.clone(),
        allowed_domains: o.allowed_domains.clone(),
        group_claim: "groups".into(),
        group_roles: Vec::new(),
        new_account: "pending".into(),
    })
}

/// UI-Einstellung vor Umgebungsvariablen; `None` = Anmeldung per OIDC ist aus.
async fn resolve(st: &AppState) -> Option<Resolved> {
    if let Some(s) = load_stored(st).await {
        if !s.enabled {
            return None;
        }
    }
    resolve_any(st).await.filter(|r| !r.redirect_url.is_empty())
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
    Json(json!({
        "oidc": { "enabled": o.is_some(), "name": o.as_ref().map(label).unwrap_or("Single Sign-On") },
        // Passkeys gehen nur mit öffentlicher Adresse (WebAuthn bindet an den Host).
        "passkey": st.cfg.public_url.is_some(),
    }))
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
                    ..Stored::default()
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
        "redirect_url": redirect_for(st, &s.redirect_url),
        "public_url_set": st.cfg.public_url.is_some(),
        "name": s.name,
        "scopes": s.scopes,
        "allowed_emails": s.allowed_emails,
        "allowed_domains": s.allowed_domains,
        "group_claim": norm_claim(&s.group_claim),
        "group_roles": s.group_roles,
        "new_account": norm_policy(&s.new_account),
        "secret_set": s.secret.is_some(),
        "secret_storage": st.cfg.secret_key.is_some(),
    })
}

#[derive(Deserialize)]
pub struct SettingsBody {
    enabled: bool,
    issuer: String,
    client_id: String,
    #[serde(default)]
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
    #[serde(default)]
    group_claim: String,
    #[serde(default)]
    group_roles: Vec<GroupRole>,
    #[serde(default)]
    new_account: String,
    /// Eigenes Passwort; nötig, wenn eine Gruppe neu auf Administrator abgebildet wird.
    current_password: Option<String>,
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

fn admin_groups(v: &[GroupRole]) -> Vec<&str> {
    v.iter()
        .filter(|g| g.role == "admin")
        .map(|g| g.group.as_str())
        .collect()
}

/// Speichert die OIDC-Einstellungen.
pub async fn settings_put(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::OidcManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(b): Json<SettingsBody>,
) -> ApiResult<Json<Value>> {
    let bad = |m: &str| ApiError::BadRequest(m.to_owned());
    // Die Werte landen in einem jsonb-Wert; NUL würde dort einen Datenbankfehler (500) auslösen.
    let has_nul = [
        &b.issuer,
        &b.client_id,
        &b.redirect_url,
        &b.name,
        &b.scopes,
        &b.group_claim,
    ]
    .into_iter()
    .chain(&b.allowed_emails)
    .chain(&b.allowed_domains)
    .chain(b.group_roles.iter().flat_map(|g| [&g.group, &g.role]))
    .any(|s| super::has_nul(s) || s.chars().any(char::is_control));
    if has_nul {
        return Err(bad("ungültige Zeichen in den Einstellungen"));
    }
    let issuer = b.issuer.trim().trim_end_matches('/').to_owned();
    let allowed_emails = clean_list(&b.allowed_emails);
    let allowed_domains = clean_list(&b.allowed_domains);
    let mut group_roles: Vec<GroupRole> = Vec::new();
    for g in &b.group_roles {
        let group = g.group.trim();
        if group.is_empty() || group.len() > 100 || Role::parse(&g.role).is_none() {
            return Err(bad(
                "Gruppenzuordnung: Gruppe (1–100 Zeichen) und gültige Rolle angeben",
            ));
        }
        if !group_roles.iter().any(|x| x.group == group) {
            group_roles.push(GroupRole {
                group: group.to_owned(),
                role: g.role.clone(),
            });
        }
    }
    if group_roles.len() > 30 {
        return Err(bad("Höchstens 30 Gruppenzuordnungen"));
    }
    if !matches!(b.new_account.as_str(), "" | "pending" | "viewer" | "reject") {
        return Err(bad("Neue Konten: ausstehend, Nur Lesen oder ablehnen"));
    }
    let existing = load_stored(&st).await;
    // Neue Administrator-Zuordnung: wie jede Admin-Vergabe nur mit eigenem Passwort (bzw. frischer OIDC-Anmeldung).
    let old_admin = existing
        .as_ref()
        .map(|e| {
            admin_groups(&e.group_roles)
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if admin_groups(&group_roles)
        .iter()
        .any(|g| !old_admin.iter().any(|o| o == g))
    {
        super::users::reauth(&st, &me, b.current_password.as_deref()).await?;
    }
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
    let redirect_url = b.redirect_url.trim().to_owned();
    if b.enabled {
        let url = crate::notify::ssrf::parse_url(&issuer, false)
            .map_err(|_| bad("Issuer muss eine gültige https://-Adresse sein"))?;
        let host = url.host_str().unwrap_or_default();
        if url.scheme() != "https"
            && !crate::notify::ssrf::host_allowed(host, &st.cfg.notify_allowed_hosts)
        {
            return Err(bad(
                "Issuer muss mit https:// beginnen (http nur für Hosts aus PATCHWATCH_NOTIFY_ALLOWED_HOSTS)",
            ));
        }
        if b.client_id.trim().is_empty() || secret.is_none() {
            return Err(bad("Client-ID und Client-Secret sind nötig"));
        }
        if redirect_for(&st, &redirect_url).is_empty() {
            return Err(bad(
                "PATCHWATCH_PUBLIC_URL ist nicht gesetzt: die Redirect-URL lässt sich nicht bilden",
            ));
        }
    }
    let stored = Stored {
        enabled: b.enabled,
        issuer,
        client_id: b.client_id.trim().to_owned(),
        redirect_url,
        name: b.name.trim().chars().take(40).collect(),
        scopes: b.scopes.trim().to_owned(),
        allowed_emails,
        allowed_domains,
        secret,
        group_claim: norm_claim(&b.group_claim),
        group_roles,
        new_account: norm_policy(&b.new_account),
    };
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(SETTING_KEY)
    .bind(serde_json::to_value(&stored).map_err(anyhow::Error::from)?)
    .execute(&st.pool)
    .await?;
    st.jwks.clear();
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "oidc.settings_changed",
        None,
        Outcome::Ok,
        &ip,
    )
    .await;
    Ok(Json(settings_view(&st).await))
}

/// Verbindungstest: Discovery und JWKS abrufen (mit allen Schutzprüfungen); nichts wird gespeichert.
pub async fn settings_test(
    CsrfAuthed(me, _): CsrfAuthed<authz::p::OidcManage>,
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
) -> ApiResult<Json<Value>> {
    st.limiter
        .check(
            &format!("oidc-test:{}", me.id),
            10,
            Duration::from_secs(600),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let Some(o) = resolve_any(&st).await else {
        return Err(ApiError::BadRequest(
            "OIDC ist nicht eingerichtet (Issuer, Client-ID, Secret)".into(),
        ));
    };
    let allowed = &st.cfg.notify_allowed_hosts;
    let result = async {
        let d = oidc::discover(&o.issuer, allowed).await?;
        let n = st.jwks.refresh(&d.jwks_uri, allowed).await?.len();
        Ok::<_, Fail>(n)
    }
    .await;
    let (outcome, body) = match result {
        Ok(n) => (
            Outcome::Ok,
            json!({ "ok": true, "keys": n, "redirect_url": o.redirect_url }),
        ),
        Err(f) => (
            Outcome::Failed,
            json!({ "ok": false, "error": f.code(), "message": fail_text(f) }),
        ),
    };
    audit::record(
        &st.pool,
        Some(me.id),
        &me.username,
        "oidc.test",
        None,
        outcome,
        &ip,
    )
    .await;
    Ok(Json(body))
}

fn fail_text(f: Fail) -> &'static str {
    match f {
        Fail::Url => "Adresse nicht erlaubt (https nötig, keine internen Adressen)",
        Fail::Network => "Anbieter nicht erreichbar",
        Fail::TooLarge => "Antwort des Anbieters ist zu groß",
        Fail::Status => "Anbieter antwortet mit einem Fehlerstatus",
        Fail::BadJson | Fail::Discovery => {
            "Discovery-Dokument ungültig oder Aussteller/Hosts passen nicht"
        }
        Fail::Jwks => "Keine brauchbaren Signaturschlüssel (RS256/ES256) gefunden",
        _ => "Prüfung fehlgeschlagen",
    }
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

/// Rücksprungziel nur aus der Positivliste relativer Pfade (kein Open Redirect).
pub fn safe_return(raw: &str) -> Option<String> {
    let ok_chars = raw.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '/' | '-' | '_' | '.' | '?' | '=' | '&' | '%' | ',')
    });
    if raw.len() > 200
        || !raw.starts_with('/')
        || raw.starts_with("//")
        || !ok_chars
        || raw.contains("..")
    {
        return None;
    }
    let seg = raw[1..].split(['/', '?']).next().unwrap_or_default();
    (RETURN_SEGMENTS.contains(&seg) || raw == "/").then(|| raw.to_owned())
}

#[derive(Deserialize)]
pub struct LoginQuery {
    return_to: Option<String>,
}

/// Startet die Anmeldung: legt state/nonce/PKCE an und leitet zum Provider.
pub async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(q): Query<LoginQuery>,
) -> ApiResult<Response> {
    let o = resolve(&st).await.ok_or(ApiError::NotFound)?;
    st.limiter
        .check(&format!("oidc-start:{ip}"), 20, Duration::from_secs(600))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let d = match oidc::discover(&o.issuer, &st.cfg.notify_allowed_hosts).await {
        Ok(d) => d,
        Err(f) => return Ok(fail(&st, &ip, f.code(), "oidc").await),
    };
    let state = security::new_session_id();
    let nonce = security::new_session_id();
    let verifier = security::new_session_id();
    let challenge = URL_SAFE_NO_PAD.encode(security::sha256(&verifier));
    let return_to = q.return_to.as_deref().and_then(safe_return);
    sqlx::query("DELETE FROM oidc_states WHERE expires_at < now()")
        .execute(&st.pool)
        .await?;
    sqlx::query("INSERT INTO oidc_states (state_hash, nonce, verifier, return_to, expires_at) VALUES ($1, $2, $3, $4, now() + interval '10 minutes')")
        .bind(security::sha256(&state))
        .bind(&nonce)
        .bind(&verifier)
        .bind(&return_to)
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

/// Allgemeine Fehlerseite für den Browser; die Ursache (fester Code) geht ins Aktivitätsprotokoll.
async fn fail(st: &AppState, ip: &str, code: &str, page: &str) -> Response {
    audit::record(
        &st.pool,
        None,
        "oidc",
        "oidc.login",
        Some(code),
        Outcome::Denied,
        ip,
    )
    .await;
    let mut resp = Redirect::to(&format!("/login?error={page}")).into_response();
    if let Ok(v) = HeaderValue::from_str(&state_cookie(st, "", 0)) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// Token-Endpunkt: Code gegen Token tauschen. Liefert (ID-Token, Access-Token).
async fn exchange(
    st: &AppState,
    o: &Resolved,
    d: &oidc::Discovery,
    code: &str,
    verifier: &str,
) -> Result<(String, Option<String>), Fail> {
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
    let creds = (o.client_id.as_str(), o.client_secret.as_str());
    if !basic {
        form.push(("client_id", creds.0));
        form.push(("client_secret", creds.1));
    }
    let tok = oidc::post_form(
        &d.token_endpoint,
        &st.cfg.notify_allowed_hosts,
        &form,
        basic.then_some(creds),
    )
    .await?;
    let id = tok["id_token"].as_str().ok_or(Fail::Format)?.to_owned();
    Ok((id, tok["access_token"].as_str().map(str::to_owned)))
}

/// ID-Token prüfen (Signatur, Claims) und die Identität bilden; E-Mail/Gruppen bei Bedarf aus UserInfo ergänzen.
async fn verified_identity(
    st: &AppState,
    o: &Resolved,
    d: &oidc::Discovery,
    nonce: &str,
    id_token: &str,
    access_token: Option<&str>,
) -> Result<Identity, Fail> {
    let allowed = &st.cfg.notify_allowed_hosts;
    let (_, kid) = oidc::peek_header(id_token)?;
    let keys = st
        .jwks
        .keys_for(&d.jwks_uri, allowed, kid.as_deref())
        .await?;
    let claims = oidc::verify(id_token, &keys)?;
    oidc::check_claims(
        &claims,
        &o.issuer,
        &o.client_id,
        nonce,
        chrono::Utc::now().timestamp(),
    )?;
    let mut profile = claims.clone();
    let missing = |k: &str| claims.get(k).is_none_or(Value::is_null);
    let need_more = missing("email") || (!o.group_roles.is_empty() && missing(o.group_claim()));
    if let (true, Some(url), Some(at)) = (need_more, &d.userinfo_endpoint, access_token) {
        // UserInfo ergänzt nur fehlende Angaben; sein `sub` muss zum ID-Token passen.
        if let Ok(u) = oidc::get_json(url, allowed, Some(at)).await {
            if u["sub"] != claims["sub"] {
                return Err(Fail::Sub);
            }
            for (k, v) in u.as_object().into_iter().flatten() {
                if profile.get(k).is_none_or(Value::is_null) {
                    profile[k] = v.clone();
                }
            }
        }
    }
    oidc::identity(&profile, o.group_claim())
}

enum Outcome2 {
    Session(i64),
    Pending,
    Denied(&'static str),
}

/// Anzeigename aus Anbieterangaben; eindeutig gemacht (Zähler), ohne Steuerzeichen, 1–60 Zeichen.
async fn free_display_name(st: &AppState, id: &Identity) -> ApiResult<String> {
    let base: String = id
        .name
        .clone()
        .or_else(|| {
            id.email
                .as_ref()
                .and_then(|e| e.split('@').next().map(str::to_owned))
        })
        .unwrap_or_else(|| "Benutzer".into())
        .chars()
        .filter(|c| !c.is_control())
        .take(50)
        .collect();
    let base = if base.trim().is_empty() {
        "Benutzer".to_owned()
    } else {
        base.trim().to_owned()
    };
    for n in 1..=50 {
        let cand = if n == 1 {
            base.clone()
        } else {
            format!("{base} ({n})")
        };
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM admin_users WHERE lower(display_name) = lower($1) AND deleted_at IS NULL)",
        )
        .bind(&cand)
        .fetch_one(&st.pool)
        .await?;
        if !taken {
            return Ok(cand);
        }
    }
    Ok(format!("{base} ({})", &security::new_session_id()[..6]))
}

/// Konto zu (Issuer, sub) finden, bewerten (Status, Gruppen→Rolle) oder neu anlegen. Nie per E-Mail.
async fn account_for(st: &AppState, o: &Resolved, id: &Identity) -> ApiResult<Outcome2> {
    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT id, status, role FROM admin_users WHERE oidc_issuer = $1 AND oidc_subject = $2 AND deleted_at IS NULL",
    )
    .bind(&o.issuer)
    .bind(&id.sub)
    .fetch_optional(&st.pool)
    .await?;
    let mapped = o.mapped_role(&id.groups);
    if let Some((uid, status, role)) = row {
        sqlx::query("UPDATE admin_users SET email = COALESCE($2, email) WHERE id = $1")
            .bind(uid)
            .bind(&id.email)
            .execute(&st.pool)
            .await?;
        let cur = Role::parse(&role).unwrap_or(Role::Viewer);
        // Herabstufung gilt sofort (und beendet alte Sitzungen); Hochstufung wartet auf die Bestätigung eines Administrators.
        let (new_role, requested) = match mapped {
            Some(m) if rank(m) < rank(cur) => (m, None),
            Some(m) if rank(m) > rank(cur) => (cur, Some(m)),
            _ => (cur, None),
        };
        if new_role != cur {
            sqlx::query("UPDATE admin_users SET role = $2 WHERE id = $1")
                .bind(uid)
                .bind(new_role.key())
                .execute(&st.pool)
                .await?;
            sqlx::query("DELETE FROM sessions WHERE admin_id = $1")
                .bind(uid)
                .execute(&st.pool)
                .await?;
            audit::record(
                &st.pool,
                Some(uid),
                "oidc",
                "user.role_changed_by_idp",
                Some(new_role.key()),
                Outcome::Ok,
                "",
            )
            .await;
        }
        sqlx::query("UPDATE admin_users SET requested_role = $2 WHERE id = $1")
            .bind(uid)
            .bind(requested.map(Role::key))
            .execute(&st.pool)
            .await?;
        return Ok(match status.as_str() {
            "active" => Outcome2::Session(uid),
            "pending" => Outcome2::Pending,
            _ => Outcome2::Denied("konto_gesperrt"),
        });
    }
    if o.new_account == "reject" {
        return Ok(Outcome2::Denied("neues_konto_abgelehnt"));
    }
    // Neue Konten starten ohne Rechte; "Nur Lesen" sofort nur nach Policy und nachweisbarer Zuordnung.
    let active = o.new_account == "viewer" && (mapped.is_some() || o.email_allowed(id));
    let requested = mapped.filter(|m| rank(*m) > rank(Role::Viewer));
    let name = free_display_name(st, id).await?;
    let username = format!("oidc-{}", hex16(&format!("{}|{}", o.issuer, id.sub)));
    let created: Option<i64> = sqlx::query_scalar(
        "INSERT INTO admin_users (username, display_name, email, auth_kind, role, status, oidc_issuer, oidc_subject, requested_role) \
         VALUES ($1, $2, $3, 'oidc', 'viewer', $4, $5, $6, $7) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(&username)
    .bind(&name)
    .bind(&id.email)
    .bind(if active { "active" } else { "pending" })
    .bind(&o.issuer)
    .bind(&id.sub)
    .bind(requested.map(Role::key))
    .fetch_optional(&st.pool)
    .await?;
    let Some(uid) = created else {
        // Gleichzeitige Anmeldung hat das Konto soeben angelegt; beim nächsten Versuch greift der Normalfall.
        return Ok(Outcome2::Denied("konto_wird_angelegt"));
    };
    audit::record(
        &st.pool,
        Some(uid),
        "oidc",
        "user.created_by_oidc",
        Some(&name),
        Outcome::Ok,
        "",
    )
    .await;
    Ok(if active {
        Outcome2::Session(uid)
    } else {
        Outcome2::Pending
    })
}

fn hex16(s: &str) -> String {
    security::sha256(s)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Rückkehr vom Provider: Code gegen Token tauschen, prüfen, Konto bestimmen, neue Sitzung anlegen.
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
    if q.error.is_some() {
        return Ok(fail(&st, &ip, "anbieter_meldet_fehler", "oidc").await);
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return Ok(fail(&st, &ip, "code_oder_state_fehlt", "oidc").await);
    };
    // Login-CSRF: Der state muss zu dem Browser gehören, der die Anmeldung gestartet hat.
    let cookie_state = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| security::cookie_value(c, STATE_COOKIE));
    if !cookie_state.is_some_and(|c| security::ct_eq(c, &state)) {
        return Ok(fail(&st, &ip, "state_cookie", "oidc").await);
    }
    let stored: Option<(String, String, Option<String>)> = sqlx::query_as(
        "DELETE FROM oidc_states WHERE state_hash = $1 AND expires_at > now() RETURNING nonce, verifier, return_to",
    )
    .bind(security::sha256(&state))
    .fetch_optional(&st.pool)
    .await?;
    let Some((nonce, verifier, return_to)) = stored else {
        return Ok(fail(&st, &ip, "state_unbekannt", "oidc").await);
    };

    let d = match oidc::discover(&o.issuer, &st.cfg.notify_allowed_hosts).await {
        Ok(d) => d,
        Err(f) => return Ok(fail(&st, &ip, f.code(), "oidc").await),
    };
    let ident = async {
        let (idt, at) = exchange(&st, &o, &d, &code, &verifier).await?;
        verified_identity(&st, &o, &d, &nonce, &idt, at.as_deref()).await
    }
    .await;
    let ident = match ident {
        Ok(i) => i,
        Err(f) => return Ok(fail(&st, &ip, f.code(), "oidc").await),
    };
    let admin_id = match account_for(&st, &o, &ident).await? {
        Outcome2::Session(id) => id,
        Outcome2::Pending => return Ok(fail(&st, &ip, "konto_ausstehend", "oidc_pending").await),
        Outcome2::Denied(why) => return Ok(fail(&st, &ip, why, "oidc").await),
    };
    // Neue Sitzungs-ID nach jeder Anmeldung (nie eine vorhandene wiederverwenden).
    let session_id = security::new_session_id();
    let ttl = st.cfg.session_ttl_hours * 3600;
    sqlx::query("INSERT INTO sessions (id_hash, admin_id, csrf_token, expires_at) VALUES ($1, $2, $3, now() + make_interval(secs => $4))")
        .bind(security::sha256(&session_id))
        .bind(admin_id)
        .bind(security::new_csrf_token())
        .bind(ttl as f64)
        .execute(&st.pool)
        .await?;
    sqlx::query("UPDATE admin_users SET last_login_at = now() WHERE id = $1")
        .bind(admin_id)
        .execute(&st.pool)
        .await?;
    audit::record(
        &st.pool,
        Some(admin_id),
        "oidc",
        "login",
        Some("oidc"),
        Outcome::Ok,
        &ip,
    )
    .await;
    let mut resp = Redirect::to(
        return_to
            .as_deref()
            .and_then(safe_return)
            .as_deref()
            .unwrap_or("/"),
    )
    .into_response();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_positive_list() {
        for ok in ["/", "/hosts", "/cves?q=a%20b", "/hosts/12", "/users"] {
            assert_eq!(safe_return(ok).as_deref(), Some(ok), "{ok}");
        }
        for bad in [
            "",
            "hosts",
            "//evil.example",
            "/\\evil",
            "https://evil.example",
            "/login",
            "/api/v1/hosts",
            "/hosts/../login",
            "/hosts@evil",
            "/hosts\n",
            "/javascript:alert(1)",
            "/ho sts",
        ] {
            assert_eq!(safe_return(bad), None, "{bad}");
        }
    }
}
