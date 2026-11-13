//! Benutzer, Rollen, Rechte: Rechtematrix, Sitzungsende, Aussperrschutz, Einmalpasswort, Aktivitätsprotokoll.
//! Wegwerf-Datenbank (sqlx::test); alle Passwörter hier sind eindeutig gekennzeichnete Testwerte.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::authz::{self, Permission, Role};
use patchwatch_server::config::Config;
use patchwatch_server::{admin, router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const PW: &str = "TESTWERT-passwort-0001";

fn state(pool: PgPool) -> AppState {
    let cfg = Config::from_sources(None, &|k| {
        (k == "PATCHWATCH_TRUST_PROXY").then(|| "true".to_owned())
    })
    .unwrap();
    AppState::new(pool, cfg).unwrap()
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    json: Value,
    raw: String,
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Resp {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let req = match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Resp {
        status: parts.status,
        headers: parts.headers,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// Konto anlegen (lokal, aktiv) mit Rolle und Status direkt in der Datenbank.
async fn mk(pool: &PgPool, name: &str, role: &str, status: &str) -> i64 {
    admin::upsert_admin(pool, name, PW).await.unwrap();
    sqlx::query_scalar(
        "UPDATE admin_users SET role = $2, status = $3 WHERE username = $1 RETURNING id",
    )
    .bind(name)
    .bind(role)
    .bind(status)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[derive(Clone)]
struct Sess {
    cookie: String,
    csrf: String,
}

impl Sess {
    fn h(&self) -> [(&str, &str); 2] {
        [
            ("cookie", self.cookie.as_str()),
            ("x-csrf-token", self.csrf.as_str()),
        ]
    }
}

static NEXT_IP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

async fn login_with(app: &Router, name: &str, pw: &str) -> Option<Sess> {
    // Eigene Quell-IP je Anmeldung (Proxy-Header), damit das Rate-Limit je IP die vielen Test-Anmeldungen nicht bremst.
    let n = NEXT_IP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ip = format!("10.9.{}.{}", n / 250, n % 250 + 1);
    let r = call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        &[("x-forwarded-for", ip.as_str())],
        Some(json!({"username": name, "password": pw})),
    )
    .await;
    if r.status != StatusCode::OK {
        return None;
    }
    let cookie = r
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    Some(Sess {
        cookie,
        csrf: r.json["csrf_token"].as_str().unwrap().to_owned(),
    })
}

async fn login(app: &Router, name: &str) -> Sess {
    login_with(app, name, PW)
        .await
        .unwrap_or_else(|| panic!("Anmeldung von {name} fehlgeschlagen"))
}

// ---------- Rechtematrix ----------

/// (Methode, Pfad, Recht, ungefährlich auch mit Recht aufrufbar?). Pfade mit Beispielwerten.
fn matrix() -> Vec<(Method, &'static str, Permission, bool)> {
    use Permission::*;
    vec![
        (Method::GET, "/api/v1/hosts", HostsRead, true),
        (Method::GET, "/api/v1/hosts/1", HostsRead, true),
        (Method::GET, "/api/v1/hosts/1/history", HostsRead, true),
        (Method::GET, "/api/v1/hosts/1/cves", HostsRead, true),
        (Method::GET, "/api/v1/hosts/1/cves/groups", HostsRead, true),
        (Method::GET, "/api/v1/hosts/1/updates", HostsRead, true),
        (Method::GET, "/api/v1/matrix", HostsRead, true),
        (Method::POST, "/api/v1/hosts", HostsWrite, false),
        (Method::DELETE, "/api/v1/hosts/1", HostsDelete, true),
        (
            Method::POST,
            "/api/v1/hosts/1/rotate-token",
            AgentsTokens,
            true,
        ),
        (Method::POST, "/api/v1/hosts/request-report", HostsRun, true),
        (
            Method::POST,
            "/api/v1/hosts/1/request-report",
            HostsRun,
            true,
        ),
        (
            Method::PUT,
            "/api/v1/hosts/1/cves/CVE-2024-0001/review",
            CvesWatch,
            true,
        ),
        (
            Method::DELETE,
            "/api/v1/hosts/1/cves/CVE-2024-0001/review",
            CvesWatch,
            true,
        ),
        (Method::GET, "/api/v1/cves", CvesRead, true),
        (Method::GET, "/api/v1/cves/scope-count", CvesRead, true),
        (Method::GET, "/api/v1/cves/CVE-2024-0001", CvesRead, true),
        (Method::GET, "/api/v1/watchlist", CvesRead, true),
        (
            Method::PUT,
            "/api/v1/watchlist/CVE-2024-0001",
            CvesWatch,
            true,
        ),
        (
            Method::DELETE,
            "/api/v1/watchlist/CVE-2024-0001",
            CvesWatch,
            true,
        ),
        (Method::GET, "/api/v1/feeds", SourcesRead, true),
        (Method::GET, "/api/v1/feeds/runs", SourcesRead, true),
        (Method::POST, "/api/v1/feeds", SourcesWrite, false),
        (Method::PUT, "/api/v1/feeds/nope", SourcesWrite, true),
        (Method::DELETE, "/api/v1/feeds/nope", SourcesWrite, true),
        (Method::POST, "/api/v1/feeds/nope/run", SourcesRun, true),
        (Method::POST, "/api/v1/feeds/refresh", SourcesRun, false),
        (Method::GET, "/api/v1/notifications", ChannelsRead, true),
        (
            Method::GET,
            "/api/v1/notifications/ntfy",
            ChannelsRead,
            true,
        ),
        (
            Method::PUT,
            "/api/v1/notifications/nope",
            ChannelsWrite,
            true,
        ),
        (
            Method::POST,
            "/api/v1/notifications/nope/test",
            ChannelsTest,
            true,
        ),
        (Method::GET, "/api/v1/settings", SettingsRead, true),
        (Method::PUT, "/api/v1/settings", SettingsWrite, false),
        (Method::GET, "/api/v1/settings/oidc", OidcManage, true),
        (Method::PUT, "/api/v1/settings/oidc", OidcManage, false),
        (Method::POST, "/api/v1/settings/oidc/test", OidcManage, true),
        (Method::GET, "/api/v1/roles", UsersManage, true),
        (Method::GET, "/api/v1/users", UsersManage, true),
        (Method::POST, "/api/v1/users", UsersManage, false),
        (Method::PATCH, "/api/v1/users/999999", UsersManage, true),
        (Method::DELETE, "/api/v1/users/999999", UsersManage, true),
        (Method::POST, "/api/v1/users/999999/lock", UsersManage, true),
        (
            Method::POST,
            "/api/v1/users/999999/unlock",
            UsersManage,
            true,
        ),
        (
            Method::POST,
            "/api/v1/users/999999/approve",
            UsersManage,
            true,
        ),
        (
            Method::POST,
            "/api/v1/users/999999/reset-password",
            UsersManage,
            true,
        ),
        (Method::GET, "/api/v1/audit", AuditRead, true),
    ]
}

#[sqlx::test(migrations = "./migrations")]
async fn permission_matrix_for_every_route_and_role(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "m-admin", "admin", "active").await;
    mk(&pool, "m-oper", "operator", "active").await;
    mk(&pool, "m-view", "viewer", "active").await;
    let locked = mk(&pool, "m-locked", "admin", "active").await;
    mk(&pool, "m-pending", "admin", "active").await;
    let mut sessions = vec![];
    for (n, r) in [
        ("m-admin", Role::Admin),
        ("m-oper", Role::Operator),
        ("m-view", Role::Viewer),
    ] {
        sessions.push((r, login(&app, n).await));
    }
    // Gesperrt und ausstehend: Sitzung bestand, bevor der Status sich änderte -> sofort wirkungslos.
    let locked_s = login(&app, "m-locked").await;
    let pending_s = login(&app, "m-pending").await;
    sqlx::query("UPDATE admin_users SET status = 'locked' WHERE id = $1")
        .bind(locked)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE admin_users SET status = 'pending' WHERE username = 'm-pending'")
        .execute(&pool)
        .await
        .unwrap();

    for (m, path, perm, safe) in matrix() {
        // Nicht angemeldet: 401, nie 403 oder Daten.
        let r = call(&app, m.clone(), path, &[], Some(json!({}))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "anonym {m} {path}");
        for (label, s) in [("gesperrt", &locked_s), ("ausstehend", &pending_s)] {
            let r = call(&app, m.clone(), path, &s.h(), Some(json!({}))).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{label} {m} {path}");
        }
        for (role, s) in &sessions {
            let r = call(&app, m.clone(), path, &s.h(), Some(json!({}))).await;
            if role.allows(perm) {
                assert!(
                    r.status != StatusCode::FORBIDDEN && r.status != StatusCode::UNAUTHORIZED
                        || !safe,
                    "{role:?} darf {m} {path}: {}",
                    r.status
                );
                if safe {
                    assert_ne!(r.status, StatusCode::FORBIDDEN, "{role:?} {m} {path}");
                }
            } else {
                assert_eq!(
                    r.status,
                    StatusCode::FORBIDDEN,
                    "{role:?} darf {m} {path} nicht"
                );
            }
        }
        // Ohne CSRF-Token verändern auch Berechtigte nichts.
        if m != Method::GET {
            let (_, a) = &sessions[0];
            let r = call(
                &app,
                m.clone(),
                path,
                &[("cookie", a.cookie.as_str())],
                Some(json!({})),
            )
            .await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "ohne CSRF {m} {path}");
        }
    }
}

/// Jeder in `routes/mod.rs` registrierte Pfad steht in der Matrix oder ist ausdrücklich öffentlich/Host-Token/eigenes Konto.
#[test]
fn every_registered_route_is_in_the_matrix_or_explicitly_exempt() {
    let src = include_str!("../src/routes/mod.rs");
    let known: Vec<String> = matrix()
        .iter()
        .map(|(_, p, _, _)| p.trim_start_matches("/api/v1").to_owned())
        .collect();
    let exempt = [
        "/report",
        "/agent/checkin",
        "/auth/login",
        "/auth/logout",
        "/auth/me",
        "/auth/providers",
        "/auth/oidc/login",
        "/auth/oidc/callback",
        "/auth/password",
        "/auth/avatar",
        "/live",
        "/healthz",
        "/readyz",
    ];
    let mut paths = vec![];
    for chunk in src.split(".route(").skip(1) {
        let start = chunk.find('"').unwrap() + 1;
        let end = start + chunk[start..].find('"').unwrap();
        paths.push(chunk[start..end].to_owned());
    }
    assert!(paths.len() > 40, "Routen gefunden: {}", paths.len());
    let norm = |p: &str| -> String {
        // /hosts/{id}/x -> /hosts/1/x usw.
        p.split('/')
            .map(|seg| if seg.starts_with('{') { "*" } else { seg })
            .collect::<Vec<_>>()
            .join("/")
    };
    let known_norm: Vec<String> = known
        .iter()
        .map(|p| {
            p.split('/')
                .map(|s| {
                    if s == "1" || s == "nope" || s == "999999" || s.starts_with("CVE-") {
                        "*"
                    } else {
                        s
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    for p in paths {
        let n = norm(&p);
        let ok = exempt.iter().any(|e| p.starts_with(e)) || known_norm.contains(&n);
        assert!(ok, "Route {p} hat kein Recht in der Rechtematrix (tests/users.rs) und ist nicht ausdrücklich ausgenommen");
    }
}

/// Jeder Handler einer Route trägt einen rechtstragenden Extractor (Standard: verweigern).
#[test]
fn every_handler_requires_a_permission_extractor() {
    let modsrc = include_str!("../src/routes/mod.rs");
    let files: [(&str, &str); 11] = [
        ("auth", include_str!("../src/routes/auth.rs")),
        ("cves", include_str!("../src/routes/cves.rs")),
        ("feeds", include_str!("../src/routes/feeds.rs")),
        ("hosts", include_str!("../src/routes/hosts.rs")),
        ("live", include_str!("../src/routes/live.rs")),
        ("matrix", include_str!("../src/routes/matrix.rs")),
        (
            "notifications",
            include_str!("../src/routes/notifications.rs"),
        ),
        ("oidc", include_str!("../src/routes/oidc.rs")),
        ("settings", include_str!("../src/routes/settings.rs")),
        ("users", include_str!("../src/routes/users.rs")),
        ("agent", include_str!("../src/routes/agent.rs")),
    ];
    // Handler ohne Benutzerrecht: öffentlich (Anmeldung), Host-Token (Agent), Gesundheit.
    let exempt = [
        "auth::login",
        "oidc::providers",
        "oidc::login",
        "oidc::callback",
        "agent::checkin",
        "report::post_report",
        "health::healthz",
        "health::readyz",
    ];
    let mut checked = 0;
    for (module, src) in files {
        let mut rest = modsrc;
        while let Some(i) = rest.find(&format!("{module}::")) {
            let after = &rest[i + module.len() + 2..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            rest = &rest[i + 2..];
            // `pub use cves::valid_cve_id;` ist kein Handler.
            let line_start = modsrc.len() - after.len() - module.len() - 2;
            let line = modsrc[..line_start].rsplit('\n').next().unwrap_or("");
            if line.trim_start().starts_with("pub use") || line.trim_start().starts_with("use ") {
                continue;
            }
            let key = format!("{module}::{name}");
            if exempt.contains(&key.as_str()) {
                continue;
            }
            let sig_start = src
                .find(&format!("pub async fn {name}("))
                .unwrap_or_else(|| panic!("Handler {key} nicht gefunden"));
            let sig = &src[sig_start..];
            let sig = &sig[..sig.find(") ->").unwrap_or_else(|| sig.find("{").unwrap())];
            let has = [
                "Authed<",
                "CsrfAuthed<",
                "SelfAdmin",
                "SelfCsrfAdmin",
                "PendingAdmin",
                "PendingCsrfAdmin",
            ]
            .iter()
            .any(|t| sig.contains(t));
            assert!(
                has,
                "Handler {key} verlangt kein Recht (Extractor Authed<..>/CsrfAuthed<..>)"
            );
            checked += 1;
        }
    }
    assert!(checked > 30, "geprüfte Handler: {checked}");
}

#[test]
fn matrix_covers_every_permission() {
    let used: Vec<Permission> = matrix().iter().map(|m| m.2).collect();
    // `*.secrets` hängen vom Inhalt der Anfrage ab (Schlüssel gesetzt oder nicht); eigene Tests: secrets_rights_*.
    let by_body = [Permission::SourcesSecrets, Permission::ChannelsSecrets];
    for p in authz::ALL.iter().copied().filter(|p| !by_body.contains(p)) {
        assert!(
            used.contains(&p),
            "Recht {} wird von keiner Route der Matrix verlangt",
            p.name()
        );
    }
}

// ---------- Benutzer anlegen, Einmalpasswort, Sitzungen ----------

#[sqlx::test(migrations = "./migrations")]
async fn one_time_password_is_returned_once_and_must_be_changed(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    let a = login(&app, "boss").await;
    let r = call(
        &app,
        Method::POST,
        "/api/v1/users",
        &a.h(),
        Some(json!({"display_name": "Erna", "auth_kind": "local", "role": "viewer"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.raw);
    let pw = r.json["initial_password"].as_str().unwrap().to_owned();
    assert!(pw.len() >= 20);
    // Nie wieder: weder Liste noch Detail noch Protokoll enthalten es; in der Datenbank steht nur ein Hash.
    let list = call(&app, Method::GET, "/api/v1/users", &a.h(), None).await;
    assert!(!list.raw.contains(&pw));
    let audit = call(&app, Method::GET, "/api/v1/audit", &a.h(), None).await;
    assert!(!audit.raw.contains(&pw));
    let stored: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM admin_users WHERE username = 'Erna'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(stored.is_some_and(|h| h.starts_with("$argon2id$") && !h.contains(&pw)));
    // Erste Anmeldung: nur Passwortwechsel erlaubt.
    let e = login_with(&app, "Erna", &pw).await.unwrap();
    let blocked = call(&app, Method::GET, "/api/v1/hosts", &e.h(), None).await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert_eq!(blocked.json["code"], "password_change_required");
    let short = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        &e.h(),
        Some(json!({"current_password": pw, "new_password": "kurz"})),
    )
    .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    let ok = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        &e.h(),
        Some(json!({"current_password": pw, "new_password": "TESTWERT-neues-passwort-77"})),
    )
    .await;
    assert_eq!(ok.status, StatusCode::NO_CONTENT);
    // Das Einmalpasswort ist danach ungültig.
    assert!(login_with(&app, "Erna", &pw).await.is_none());
    assert!(login_with(&app, "Erna", "TESTWERT-neues-passwort-77")
        .await
        .is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn sessions_end_on_role_change_lock_reset_and_delete(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    mk(&pool, "second", "admin", "active").await;
    let a = login(&app, "boss").await;
    let mut ids = std::collections::HashMap::new();
    for n in ["u-role", "u-lock", "u-reset", "u-del"] {
        ids.insert(n, mk(&pool, n, "viewer", "active").await);
    }
    let alive = |s: Sess| {
        let app = app.clone();
        async move {
            call(&app, Method::GET, "/api/v1/hosts", &s.h(), None)
                .await
                .status
                == StatusCode::OK
        }
    };
    // Rollenwechsel (zu Betreiber: kein Passwort nötig, Bestätigung mit Namen).
    let s = login(&app, "u-role").await;
    assert!(alive(s.clone()).await);
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{}", ids["u-role"]),
        &a.h(),
        Some(json!({"role": "operator", "confirm_name": "u-role", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert!(!alive(s).await, "alte Sitzung nach Rollenwechsel");
    let s2 = login(&app, "u-role").await;
    assert_eq!(
        call(&app, Method::GET, "/api/v1/auth/me", &s2.h(), None)
            .await
            .json["role"],
        "operator"
    );
    // Sperren / Entsperren.
    let s = login(&app, "u-lock").await;
    assert_eq!(
        call(
            &app,
            Method::POST,
            &format!("/api/v1/users/{}/lock", ids["u-lock"]),
            &a.h(),
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    assert!(!alive(s).await);
    assert!(
        login_with(&app, "u-lock", PW).await.is_none(),
        "gesperrtes Konto meldet sich nicht an"
    );
    assert_eq!(
        call(
            &app,
            Method::POST,
            &format!("/api/v1/users/{}/unlock", ids["u-lock"]),
            &a.h(),
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    assert!(login_with(&app, "u-lock", PW).await.is_some());
    // Passwort zurücksetzen.
    let s = login(&app, "u-reset").await;
    let r = call(
        &app,
        Method::POST,
        &format!("/api/v1/users/{}/reset-password", ids["u-reset"]),
        &a.h(),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!alive(s).await);
    assert!(
        login_with(&app, "u-reset", PW).await.is_none(),
        "altes Passwort ungültig"
    );
    assert!(login_with(
        &app,
        "u-reset",
        r.json["initial_password"].as_str().unwrap()
    )
    .await
    .is_some());
    // Löschen (weich, anonymisiert).
    let s = login(&app, "u-del").await;
    let r = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/users/{}", ids["u-del"]),
        &a.h(),
        Some(json!({"confirm_name": "u-del"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.raw);
    assert!(!alive(s).await);
    assert!(login_with(&app, "u-del", PW).await.is_none());
    let (name, hash): (String, Option<String>) =
        sqlx::query_as("SELECT display_name, password_hash FROM admin_users WHERE id = $1")
            .bind(ids["u-del"])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(name.starts_with("gelöscht-") && hash.is_none());
    // Passwortwechsel beendet andere Sitzungen (bestehendes Verhalten).
    let (s1, s2) = (login(&app, "second").await, login(&app, "second").await);
    let r = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        &s1.h(),
        Some(json!({"current_password": PW, "new_password": "TESTWERT-wechsel-12345"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(!alive(s2).await);
}

#[sqlx::test(migrations = "./migrations")]
async fn the_last_admin_is_protected_even_under_concurrent_requests(pool: PgPool) {
    let app = router(state(pool.clone()));
    let a_id = mk(&pool, "adm-a", "admin", "active").await;
    let b_id = mk(&pool, "adm-b", "admin", "active").await;
    let sa = login(&app, "adm-a").await;
    let sb = login(&app, "adm-b").await;
    // Beide sperren sich gleichzeitig gegenseitig: genau einer darf gelingen.
    let (ha, hb) = (sa.h(), sb.h());
    let (ub, ua) = (
        format!("/api/v1/users/{b_id}/lock"),
        format!("/api/v1/users/{a_id}/lock"),
    );
    let (r1, r2) = tokio::join!(
        call(&app, Method::POST, &ub, &ha, None),
        call(&app, Method::POST, &ua, &hb, None)
    );
    let oks = [r1.status, r2.status]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    assert_eq!(oks, 1, "{} / {}", r1.status, r2.status);
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_users WHERE role = 'admin' AND status = 'active'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 1);
    // Der verbliebene ist der letzte: nicht löschen, nicht herabstufen (auch nicht von einem Betreiber/Selbst).
    let (survivor, victim_id) = if r1.status == StatusCode::OK {
        (sa, a_id)
    } else {
        (sb, b_id)
    };
    let _ = victim_id;
    let me = call(&app, Method::GET, "/api/v1/auth/me", &survivor.h(), None).await;
    assert_eq!(me.json["role"], "admin");
    // Zweiten Administrator entsperren und dann parallel beide herabstufen/löschen lassen ist durch "keine eigene Rolle" gedeckt.
    let other: i64 =
        sqlx::query_scalar("SELECT id FROM admin_users WHERE status = 'locked' AND role = 'admin'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let del = call(&app, Method::DELETE, &format!("/api/v1/users/{other}"), &survivor.h(), Some(json!({"confirm_name": if other == a_id { "adm-a" } else { "adm-b" }, "confirm_password": PW}))).await;
    assert_eq!(
        del.status,
        StatusCode::NO_CONTENT,
        "gesperrter Administrator darf gelöscht werden: {}",
        del.raw
    );
    let self_id: i64 =
        sqlx::query_scalar("SELECT id FROM admin_users WHERE status = 'active' AND role = 'admin'")
            .fetch_one(&pool)
            .await
            .unwrap();
    for (m, path, body) in [
        (
            Method::DELETE,
            format!("/api/v1/users/{self_id}"),
            json!({"confirm_name": "x", "confirm_password": PW}),
        ),
        (
            Method::POST,
            format!("/api/v1/users/{self_id}/lock"),
            json!({}),
        ),
        (
            Method::PATCH,
            format!("/api/v1/users/{self_id}"),
            json!({"role": "viewer", "confirm_name": "x", "confirm_password": PW}),
        ),
    ] {
        let r = call(&app, m.clone(), &path, &survivor.h(), Some(body)).await;
        assert_eq!(
            r.status,
            StatusCode::FORBIDDEN,
            "Selbstschutz {m} {path}: {}",
            r.raw
        );
    }
    // Zweiter Administrator, der OIDC ist: der einzige LOKALE Administrator bleibt trotzdem geschützt.
    sqlx::query("INSERT INTO admin_users (username, display_name, auth_kind, role, status, oidc_issuer, oidc_subject) VALUES ('oidc-adm', 'oidc-adm', 'oidc', 'admin', 'active', 'https://idp.test', 'sub-1')")
        .execute(&pool).await.unwrap();
    let oidc_id: i64 = sqlx::query_scalar("SELECT id FROM admin_users WHERE username = 'oidc-adm'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let r = call(
        &app,
        Method::POST,
        &format!("/api/v1/users/{oidc_id}/lock"),
        &survivor.h(),
        None,
    )
    .await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "OIDC-Administrator darf gesperrt werden, solange ein lokaler bleibt"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nobody_changes_their_own_role_and_admin_grants_need_the_password(pool: PgPool) {
    let app = router(state(pool.clone()));
    let boss = mk(&pool, "boss", "admin", "active").await;
    mk(&pool, "boss2", "admin", "active").await;
    let v = mk(&pool, "vvv", "viewer", "active").await;
    let a = login(&app, "boss").await;
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{boss}"),
        &a.h(),
        Some(json!({"role": "viewer", "confirm_name": "boss", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "eigene Rolle");
    // Zum Administrator machen: ohne Passwort 403, mit falschem 403, mit richtigem ok.
    let body =
        |pw: Option<&str>| json!({"role": "admin", "confirm_name": "vvv", "confirm_password": pw});
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{v}"),
        &a.h(),
        Some(body(None)),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{v}"),
        &a.h(),
        Some(body(Some("falsch-falsch-falsch"))),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Bestätigung mit falschem Namen.
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{v}"),
        &a.h(),
        Some(json!({"role": "admin", "confirm_name": "anderer", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{v}"),
        &a.h(),
        Some(body(Some(PW))),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    // Anlegen eines Administrators verlangt ebenfalls das Passwort.
    let new_admin = |pw: Option<&str>| json!({"display_name": "Neu", "auth_kind": "local", "role": "admin", "confirm_password": pw});
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/users",
            &a.h(),
            Some(new_admin(None))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/users",
            &a.h(),
            Some(new_admin(Some(PW)))
        )
        .await
        .status,
        StatusCode::CREATED
    );
    // Doppelter Anzeigename (Groß-/Kleinschreibung egal): 409.
    let dup = json!({"display_name": "NEU", "auth_kind": "local", "role": "viewer"});
    assert_eq!(
        call(&app, Method::POST, "/api/v1/users", &a.h(), Some(dup))
            .await
            .status,
        StatusCode::CONFLICT
    );
    // Ungültige Eingaben.
    for bad in [
        json!({"display_name": "", "auth_kind": "local", "role": "viewer"}),
        json!({"display_name": "x", "auth_kind": "local", "role": "root"}),
        json!({"display_name": "a\u{0}b", "auth_kind": "local", "role": "viewer"}),
        json!({"display_name": "x", "auth_kind": "ldap", "role": "viewer"}),
    ] {
        let r = call(&app, Method::POST, "/api/v1/users", &a.h(), Some(bad)).await;
        assert!(r.status == StatusCode::BAD_REQUEST, "{}", r.status);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn login_failures_look_identical_and_everything_is_audited_without_secrets(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    mk(&pool, "gesperrt", "viewer", "locked").await;
    mk(&pool, "wartet", "viewer", "pending").await;
    let mut bodies = vec![];
    for (n, pw) in [
        ("gesperrt", PW),
        ("wartet", PW),
        ("gibt-es-nicht", PW),
        ("boss", "TESTWERT-falsch-12345"),
    ] {
        let r = call(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            &[],
            Some(json!({"username": n, "password": pw})),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{n}");
        bodies.push(r.raw);
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "Fehlermeldungen unterscheiden sich: {bodies:?}"
    );
    let a = login(&app, "boss").await;
    let _ = call(
        &app,
        Method::POST,
        "/api/v1/users",
        &a.h(),
        Some(json!({"display_name": "Zed", "auth_kind": "local", "role": "viewer"})),
    )
    .await;
    let log = call(&app, Method::GET, "/api/v1/audit?limit=100", &a.h(), None).await;
    let entries = log.json["entries"].as_array().unwrap();
    let actions: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"login") && actions.contains(&"user.created"),
        "{actions:?}"
    );
    assert!(entries
        .iter()
        .any(|e| e["action"] == "login" && e["result"] == "failed"));
    assert!(
        !log.raw.contains(PW) && !log.raw.contains("TESTWERT-falsch"),
        "Passwörter im Protokoll"
    );
    // IP gekürzt; Filter funktionieren.
    assert!(entries.iter().all(|e| e["ip"]
        .as_str()
        .is_some_and(|i| i == "unbekannt" || i.ends_with("/24") || i.ends_with("/48"))));
    let f = call(
        &app,
        Method::GET,
        "/api/v1/audit?result=failed",
        &a.h(),
        None,
    )
    .await;
    assert!(f.json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["result"] == "failed"));
    assert_eq!(
        call(
            &app,
            Method::GET,
            "/api/v1/audit?result=boese",
            &a.h(),
            None
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_oidc_accounts_become_pending_and_keep_no_access(pool: PgPool) {
    // Die Migration ist schon gelaufen; ein altes E-Mail-Konto wird hier wie von der alten Version angelegt und neu migriert.
    sqlx::query("INSERT INTO admin_users (username, password_hash, auth_kind) VALUES ('oidc:alt@example.org', 'x', 'local')").execute(&pool).await.unwrap();
    // Neue Konten dieser Art entstehen nicht mehr; die Migrationsregel wird zur Prüfung erneut ausgeführt.
    sqlx::query("UPDATE admin_users SET auth_kind = 'oidc', status = 'pending', role = 'viewer', email = substr(username, 6), password_hash = NULL WHERE username LIKE 'oidc:%'").execute(&pool).await.unwrap();
    let app = router(state(pool.clone()));
    assert!(
        login_with(&app, "oidc:alt@example.org", "irgendwas-langes-123")
            .await
            .is_none()
    );
    mk(&pool, "boss", "admin", "active").await;
    let a = login(&app, "boss").await;
    // Ohne (Issuer, Subject) lässt sich das Konto nicht freigeben: die E-Mail ist kein Schlüssel.
    let id: i64 =
        sqlx::query_scalar("SELECT id FROM admin_users WHERE username = 'oidc:alt@example.org'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let r = call(
        &app,
        Method::POST,
        &format!("/api/v1/users/{id}/approve"),
        &a.h(),
        Some(json!({"role": "viewer"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.raw);
    let list = call(&app, Method::GET, "/api/v1/users", &a.h(), None).await;
    assert_eq!(list.json["pending"], 1, "{} {}", list.status, list.raw);
}

#[sqlx::test(migrations = "./migrations")]
async fn recover_admin_restores_a_locked_or_oidc_account_and_ends_sessions(pool: PgPool) {
    // Gesperrter, herabgestufter lokaler Konto-Fall: Notzugang macht es wieder zum aktiven Administrator.
    mk(&pool, "notfall", "viewer", "locked").await;
    let app = router(state(pool.clone()));
    admin::recover_admin(&pool, "notfall", "TESTWERT-notfall-0001")
        .await
        .unwrap();
    let (role, status, kind): (String, String, String) = sqlx::query_as(
        "SELECT role, status, auth_kind FROM admin_users WHERE username = 'notfall'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (role.as_str(), status.as_str(), kind.as_str()),
        ("admin", "active", "local")
    );
    let s = login_with(&app, "notfall", "TESTWERT-notfall-0001")
        .await
        .expect("Anmeldung mit dem neuen Passwort");
    assert_eq!(
        call(&app, Method::GET, "/api/v1/users", &s.h(), None)
            .await
            .status,
        StatusCode::OK
    );
    // Ein zweiter Aufruf beendet die laufende Sitzung und protokolliert ohne Passwort.
    admin::recover_admin(&pool, "notfall", "TESTWERT-notfall-0002")
        .await
        .unwrap();
    assert_eq!(
        call(&app, Method::GET, "/api/v1/users", &s.h(), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let log: String = sqlx::query_scalar("SELECT string_agg(action || coalesce(target,''), ',') FROM audit_log WHERE action = 'admin.recovered'")
        .fetch_one(&pool).await.unwrap();
    assert!(log.contains("admin.recovered") && !log.contains("TESTWERT"));
    // Zu kurzes Passwort wird abgelehnt.
    assert!(admin::recover_admin(&pool, "notfall", "kurz")
        .await
        .is_err());
}

/// Regression: OIDC-Konten haben keinen Passwort-Hash; die Prüfung auf Standardpasswörter beim Start darf daran nicht scheitern.
#[sqlx::test(migrations = "./migrations")]
async fn startup_default_password_scan_skips_accounts_without_a_hash(pool: PgPool) {
    sqlx::query("INSERT INTO admin_users (username, display_name, auth_kind, role, status, oidc_issuer, oidc_subject) VALUES ('oidc-x', 'X', 'oidc', 'viewer', 'pending', 'https://idp.test', 's')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(admin::flag_default_passwords(&pool)
        .await
        .unwrap()
        .is_empty());
}

// ---------- Einzelrechte ----------

async fn set_perms(pool: &PgPool, name: &str, perms: Option<&[&str]>) {
    let v: Option<Vec<String>> = perms.map(|p| p.iter().map(|s| (*s).to_owned()).collect());
    sqlx::query("UPDATE admin_users SET permissions = $2 WHERE username = $1")
        .bind(name)
        .bind(v)
        .execute(pool)
        .await
        .unwrap();
}

/// Betreiber-Rechte plus `users.manage`: ein Verwalter, der kein Administrator ist.
fn manager_perms() -> Vec<String> {
    let mut v: Vec<String> = Role::Operator
        .permissions()
        .iter()
        .map(|p| p.name().to_owned())
        .collect();
    v.push("users.manage".into());
    v
}

async fn mk_manager(pool: &PgPool, name: &str) -> i64 {
    let id = mk(pool, name, "operator", "active").await;
    let v = manager_perms();
    let refs: Vec<&str> = v.iter().map(String::as_str).collect();
    set_perms(pool, name, Some(&refs)).await;
    id
}

#[sqlx::test(migrations = "./migrations")]
async fn manager_without_all_admin_rights_cannot_take_over_an_admin(pool: PgPool) {
    let app = router(state(pool.clone()));
    let adm = mk(&pool, "the-admin", "admin", "active").await;
    mk(&pool, "second-admin", "admin", "active").await;
    mk_manager(&pool, "mgr").await;
    let m = login(&app, "mgr").await;
    let url = |id: i64, tail: &str| format!("/api/v1/users/{id}{tail}");
    // Passwort zurücksetzen, sperren, ändern, löschen: alles 403 mit Klartext.
    for (method, tail, body) in [
        (Method::POST, "/reset-password", json!({})),
        (Method::POST, "/lock", json!({})),
        (Method::POST, "/unlock", json!({})),
        (Method::PATCH, "", json!({"display_name": "Neu"})),
        (
            Method::DELETE,
            "",
            json!({"confirm_name": "the-admin", "confirm_password": PW}),
        ),
    ] {
        let r = call(&app, method.clone(), &url(adm, tail), &m.h(), Some(body)).await;
        assert_eq!(
            r.status,
            StatusCode::FORBIDDEN,
            "{method} {tail}: {}",
            r.raw
        );
        assert!(r.raw.contains("Rechte"), "Klartext fehlt: {}", r.raw);
    }
    // Das Konto des Administrators ist unverändert.
    let st: String = sqlx::query_scalar("SELECT status FROM admin_users WHERE id = $1")
        .bind(adm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(st, "active");
}

#[sqlx::test(migrations = "./migrations")]
async fn nobody_can_grant_rights_they_do_not_have(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    mk_manager(&pool, "mgr").await;
    let victim = mk(&pool, "vic", "viewer", "active").await;
    let m = login(&app, "mgr").await;
    // Anlegen mit Rolle Administrator oder mit einzelnem Recht, das der Verwalter nicht hat.
    for body in [
        json!({"display_name": "n1", "auth_kind": "local", "role": "admin", "confirm_password": PW}),
        json!({"display_name": "n2", "auth_kind": "local", "role": "viewer", "permissions": ["hosts.read", "audit.read"], "confirm_password": PW}),
        json!({"display_name": "n3", "auth_kind": "local", "role": "viewer", "permissions": ["hosts.read", "oidc.manage", "settings.read"], "confirm_password": PW}),
    ] {
        let r = call(&app, Method::POST, "/api/v1/users", &m.h(), Some(body)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    }
    // Einem anderen Rechte geben, die man nicht hat.
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{victim}"),
        &m.h(),
        Some(json!({"permissions": ["hosts.read", "audit.read"], "confirm_name": "vic", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    // Sich selbst Rechte geben (auch solche, die er hätte): verboten.
    let me: i64 = sqlx::query_scalar("SELECT id FROM admin_users WHERE username = 'mgr'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{me}"),
        &m.h(),
        Some(json!({"permissions": ["hosts.read"], "confirm_name": "mgr", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    // Erlaubt: Rechte, die er hat (kein sensibles Recht, also ohne Passwort), mit Namensbestätigung.
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{victim}"),
        &m.h(),
        Some(json!({"permissions": ["hosts.read", "hosts.write"], "confirm_name": "vic"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.json["permissions"], json!(["hosts.read", "hosts.write"]));
    assert_eq!(r.json["custom_permissions"], true);
}

#[sqlx::test(migrations = "./migrations")]
async fn sensitive_grants_and_role_changes_need_the_password(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    let victim = mk(&pool, "vic", "viewer", "active").await;
    let a = login(&app, "boss").await;
    let url = format!("/api/v1/users/{victim}");
    // Sensibles Recht ohne Passwort: abgelehnt; mit falscher Namensbestätigung: 400.
    let r = call(
        &app,
        Method::PATCH,
        &url,
        &a.h(),
        Some(json!({"permissions": ["audit.read"], "confirm_name": "vic"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    let r = call(&app, Method::PATCH, &url, &a.h(), Some(json!({"permissions": ["audit.read"], "confirm_name": "falsch", "confirm_password": PW}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.raw);
    // Rollenwechsel (auch zu Betreiber) ohne Passwort: abgelehnt.
    let r = call(
        &app,
        Method::PATCH,
        &url,
        &a.h(),
        Some(json!({"role": "operator", "confirm_name": "vic"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    let r = call(
        &app,
        Method::PATCH,
        &url,
        &a.h(),
        Some(json!({"permissions": ["audit.read"], "confirm_name": "vic", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    // Rollenwechsel setzt die Einzelrechte auf die Vorlage zurück.
    let r = call(
        &app,
        Method::PATCH,
        &url,
        &a.h(),
        Some(json!({"role": "operator", "confirm_name": "vic", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.json["custom_permissions"], false);
    let stored: Option<Vec<String>> =
        sqlx::query_scalar("SELECT permissions FROM admin_users WHERE id = $1")
            .bind(victim)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(stored.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_names_and_missing_prerequisites_are_not_granted(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    mk(&pool, "u-unknown", "viewer", "active").await;
    mk(&pool, "u-nodeps", "viewer", "active").await;
    mk(&pool, "u-allbogus", "admin", "active").await;
    // Unbekannter Name daneben: bekannte Rechte gelten, der unbekannte ist nie ein Fehler und nie erlaubt.
    set_perms(&pool, "u-unknown", Some(&["hosts.read", "hosts.erase", ""])).await;
    // Schreibrecht ohne Leserecht in den gespeicherten Daten: fällt weg (auch hosts.delete kaskadiert).
    set_perms(
        &pool,
        "u-nodeps",
        Some(&["hosts.write", "hosts.delete", "cves.read"]),
    )
    .await;
    // Nur Unbekanntes: keine Rechte (nicht "wie die Rolle").
    set_perms(&pool, "u-allbogus", Some(&["alles.erlaubt"])).await;
    let get = |app: Router, s: Sess, path: &'static str| async move {
        call(&app, Method::GET, path, &s.h(), None).await.status
    };
    let s = login(&app, "u-unknown").await;
    assert_eq!(
        get(app.clone(), s.clone(), "/api/v1/hosts").await,
        StatusCode::OK
    );
    assert_eq!(
        get(app.clone(), s.clone(), "/api/v1/cves").await,
        StatusCode::FORBIDDEN
    );
    let s = login(&app, "u-nodeps").await;
    assert_eq!(
        get(app.clone(), s.clone(), "/api/v1/hosts").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(app.clone(), s.clone(), "/api/v1/cves").await,
        StatusCode::OK
    );
    let r = call(&app, Method::DELETE, "/api/v1/hosts/1", &s.h(), None).await;
    assert_eq!(
        r.status,
        StatusCode::FORBIDDEN,
        "hosts.delete ohne hosts.read/write"
    );
    let s = login(&app, "u-allbogus").await;
    assert_eq!(
        get(app.clone(), s.clone(), "/api/v1/hosts").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(app.clone(), s, "/api/v1/users").await,
        StatusCode::FORBIDDEN
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn api_rejects_unknown_rights_and_missing_prerequisites(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    let victim = mk(&pool, "vic", "viewer", "active").await;
    let a = login(&app, "boss").await;
    let url = format!("/api/v1/users/{victim}");
    for perms in [
        json!(["hosts.erase"]),
        json!(["hosts.write"]),
        json!(["hosts.read", "hosts.delete"]),
    ] {
        let r = call(
            &app,
            Method::PATCH,
            &url,
            &a.h(),
            Some(json!({"permissions": perms, "confirm_name": "vic"})),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{perms}: {}", r.raw);
    }
    // Leserecht später entziehen: die abhängigen Schreibrechte fallen mit weg.
    let r = call(&app, Method::PATCH, &url, &a.h(), Some(json!({"permissions": ["hosts.read", "hosts.write", "hosts.delete", "cves.read"], "confirm_name": "vic"}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    set_perms(
        &pool,
        "vic",
        Some(&["hosts.write", "hosts.delete", "cves.read"]),
    )
    .await; // hosts.read entzogen
    let r = call(&app, Method::GET, "/api/v1/users", &a.h(), None).await;
    let vic = r.json["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == victim)
        .unwrap()
        .clone();
    assert_eq!(
        vic["permissions"],
        json!(["cves.read"]),
        "abhängige Rechte fallen mit weg"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn secrets_rights_are_separate_from_write_rights(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    mk(&pool, "nosecret", "operator", "active").await;
    let v: Vec<String> = Role::Operator
        .permissions()
        .iter()
        .map(|p| p.name().to_owned())
        .filter(|n| !n.ends_with(".secrets"))
        .collect();
    let refs: Vec<&str> = v.iter().map(String::as_str).collect();
    set_perms(&pool, "nosecret", Some(&refs)).await;
    let s = login(&app, "nosecret").await;
    // Kanal: Geheimnis setzen oder löschen verboten, ohne Geheimnis nicht an dieser Stelle abgewiesen (erst später 404).
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/ntfy",
        &s.h(),
        Some(json!({"enabled": true, "secret": "TESTWERT-geheim-1234"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    assert!(
        !r.raw.contains("TESTWERT-geheim"),
        "Geheimnis in der Antwort"
    );
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/ntfy",
        &s.h(),
        Some(json!({"enabled": true, "clear_secret": true})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/ntfy",
        &s.h(),
        Some(json!({"enabled": true})),
    )
    .await;
    assert_ne!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    // Quelle: Schlüssel verboten.
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/feeds/nvd",
        &s.h(),
        Some(json!({"secret": "TESTWERT-schluessel-12"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
    let r = call(
        &app,
        Method::POST,
        "/api/v1/feeds",
        &s.h(),
        Some(json!({"type": "nvd", "secret": "TESTWERT-schluessel-12"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
}

/// Zwei Verwalter löschen sich gleichzeitig gegenseitig: einer bleibt immer übrig (Sperre in der Transaktion).
#[sqlx::test(migrations = "./migrations")]
async fn last_local_manager_survives_parallel_deletes(pool: PgPool) {
    let app = router(state(pool.clone()));
    let a = mk_manager(&pool, "mgr-a").await;
    let b = mk_manager(&pool, "mgr-b").await;
    let sa = login(&app, "mgr-a").await;
    let sb = login(&app, "mgr-b").await;
    let del = |app: Router, s: Sess, id: i64, name: &'static str| async move {
        call(
            &app,
            Method::DELETE,
            &format!("/api/v1/users/{id}"),
            &s.h(),
            Some(json!({"confirm_name": name, "confirm_password": PW})),
        )
        .await
        .status
    };
    let (r1, r2) = tokio::join!(
        del(app.clone(), sa, b, "mgr-b"),
        del(app.clone(), sb, a, "mgr-a")
    );
    let alive: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE username IN ('mgr-a','mgr-b') AND deleted_at IS NULL AND status = 'active'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(alive >= 1, "beide Verwalter weg: {r1} {r2}");
    assert!(
        r1 != StatusCode::NO_CONTENT || r2 != StatusCode::NO_CONTENT,
        "beide Löschungen gelangen"
    );
}

/// Entzug von `users.manage` beim letzten (lokalen) Verwalter wird abgelehnt.
#[sqlx::test(migrations = "./migrations")]
async fn revoking_users_manage_from_the_last_manager_is_refused(pool: PgPool) {
    let app = router(state(pool.clone()));
    let only = mk_manager(&pool, "only-mgr").await;
    // Ein zweites, eigenes Konto mit allen Rechten, aber gesperrt (zählt nicht als Verwalter).
    mk(&pool, "frozen-admin", "admin", "locked").await;
    mk(&pool, "boss", "admin", "active").await;
    let a = login(&app, "boss").await;
    // boss ist Verwalter und lokal: Entzug beim anderen ist erlaubt. Dann boss herabstufen lassen: nicht möglich.
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{only}"),
        &a.h(),
        Some(json!({"permissions": ["hosts.read"], "confirm_name": "only-mgr", "confirm_password": PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    // boss ist nun der einzige Verwalter: ein anderer Verwalter gibt es nicht, also auch kein Weg, ihn herabzustufen; Selbständerung verboten.
    let boss: i64 = sqlx::query_scalar("SELECT id FROM admin_users WHERE username = 'boss'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{boss}"),
        &a.h(),
        Some(
            json!({"permissions": ["hosts.read"], "confirm_name": "boss", "confirm_password": PW}),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.raw);
}

/// Eine Rechteänderung beendet die Sitzungen des Benutzers und steht ohne Geheimnisse im Protokoll.
#[sqlx::test(migrations = "./migrations")]
async fn permission_change_ends_sessions_and_is_audited_without_secrets(pool: PgPool) {
    let app = router(state(pool.clone()));
    mk(&pool, "boss", "admin", "active").await;
    let id = mk(&pool, "target", "viewer", "active").await;
    let a = login(&app, "boss").await;
    let s = login(&app, "target").await;
    let alive = |s: Sess| {
        let app = app.clone();
        async move {
            call(&app, Method::GET, "/api/v1/hosts", &s.h(), None)
                .await
                .status
                == StatusCode::OK
        }
    };
    assert!(alive(s.clone()).await);
    let r = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/users/{id}"),
        &a.h(),
        Some(json!({"permissions": ["hosts.read", "cves.read"], "confirm_name": "target"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert!(!alive(s).await, "alte Sitzung nach Rechteänderung");
    let log: String = sqlx::query_scalar(
        "SELECT string_agg(action || ' ' || coalesce(target,''), ',') FROM audit_log WHERE action = 'user.permissions_changed'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(log.contains("user.permissions_changed"), "{log}");
    assert!(!log.contains(PW), "Passwort im Protokoll");
}

/// Die Migration fügt nur eine Spalte ohne Vorgabe hinzu: bestehende Konten behalten `NULL` und damit die Rechte ihrer Rolle.
#[sqlx::test(migrations = "./migrations")]
async fn migration_leaves_existing_accounts_on_their_role_template(pool: PgPool) {
    let app = router(state(pool.clone()));
    let nullable: (String, Option<String>) = sqlx::query_as(
        "SELECT is_nullable, column_default FROM information_schema.columns WHERE table_name = 'admin_users' AND column_name = 'permissions'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(nullable.0, "YES");
    assert!(
        nullable.1.is_none(),
        "keine Vorgabe, sonst änderte die Migration Bestandskonten"
    );
    for (n, role) in [
        ("old-admin", "admin"),
        ("old-op", "operator"),
        ("old-ro", "viewer"),
    ] {
        mk(&pool, n, role, "active").await;
        let p: Option<Vec<String>> =
            sqlx::query_scalar("SELECT permissions FROM admin_users WHERE username = $1")
                .bind(n)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(p.is_none(), "{n}: Rechte folgen der Rolle");
        let me = call(
            &app,
            Method::GET,
            "/api/v1/auth/me",
            &login(&app, n).await.h(),
            None,
        )
        .await;
        let got: Vec<String> = serde_json::from_value(me.json["permissions"].clone()).unwrap();
        let want: Vec<String> = authz::effective(Role::parse(role).unwrap(), None)
            .iter()
            .map(|p| p.name().to_owned())
            .collect();
        assert_eq!(got, want, "{n}");
    }
}
