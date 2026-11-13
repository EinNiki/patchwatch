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
        (Method::DELETE, "/api/v1/hosts/1", HostsWrite, true),
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
    for p in authz::ALL {
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
        Some(json!({"role": "operator", "confirm_name": "u-role"})),
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
