//! Zwei-Faktor (TOTP), Sitzungsübersicht und einstellbare Anmeldedauer.
//! Wegwerf-Datenbank (sqlx::test); alle Passwörter sind eindeutig gekennzeichnete Testwerte.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::totp;
use patchwatch_server::{admin, router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const PW: &str = "TESTWERT-passwort-0001";

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    json: Value,
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
    let (parts, body) = app.clone().oneshot(req).await.unwrap().into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Resp {
        status: parts.status,
        headers: parts.headers,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

fn app(pool: PgPool) -> Router {
    let cfg = Config::from_sources(None, &|k| {
        (k == "PATCHWATCH_TRUST_PROXY").then(|| "true".to_owned())
    })
    .unwrap();
    router(AppState::new(pool, cfg).unwrap())
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
fn fresh_ip() -> String {
    let n = NEXT_IP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("10.8.{}.{}", n / 250, n % 250 + 1)
}

fn sess_from(r: &Resp) -> Sess {
    Sess {
        cookie: r
            .headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
        csrf: r.json["csrf_token"].as_str().unwrap().to_owned(),
    }
}

/// Erster Schritt der Anmeldung (Passwort); gibt die rohe Antwort zurück.
async fn password_step(app: &Router, name: &str, pw: &str) -> Resp {
    call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        &[
            ("x-forwarded-for", &fresh_ip()),
            ("user-agent", "TestBrowser/1.0 (Linux)"),
        ],
        Some(json!({"username": name, "password": pw})),
    )
    .await
}

async fn login(app: &Router, name: &str) -> Sess {
    let r = password_step(app, name, PW).await;
    assert_eq!(r.status, StatusCode::OK);
    sess_from(&r)
}

async fn mk(pool: &PgPool, name: &str, role: &str) -> i64 {
    admin::upsert_admin(pool, name, PW).await.unwrap();
    sqlx::query_scalar("UPDATE admin_users SET role = $2 WHERE username = $1 RETURNING id")
        .bind(name)
        .bind(role)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn code_at(secret_b32: &str, offset: i64) -> String {
    let s = totp::base32_decode(secret_b32).unwrap();
    let step = (now() / totp::STEP_SECS) as i64 + offset;
    format!("{:06}", totp::code_for_step(&s, step as u64))
}

/// Richtet Zwei-Faktor ein; gibt (Geheimnis, Wiederherstellungscodes) zurück.
async fn enable_mfa(app: &Router, s: &Sess) -> (String, Vec<String>) {
    let r = call(
        app,
        Method::POST,
        "/api/v1/auth/2fa/setup",
        &s.h(),
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let secret = r.json["secret"].as_str().unwrap().to_owned();
    assert!(r.json["otpauth_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/patchwatch:"));
    // Falscher Code schaltet nichts ein.
    let bad = call(
        app,
        Method::POST,
        "/api/v1/auth/2fa/enable",
        &s.h(),
        Some(json!({"code": "000000"})),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let ok = call(
        app,
        Method::POST,
        "/api/v1/auth/2fa/enable",
        &s.h(),
        Some(json!({"code": code_at(&secret, 0)})),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json);
    let codes: Vec<String> = ok.json["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    (secret, codes)
}

async fn mfa_step(app: &Router, token: &str, code: &str) -> Resp {
    call(
        app,
        Method::POST,
        "/api/v1/auth/login/mfa",
        &[("x-forwarded-for", &fresh_ip())],
        Some(json!({"mfa_token": token, "code": code})),
    )
    .await
}

#[sqlx::test(migrations = "./migrations")]
async fn login_needs_second_factor(pool: PgPool) {
    mk(&pool, "mfa1", "admin").await;
    let app = app(pool.clone());
    let s = login(&app, "mfa1").await;
    let (secret, _) = enable_mfa(&app, &s).await;

    // Passwort allein reicht nicht mehr: kein Cookie, nur ein Zwischenschritt.
    let r = password_step(&app, "mfa1", PW).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["mfa_required"], true);
    assert!(r.headers.get(header::SET_COOKIE).is_none());
    assert!(r.json.get("csrf_token").is_none());
    let token = r.json["mfa_token"].as_str().unwrap().to_owned();

    // Falscher Code, dann richtiger Code (der Folgeschritt, denn der aktuelle wurde bei der Einrichtung verbraucht).
    assert_eq!(
        mfa_step(&app, &token, "123456").await.status,
        StatusCode::UNAUTHORIZED
    );
    let code = code_at(&secret, 1);
    let ok = mfa_step(&app, &token, &code).await;
    assert_eq!(ok.status, StatusCode::OK);
    let s2 = sess_from(&ok);
    let me = call(&app, Method::GET, "/api/v1/auth/me", &s2.h(), None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json["totp_enabled"], true);

    // Token ist einmalig; derselbe Code gilt auch mit neuem Token nicht noch einmal.
    assert_eq!(
        mfa_step(&app, &token, &code).await.status,
        StatusCode::UNAUTHORIZED
    );
    let r2 = password_step(&app, "mfa1", PW).await;
    let t2 = r2.json["mfa_token"].as_str().unwrap().to_owned();
    assert_eq!(
        mfa_step(&app, &t2, &code).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Falsches Passwort verrät nichts über Zwei-Faktor.
    assert_eq!(
        password_step(&app, "mfa1", "falsch-falsch-falsch")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // Das Geheimnis steht nie in /me oder /2fa.
    let st = call(&app, Method::GET, "/api/v1/auth/2fa", &s2.h(), None).await;
    assert_eq!(st.json["enabled"], true);
    assert_eq!(st.json["recovery_codes_left"], 10);
    assert!(!st.json.to_string().contains(&secret));
    assert!(!me.json.to_string().contains(&secret));
}

#[sqlx::test(migrations = "./migrations")]
async fn recovery_code_works_once(pool: PgPool) {
    mk(&pool, "mfa2", "admin").await;
    let app = app(pool.clone());
    let s = login(&app, "mfa2").await;
    let (_, codes) = enable_mfa(&app, &s).await;
    let t = password_step(&app, "mfa2", PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    // Schreibweise egal (Großbuchstaben, ohne Bindestrich).
    let weird = codes[0].replace('-', "").to_uppercase();
    assert_eq!(mfa_step(&app, &t, &weird).await.status, StatusCode::OK);
    let t = password_step(&app, "mfa2", PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        mfa_step(&app, &t, &codes[0]).await.status,
        StatusCode::UNAUTHORIZED
    );
    // Ein anderer Code geht weiter.
    let t = password_step(&app, "mfa2", PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(mfa_step(&app, &t, &codes[1]).await.status, StatusCode::OK);
    let s = login_after_recovery(&app, &codes[2]).await;
    let st = call(&app, Method::GET, "/api/v1/auth/2fa", &s.h(), None).await;
    assert_eq!(st.json["recovery_codes_left"], 7);
}

async fn login_after_recovery(app: &Router, code: &str) -> Sess {
    let t = password_step(app, "mfa2", PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    sess_from(&mfa_step(app, &t, code).await)
}

#[sqlx::test(migrations = "./migrations")]
async fn too_many_wrong_codes_kill_the_token(pool: PgPool) {
    mk(&pool, "mfa3", "admin").await;
    let app = app(pool.clone());
    let s = login(&app, "mfa3").await;
    let (secret, _) = enable_mfa(&app, &s).await;
    let t = password_step(&app, "mfa3", PW).await.json["mfa_token"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..5 {
        assert_eq!(
            mfa_step(&app, &t, "111111").await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    // Danach hilft nicht einmal der richtige Code: neu mit dem Passwort beginnen.
    assert_eq!(
        mfa_step(&app, &t, &code_at(&secret, 1)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        mfa_step(&app, "unbekanntes-token", "123456").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn disable_needs_password_and_code_and_admin_can_reset(pool: PgPool) {
    mk(&pool, "mfa4", "admin").await;
    mk(&pool, "boss", "admin").await;
    let app = app(pool.clone());
    let s = login(&app, "mfa4").await;
    let (secret, codes) = enable_mfa(&app, &s).await;
    // Schon eingeschaltet: nochmal einrichten geht nicht.
    let again = call(
        &app,
        Method::POST,
        "/api/v1/auth/2fa/setup",
        &s.h(),
        Some(json!({})),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    let no_pw = call(
        &app,
        Method::POST,
        "/api/v1/auth/2fa/disable",
        &s.h(),
        Some(json!({"code": code_at(&secret, 1)})),
    )
    .await;
    assert_eq!(no_pw.status, StatusCode::FORBIDDEN);
    let bad_code = call(
        &app,
        Method::POST,
        "/api/v1/auth/2fa/disable",
        &s.h(),
        Some(json!({"code": "000000", "password": PW})),
    )
    .await;
    assert_eq!(bad_code.status, StatusCode::FORBIDDEN);
    let ok = call(
        &app,
        Method::POST,
        "/api/v1/auth/2fa/disable",
        &s.h(),
        Some(json!({"code": codes[0], "password": PW})),
    )
    .await;
    assert_eq!(ok.status, StatusCode::NO_CONTENT);
    assert!(password_step(&app, "mfa4", PW)
        .await
        .headers
        .get(header::SET_COOKIE)
        .is_some());
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM totp_recovery_codes WHERE admin_id = (SELECT id FROM admin_users WHERE username = 'mfa4')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);

    // Verwalter setzt ein verlorenes Gerät zurück; die Sitzungen des Kontos enden.
    let s = login(&app, "mfa4").await;
    enable_mfa(&app, &s).await;
    let boss = login(&app, "boss").await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM admin_users WHERE username = 'mfa4'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let own = call(
        &app,
        Method::POST,
        "/api/v1/users/1/reset-2fa",
        &boss.h(),
        Some(json!({})),
    )
    .await;
    assert!(
        own.status == StatusCode::FORBIDDEN
            || own.status == StatusCode::NOT_FOUND
            || own.status == StatusCode::NO_CONTENT
    );
    let r = call(
        &app,
        Method::POST,
        &format!("/api/v1/users/{id}/reset-2fa"),
        &boss.h(),
        Some(json!({})),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        call(&app, Method::GET, "/api/v1/auth/me", &s.h(), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert!(password_step(&app, "mfa4", PW)
        .await
        .headers
        .get(header::SET_COOKIE)
        .is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn sessions_list_and_revoke(pool: PgPool) {
    mk(&pool, "dev1", "admin").await;
    mk(&pool, "other", "admin").await;
    let app = app(pool.clone());
    let a = login(&app, "dev1").await;
    let b = login(&app, "dev1").await;
    let o = login(&app, "other").await;

    let l = call(&app, Method::GET, "/api/v1/auth/sessions", &a.h(), None).await;
    let list = l.json["sessions"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list.iter().filter(|x| x["current"] == true).count(), 1);
    assert_eq!(list[0]["user_agent"], "TestBrowser/1.0 (Linux)");
    assert_eq!(list[0]["method"], "password");
    assert!(list[0]["ip"].as_str().unwrap().starts_with("10.8."));
    // Keine Geheimnisse in der Liste (weder Cookie noch CSRF).
    let raw = l.json.to_string();
    assert!(!raw.contains(a.cookie.split('=').nth(1).unwrap()));
    assert!(!raw.contains(&a.csrf));

    // Fremde Sitzungen eines anderen Kontos sind weder sichtbar noch beendbar.
    let other_id: String = sqlx::query_scalar("SELECT public_id::text FROM sessions s JOIN admin_users u ON u.id = s.admin_id WHERE u.username = 'other'").fetch_one(&pool).await.unwrap();
    assert!(!raw.contains(&other_id));
    let steal = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/auth/sessions/{other_id}"),
        &a.h(),
        None,
    )
    .await;
    assert_eq!(steal.status, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&app, Method::GET, "/api/v1/auth/me", &o.h(), None)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            Method::DELETE,
            "/api/v1/auth/sessions/kein-uuid",
            &a.h(),
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );

    // Die andere Sitzung beenden.
    let other_of_a = list.iter().find(|x| x["current"] == false).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let d = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/auth/sessions/{other_of_a}"),
        &a.h(),
        None,
    )
    .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    assert_eq!(
        call(&app, Method::GET, "/api/v1/auth/me", &b.h(), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, Method::GET, "/api/v1/auth/me", &a.h(), None)
            .await
            .status,
        StatusCode::OK
    );

    // Alle anderen abmelden, dann alle (auch dieses Gerät).
    let _c = login(&app, "dev1").await;
    let _d = login(&app, "dev1").await;
    let r = call(
        &app,
        Method::POST,
        "/api/v1/auth/sessions/revoke-all",
        &a.h(),
        Some(json!({})),
    )
    .await;
    assert_eq!(r.json["revoked"], 2);
    assert_eq!(
        call(&app, Method::GET, "/api/v1/auth/me", &a.h(), None)
            .await
            .status,
        StatusCode::OK
    );
    let r = call(
        &app,
        Method::POST,
        "/api/v1/auth/sessions/revoke-all",
        &a.h(),
        Some(json!({"include_current": true})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert_eq!(
        call(&app, Method::GET, "/api/v1/auth/me", &a.h(), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // Ohne CSRF-Token kein Abmelden.
    let x = login(&app, "dev1").await;
    let no_csrf = call(
        &app,
        Method::POST,
        "/api/v1/auth/sessions/revoke-all",
        &[("cookie", x.cookie.as_str())],
        Some(json!({})),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn session_lifetime_is_configurable(pool: PgPool) {
    mk(&pool, "ttl1", "admin").await;
    let app = app(pool.clone());
    let s = login(&app, "ttl1").await;
    let g = call(&app, Method::GET, "/api/v1/settings", &s.h(), None).await;
    assert_eq!(g.json["session_ttl_hours"], 12);
    for bad in [0, -5, 100000] {
        let r = call(
            &app,
            Method::PUT,
            "/api/v1/settings",
            &s.h(),
            Some(json!({"session_ttl_hours": bad})),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let ok = call(
        &app,
        Method::PUT,
        "/api/v1/settings",
        &s.h(),
        Some(json!({"session_ttl_hours": 2})),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    let r = password_step(&app, "ttl1", PW).await;
    let cookie = r
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.contains("Max-Age=7200"), "{cookie}");
    let hours: f64 = sqlx::query_scalar("SELECT (extract(epoch FROM (expires_at - created_at)) / 3600)::float8 FROM sessions ORDER BY created_at DESC LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!((hours - 2.0).abs() < 0.01, "{hours}");
    // Nur wer Einstellungen ändern darf.
    mk(&pool, "viewer", "viewer").await;
    let v = login(&app, "viewer").await;
    let no = call(
        &app,
        Method::PUT,
        "/api/v1/settings",
        &v.h(),
        Some(json!({"session_ttl_hours": 99})),
    )
    .await;
    assert_eq!(no.status, StatusCode::FORBIDDEN);
}
