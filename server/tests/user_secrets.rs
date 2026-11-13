//! Einmalpasswörter, Passwörter und das OIDC-Client-Secret dürfen in keinem Log stehen (auch nicht bei TRACE).
//! Eigene Test-Binary, damit der globale Log-Collector keine anderen Tests stört. Alle Werte sind Testwerte.

use axum::body::Body;
use axum::http::{header, Method, Request};
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::{admin, router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const ADMIN_PW: &str = "TESTWERT-admin-passwort-77";
const NEW_PW: &str = "TESTWERT-neues-passwort-88";
const CLIENT_SECRET: &str = "TESTWERT-client-secret-99";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

async fn call(
    app: &axum::Router,
    method: Method,
    uri: &str,
    h: &[(&str, &str)],
    body: Option<Value>,
) -> (u16, Value, Vec<String>) {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in h {
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
    let cookies = parts
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    (
        parts.status.as_u16(),
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookies,
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn passwords_and_client_secret_never_reach_logs(pool: PgPool) {
    let cap = Capture::default();
    tracing_subscriber::fmt()
        .with_writer(cap.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .init();
    let cfg = Config::from_sources(None, &|k| match k {
        "PATCHWATCH_SECRET_KEY" => Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".to_owned()),
        "PATCHWATCH_PUBLIC_URL" => Some("https://pw.example".to_owned()),
        _ => None,
    })
    .unwrap();
    let app = router(AppState::new(pool.clone(), cfg).unwrap());
    admin::upsert_admin(&pool, "boss", ADMIN_PW).await.unwrap();
    let (st, j, ck) = call(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username":"boss","password":ADMIN_PW})),
    )
    .await;
    assert_eq!(st, 200);
    let cookie = ck[0].split(';').next().unwrap().to_owned();
    let csrf = j["csrf_token"].as_str().unwrap().to_owned();
    let h = [("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];

    // Benutzer anlegen (Einmalpasswort in der Antwort), zurücksetzen, anmelden, Passwort ändern, Client-Secret speichern.
    let (st, j, _) = call(
        &app,
        Method::POST,
        "/api/v1/users",
        &h,
        Some(json!({"display_name":"anna","auth_kind":"local","role":"viewer"})),
    )
    .await;
    assert!(st == 200 || st == 201, "Anlegen: {st}");
    let once = j["initial_password"]
        .as_str()
        .expect("Einmalpasswort in der Antwort")
        .to_owned();
    let id = j["user"]["id"].as_i64().unwrap();
    let (_, j2, _) = call(
        &app,
        Method::POST,
        &format!("/api/v1/users/{id}/reset-password"),
        &h,
        None,
    )
    .await;
    let once2 = j2["initial_password"].as_str().unwrap().to_owned();
    assert_ne!(once, once2);
    let (st, j, ck) = call(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username":"anna","password":once2})),
    )
    .await;
    assert_eq!(st, 200);
    let c2 = ck[0].split(';').next().unwrap().to_owned();
    let t2 = j["csrf_token"].as_str().unwrap().to_owned();
    let (st, _, _) = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        &[("cookie", c2.as_str()), ("x-csrf-token", t2.as_str())],
        Some(json!({"current_password":once2,"new_password":NEW_PW})),
    )
    .await;
    assert!(st == 200 || st == 204, "Passwortwechsel: {st}");
    let (st, _, _) = call(&app, Method::PUT, "/api/v1/settings/oidc", &h, Some(json!({"enabled":false,"issuer":"https://idp.example","client_id":"c","client_secret":CLIENT_SECRET}))).await;
    assert_eq!(st, 200);
    // Fehlversuche und Fehlerpfade ebenfalls.
    call(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username":"anna","password":"TESTWERT-falsch-123456"})),
    )
    .await;

    let log = String::from_utf8_lossy(&cap.0.lock().unwrap()).into_owned();
    assert!(
        !log.is_empty(),
        "der Log-Mitschnitt ist leer: Test wäre wertlos"
    );
    for (what, secret) in [
        ("Einmalpasswort", &once),
        ("zweites Einmalpasswort", &once2),
        ("Admin-Passwort", &ADMIN_PW.to_owned()),
        ("neues Passwort", &NEW_PW.to_owned()),
        ("Client-Secret", &CLIENT_SECRET.to_owned()),
        ("Fehlversuch", &"TESTWERT-falsch-123456".to_owned()),
    ] {
        assert!(!log.contains(secret.as_str()), "{what} steht im Log");
    }
}
