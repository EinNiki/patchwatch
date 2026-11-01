//! OIDC-Anmeldung gegen einen lokalen Mock-Provider.
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use patchwatch_server::config::Config;
use patchwatch_server::{router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[derive(Clone, Default)]
struct Idp {
    base: String,
    nonce: Arc<Mutex<String>>,
    email: Arc<Mutex<String>>,
}

async fn start_idp() -> Idp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let idp = Idp {
        base: base.clone(),
        ..Default::default()
    };
    async fn discovery(State(i): State<Idp>) -> Json<Value> {
        Json(json!({
            "issuer": i.base,
            "authorization_endpoint": format!("{}/authorize", i.base),
            "token_endpoint": format!("{}/token", i.base),
        }))
    }
    async fn token(State(i): State<Idp>) -> Json<Value> {
        let claims = json!({
            "iss": i.base, "aud": "pw-client", "sub": "u1",
            "exp": chrono::Utc::now().timestamp() + 300,
            "nonce": i.nonce.lock().unwrap().clone(),
            "email": i.email.lock().unwrap().clone(), "email_verified": true,
        });
        let part = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
        Json(
            json!({ "id_token": format!("{}.{}.sig", part(&json!({"alg":"none"})), part(&claims)), "access_token": "at" }),
        )
    }
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

fn app(pool: PgPool, idp: &Idp, extra: Option<(&str, &str)>) -> Router {
    let issuer = idp.base.clone();
    let cfg = Config::from_sources(None, &|k| {
        let v = match k {
            "PATCHWATCH_OIDC_ISSUER" => &issuer,
            "PATCHWATCH_OIDC_CLIENT_ID" => "pw-client",
            "PATCHWATCH_OIDC_CLIENT_SECRET" => "secret",
            "PATCHWATCH_OIDC_REDIRECT_URL" => "https://pw.example/api/v1/auth/oidc/callback",
            "PATCHWATCH_OIDC_ALLOWED_DOMAINS" => "example.org",
            "PATCHWATCH_OIDC_ALLOWED_EMAILS" => "boss@other.org",
            _ => return extra.filter(|(n, _)| *n == k).map(|(_, v)| v.to_owned()),
        };
        Some(v.to_owned())
    })
    .unwrap();
    router(AppState::new(pool, cfg).unwrap())
}

async fn get_path(app: &Router, uri: &str, cookie: Option<&str>) -> axum::http::Response<Body> {
    let mut b = Request::builder().uri(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    app.clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn param(url: &str, key: &str) -> String {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap()
}

/// Startet die Anmeldung und liefert (state, Cookie-Header).
async fn begin(app: &Router, idp: &Idp) -> (String, String) {
    let login = get_path(app, "/api/v1/auth/oidc/login", None).await;
    assert!(login.status().is_redirection());
    let loc = login.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(loc.starts_with(&format!("{}/authorize", idp.base)), "{loc}");
    assert_eq!(param(&loc, "code_challenge_method"), "S256");
    *idp.nonce.lock().unwrap() = param(&loc, "nonce");
    let cookie = login.headers()[header::SET_COOKIE].to_str().unwrap();
    let pair = cookie.split(';').next().unwrap().to_owned();
    (param(&loc, "state"), pair)
}

#[sqlx::test(migrations = "./migrations")]
async fn allowed_user_gets_a_session(pool: PgPool) {
    let idp = start_idp().await;
    let app = app(pool.clone(), &idp, None);
    let providers = get_path(&app, "/api/v1/auth/providers", None).await;
    assert_eq!(providers.status(), StatusCode::OK);

    *idp.email.lock().unwrap() = "Alice@Example.org".into();
    let (state, cookie) = begin(&app, &idp).await;
    let cb = get_path(
        &app,
        &format!("/api/v1/auth/oidc/callback?code=c&state={state}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(cb.headers()[header::LOCATION], "/");
    let cookies: Vec<_> = cb
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let session = cookies
        .iter()
        .find(|c| c.starts_with("pw_session="))
        .expect("Sitzungs-Cookie");
    let me = get_path(
        &app,
        "/api/v1/auth/me",
        Some(session.split(';').next().unwrap()),
    )
    .await;
    assert_eq!(me.status(), StatusCode::OK);
    let user: String = sqlx::query_scalar("SELECT username FROM admin_users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(user, "oidc:alice@example.org");

    // Der state ist nur einmal verwendbar.
    let again = get_path(
        &app,
        &format!("/api/v1/auth/oidc/callback?code=c&state={state}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(again.headers()[header::LOCATION], "/login?error=oidc");
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_user_or_foreign_browser_is_rejected(pool: PgPool) {
    let idp = start_idp().await;
    let app = app(pool.clone(), &idp, None);

    // E-Mail nicht auf der Allow-List.
    *idp.email.lock().unwrap() = "mallory@evil.test".into();
    let (state, cookie) = begin(&app, &idp).await;
    let cb = get_path(
        &app,
        &format!("/api/v1/auth/oidc/callback?code=c&state={state}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(cb.headers()[header::LOCATION], "/login?error=oidc");
    assert!(cb
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .all(|v| !v.to_str().unwrap().starts_with("pw_session=")));

    // Erlaubter Benutzer, aber der Browser hat das state-Cookie nicht (Login-CSRF).
    *idp.email.lock().unwrap() = "bob@example.org".into();
    let (state, _cookie) = begin(&app, &idp).await;
    let cb = get_path(
        &app,
        &format!("/api/v1/auth/oidc/callback?code=c&state={state}"),
        None,
    )
    .await;
    assert_eq!(cb.headers()[header::LOCATION], "/login?error=oidc");
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

#[test]
fn oidc_needs_an_allow_list() {
    let env = |k: &str| match k {
        "PATCHWATCH_OIDC_ISSUER" => Some("https://idp.example".to_owned()),
        "PATCHWATCH_OIDC_CLIENT_ID" => Some("x".to_owned()),
        "PATCHWATCH_OIDC_CLIENT_SECRET" => Some("y".to_owned()),
        "PATCHWATCH_OIDC_REDIRECT_URL" => Some("https://pw/cb".to_owned()),
        _ => None,
    };
    assert!(Config::from_sources(None, &env).is_err());
}
