//! OIDC gegen einen lokalen Mock-Anbieter (ES256-Schlüssel zur Laufzeit erzeugt, kein echter Identitätsanbieter).
//! Der Mock lauscht auf einer privaten Adresse des Rechners (Loopback ist für Abrufe immer gesperrt) und wird über
//! `PATCHWATCH_NOTIFY_ALLOWED_HOSTS` freigegeben. Alle Geheimnisse sind eindeutig gekennzeichnete Testwerte.
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::{admin, router, AppState};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const CLIENT_SECRET: &str = "TESTWERT-client-secret-0001";
const PW: &str = "TESTWERT-passwort-0001";
const CODE: &str = "TESTWERT-code";

#[derive(Clone)]
struct Knobs {
    iss: Option<String>,
    aud: Value,
    azp: Option<String>,
    exp_in: i64,
    iat_off: i64,
    nbf_off: Option<i64>,
    nonce: Option<String>,
    sub: String,
    email: String,
    verified: Value,
    groups: Vec<String>,
    alg: String,
    kid: Option<String>,
    /// Index des Schlüssels, mit dem signiert wird (2 = nie veröffentlicht).
    sign: usize,
    /// Index des veröffentlichten Schlüssels.
    publish: usize,
    discovery: &'static str,
    // Vom Authorize-Aufruf übernommen:
    expected_nonce: String,
    challenge: String,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            iss: None,
            aud: json!("pw-client"),
            azp: None,
            exp_in: 300,
            iat_off: -5,
            nbf_off: None,
            nonce: None,
            sub: "sub-1".into(),
            email: "alice@example.org".into(),
            verified: json!(true),
            groups: vec![],
            alg: "ES256".into(),
            kid: None,
            sign: 0,
            publish: 0,
            discovery: "ok",
            expected_nonce: String::new(),
            challenge: String::new(),
        }
    }
}

struct Mock {
    base: String,
    host: String,
    knobs: Mutex<Knobs>,
    keys: Vec<EcdsaKeyPair>,
    jwks_hits: AtomicUsize,
    token_calls: AtomicUsize,
}

fn b64(v: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(v)
}

fn make_token(m: &Mock, k: &Knobs) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut c = json!({
        "iss": k.iss.clone().unwrap_or_else(|| m.base.clone()), "aud": k.aud, "exp": now + k.exp_in,
        "iat": now + k.iat_off, "nonce": k.nonce.clone().unwrap_or_else(|| k.expected_nonce.clone()),
        "sub": k.sub, "email": k.email, "email_verified": k.verified, "groups": k.groups,
    });
    if let Some(a) = &k.azp {
        c["azp"] = json!(a);
    }
    if let Some(n) = k.nbf_off {
        c["nbf"] = json!(now + n);
    }
    let kid = k
        .kid
        .clone()
        .unwrap_or_else(|| format!("k{}", k.sign.min(1) + 1));
    let head = json!({"alg": k.alg, "kid": kid, "typ": "JWT"});
    let input = format!(
        "{}.{}",
        b64(head.to_string().as_bytes()),
        b64(c.to_string().as_bytes())
    );
    let sig = match k.alg.as_str() {
        "none" => Vec::new(),
        "HS256" => {
            // Algorithmen-Verwechslung: HMAC mit dem öffentlichen Schlüssel als Geheimnis.
            let key =
                ring::hmac::Key::new(ring::hmac::HMAC_SHA256, m.keys[0].public_key().as_ref());
            ring::hmac::sign(&key, input.as_bytes()).as_ref().to_vec()
        }
        _ => m.keys[k.sign]
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap()
            .as_ref()
            .to_vec(),
    };
    format!("{input}.{}", b64(&sig))
}

async fn discovery(State(m): State<Arc<Mock>>) -> Json<Value> {
    let b = &m.base;
    let mode = m.knobs.lock().unwrap().discovery;
    let token = if mode == "foreign" {
        "http://203.0.113.9/token".to_owned()
    } else {
        format!("{b}/token")
    };
    let mut v = json!({
        "issuer": b, "authorization_endpoint": format!("{b}/authorize"), "token_endpoint": token,
        "jwks_uri": format!("{b}/jwks"),
    });
    if mode == "huge" {
        v["padding"] = json!("x".repeat(300 * 1024));
    }
    Json(v)
}

async fn jwks(State(m): State<Arc<Mock>>) -> Json<Value> {
    m.jwks_hits.fetch_add(1, Ordering::SeqCst);
    let i = m.knobs.lock().unwrap().publish;
    let p = m.keys[i].public_key().as_ref();
    Json(
        json!({"keys": [{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":format!("k{}", i + 1),
        "x": b64(&p[1..33]), "y": b64(&p[33..65])}]}),
    )
}

async fn token(
    State(m): State<Arc<Mock>>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    m.token_calls.fetch_add(1, Ordering::SeqCst);
    let k = m.knobs.lock().unwrap().clone();
    let basic_ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| STANDARD.decode(v).ok())
        .is_some_and(|v| v == format!("pw-client:{CLIENT_SECRET}").as_bytes());
    let post_ok = f.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET);
    let pkce_ok = f.get("code_verifier").is_some_and(|v| {
        b64(ring::digest::digest(&ring::digest::SHA256, v.as_bytes()).as_ref()) == k.challenge
    });
    if !(basic_ok || post_ok) || f.get("code").map(String::as_str) != Some(CODE) || !pkce_ok {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"id_token": make_token(&m, &k), "access_token": "TESTWERT-at"})),
    )
}

/// Eine private (nicht Loopback-)Adresse des Rechners, sonst `None` (Test wird übersprungen).
fn private_ip() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    match ip {
        std::net::IpAddr::V4(v4) if v4.is_private() => Some(ip.to_string()),
        _ => None,
    }
}

async fn start_mock() -> Option<Arc<Mock>> {
    let host = private_ip()?;
    let l = tokio::net::TcpListener::bind(format!("{host}:0"))
        .await
        .ok()?;
    let rng = SystemRandom::new();
    let keys = (0..3)
        .map(|_| {
            let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), &rng).unwrap()
        })
        .collect();
    let m = Arc::new(Mock {
        base: format!("http://{}", l.local_addr().unwrap()),
        host,
        knobs: Mutex::new(Knobs::default()),
        keys,
        jwks_hits: AtomicUsize::new(0),
        token_calls: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(m.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    Some(m)
}

fn cfg(m: &Mock, with_env_oidc: bool) -> Config {
    Config::from_sources(None, &|k| {
        let v = match k {
            "PATCHWATCH_TRUST_PROXY" => "true".to_owned(),
            "PATCHWATCH_NOTIFY_ALLOWED_HOSTS" => m.host.clone(),
            "PATCHWATCH_PUBLIC_URL" => "https://pw.example".to_owned(),
            "PATCHWATCH_SECRET_KEY" => STANDARD.encode([9u8; 32]),
            "PATCHWATCH_OIDC_ISSUER" if with_env_oidc => m.base.clone(),
            "PATCHWATCH_OIDC_CLIENT_ID" if with_env_oidc => "pw-client".to_owned(),
            "PATCHWATCH_OIDC_CLIENT_SECRET" if with_env_oidc => CLIENT_SECRET.to_owned(),
            _ => return None,
        };
        Some(v)
    })
    .unwrap()
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    json: Value,
}

impl Resp {
    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }
    fn cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_owned)
            .collect()
    }
}

static NEXT_IP: AtomicUsize = AtomicUsize::new(1);

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Resp {
    let n = NEXT_IP.fetch_add(1, Ordering::Relaxed);
    let ip = format!("10.8.{}.{}", n / 250, n % 250 + 1);
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", ip);
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

fn param(url: &str, key: &str) -> String {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

struct Flow {
    callback: Resp,
}

impl Flow {
    fn session_cookie(&self) -> Option<String> {
        self.callback
            .cookies()
            .into_iter()
            .find(|c| c.starts_with("pw_session=") && !c.contains("Max-Age=0"))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }
}

/// Vollständiger Ablauf: Login → (Mock) → Callback. `tweak` ändert den Mock vor dem Token-Abruf.
async fn flow_with(
    app: &Router,
    m: &Mock,
    return_to: Option<&str>,
    tweak: impl FnOnce(&mut Knobs),
) -> Flow {
    let uri = match return_to {
        Some(r) => format!("/api/v1/auth/oidc/login?return_to={r}"),
        None => "/api/v1/auth/oidc/login".to_owned(),
    };
    let login = call(app, Method::GET, &uri, &[], None).await;
    assert!(login.status.is_redirection(), "login: {}", login.status);
    let loc = login.location();
    assert!(loc.starts_with(&format!("{}/authorize", m.base)), "{loc}");
    assert_eq!(param(&loc, "code_challenge_method"), "S256");
    assert_eq!(
        param(&loc, "redirect_uri"),
        "https://pw.example/api/v1/auth/oidc/callback"
    );
    let state = param(&loc, "state");
    {
        let mut k = m.knobs.lock().unwrap();
        // Jeder Ablauf beginnt mit dem Standardverhalten des Mocks.
        *k = Knobs::default();
        k.expected_nonce = param(&loc, "nonce");
        k.challenge = param(&loc, "code_challenge");
        tweak(&mut k);
    }
    let cookie = format!("pw_oidc={state}");
    let callback = call(
        app,
        Method::GET,
        &format!("/api/v1/auth/oidc/callback?code={CODE}&state={state}"),
        &[("cookie", &cookie)],
        None,
    )
    .await;
    Flow { callback }
}

async fn flow(app: &Router, m: &Mock) -> Flow {
    flow_with(app, m, None, |_| {}).await
}

async fn last_audit(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT COALESCE(target, '') FROM audit_log WHERE action = 'oidc.login' ORDER BY id DESC LIMIT 1")
        .fetch_optional(pool)
        .await
        .unwrap()
        .unwrap_or_default()
}

async fn count_oidc_users(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE auth_kind = 'oidc'")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn admin_session(app: &Router, pool: &PgPool) -> (String, String) {
    admin::upsert_admin(pool, "root", PW).await.unwrap();
    let r = call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username":"root","password":PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let cookie = r.cookies()[0].split(';').next().unwrap().to_owned();
    (cookie, r.json["csrf_token"].as_str().unwrap().to_owned())
}

async fn put_settings(app: &Router, s: &(String, String), body: Value) -> Resp {
    call(
        app,
        Method::PUT,
        "/api/v1/settings/oidc",
        &[("cookie", &s.0), ("x-csrf-token", &s.1)],
        Some(body),
    )
    .await
}

fn settings_body(m: &Mock, extra: Value) -> Value {
    let mut b = json!({"enabled": true, "issuer": m.base, "client_id": "pw-client", "client_secret": CLIENT_SECRET, "name": "Mock"});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    b
}

macro_rules! mock_or_skip {
    ($m:ident) => {
        let Some($m) = start_mock().await else {
            eprintln!("übersprungen: keine private Netzwerkadresse für den Mock-Anbieter");
            return;
        };
    };
}

#[sqlx::test(migrations = "./migrations")]
async fn new_accounts_wait_for_approval_then_log_in(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, true)).unwrap());
    let p = call(&app, Method::GET, "/api/v1/auth/providers", &[], None).await;
    assert_eq!(p.json["oidc"]["enabled"], true);

    // Gültiger Ablauf, aber unbekanntes (iss, sub): Konto "ausstehend", keine Sitzung.
    let f = flow(&app, &m).await;
    assert_eq!(f.callback.location(), "/login?error=oidc_pending");
    assert!(f.session_cookie().is_none());
    let (id, status, role, auth): (i64, String, String, String) = sqlx::query_as(
        "SELECT id, status, role, auth_kind FROM admin_users WHERE oidc_subject = 'sub-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (status.as_str(), role.as_str(), auth.as_str()),
        ("pending", "viewer", "oidc")
    );
    // Wiederholte Anmeldung legt kein zweites Konto an.
    flow(&app, &m).await;
    assert_eq!(count_oidc_users(&pool).await, 1);

    let adm = admin_session(&app, &pool).await;
    let r = call(
        &app,
        Method::POST,
        &format!("/api/v1/users/{id}/approve"),
        &[("cookie", &adm.0), ("x-csrf-token", &adm.1)],
        Some(json!({"role": "viewer"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);

    let f1 = flow(&app, &m).await;
    assert_eq!(f1.callback.location(), "/");
    let c1 = f1.session_cookie().expect("Sitzung nach Freigabe");
    let f2 = flow(&app, &m).await;
    let c2 = f2.session_cookie().unwrap();
    assert_ne!(c1, c2, "jede Anmeldung bekommt eine neue Sitzungs-ID");
    let me = call(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        &[("cookie", &c1)],
        None,
    )
    .await;
    assert_eq!(
        (
            me.status,
            me.json["role"].as_str(),
            me.json["auth_kind"].as_str()
        ),
        (StatusCode::OK, Some("viewer"), Some("oidc"))
    );
    // Nur Lesen: kein Schreiben, keine Benutzerverwaltung.
    let r = call(&app, Method::GET, "/api/v1/users", &[("cookie", &c1)], None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let last: Option<String> =
        sqlx::query_scalar("SELECT last_login_at::text FROM admin_users WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(last.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_tokens_are_rejected_without_creating_accounts(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, true)).unwrap());
    type Tweak = Box<dyn Fn(&mut Knobs)>;
    let cases: Vec<(&str, Tweak)> = vec![
        (
            "iss",
            Box::new(|k| k.iss = Some("https://evil.example".into())),
        ),
        ("aud", Box::new(|k| k.aud = json!("anderer-client"))),
        ("azp", Box::new(|k| k.aud = json!(["pw-client", "zweiter"]))),
        ("azp", Box::new(|k| k.azp = Some("anderer".into()))),
        ("abgelaufen", Box::new(|k| k.exp_in = -120)),
        ("nbf", Box::new(|k| k.nbf_off = Some(300))),
        ("iat", Box::new(|k| k.iat_off = 300)),
        ("nonce", Box::new(|k| k.nonce = Some("falsch".into()))),
        ("algorithmus", Box::new(|k| k.alg = "none".into())),
        ("algorithmus", Box::new(|k| k.alg = "HS256".into())),
        (
            "signatur",
            Box::new(|k| {
                k.sign = 2;
                k.kid = Some("k1".into());
            }),
        ),
        ("sub", Box::new(|k| k.sub = String::new())),
    ];
    for (i, (code, tweak)) in cases.iter().enumerate() {
        let f = flow_with(&app, &m, None, |k| tweak(k)).await;
        assert_eq!(f.callback.location(), "/login?error=oidc", "Fall {i}");
        assert!(f.session_cookie().is_none(), "Fall {i}");
        assert_eq!(last_audit(&pool).await, *code, "Fall {i}");
    }
    assert_eq!(count_oidc_users(&pool).await, 0);
    // Gegenprobe: ohne Manipulation klappt derselbe Ablauf (Konto ausstehend).
    assert_eq!(
        flow(&app, &m).await.callback.location(),
        "/login?error=oidc_pending"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn state_cookie_replay_and_pkce_are_enforced(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, true)).unwrap());
    let begin = |app: Router| async move {
        let login = call(&app, Method::GET, "/api/v1/auth/oidc/login", &[], None).await;
        let loc = login.location();
        (
            param(&loc, "state"),
            param(&loc, "nonce"),
            param(&loc, "code_challenge"),
        )
    };
    let cb = |state: String, cookie: Option<String>| {
        let app = app.clone();
        async move {
            let uri = format!("/api/v1/auth/oidc/callback?code={CODE}&state={state}");
            match cookie {
                Some(c) => call(&app, Method::GET, &uri, &[("cookie", &c)], None).await,
                None => call(&app, Method::GET, &uri, &[], None).await,
            }
        }
    };
    // Fremder Browser (Cookie fehlt oder gehört zu anderem state): Login-CSRF.
    let (s1, n1, c1) = begin(app.clone()).await;
    {
        let mut k = m.knobs.lock().unwrap();
        (k.expected_nonce, k.challenge) = (n1, c1);
    }
    assert_eq!(cb(s1.clone(), None).await.location(), "/login?error=oidc");
    assert_eq!(last_audit(&pool).await, "state_cookie");
    assert_eq!(
        cb(s1.clone(), Some("pw_oidc=anderer".into()))
            .await
            .location(),
        "/login?error=oidc"
    );
    // Richtiger Browser klappt einmal; Wiederholung (Replay) scheitert, der state ist verbraucht.
    assert_eq!(
        cb(s1.clone(), Some(format!("pw_oidc={s1}")))
            .await
            .location(),
        "/login?error=oidc_pending"
    );
    assert_eq!(
        cb(s1.clone(), Some(format!("pw_oidc={s1}")))
            .await
            .location(),
        "/login?error=oidc"
    );
    assert_eq!(last_audit(&pool).await, "state_unbekannt");
    // Unbekannter state mit passendem Cookie.
    assert_eq!(
        cb("unbekannt".into(), Some("pw_oidc=unbekannt".into()))
            .await
            .location(),
        "/login?error=oidc"
    );
    // Falscher PKCE-Verifier: der Mock kennt eine andere Challenge, der Token-Abruf scheitert.
    let (s2, n2, _) = begin(app.clone()).await;
    {
        let mut k = m.knobs.lock().unwrap();
        (k.expected_nonce, k.challenge) = (n2, b64(b"andere-challenge"));
    }
    assert_eq!(
        cb(s2.clone(), Some(format!("pw_oidc={s2}")))
            .await
            .location(),
        "/login?error=oidc"
    );
    assert_eq!(last_audit(&pool).await, "http_status");
    // Fehlermeldung des Anbieters im Callback.
    let r = call(
        &app,
        Method::GET,
        "/api/v1/auth/oidc/callback?error=access_denied",
        &[],
        None,
    )
    .await;
    assert_eq!(r.location(), "/login?error=oidc");
}

#[sqlx::test(migrations = "./migrations")]
async fn same_email_with_new_subject_never_links(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, true)).unwrap());
    // Bestehende Konten: ein aktiver Betreiber mit (iss, sub-1) und ein lokaler Administrator mit gleicher E-Mail.
    sqlx::query("INSERT INTO admin_users (username, display_name, email, auth_kind, role, status, oidc_issuer, oidc_subject) VALUES ('op', 'Op', 'alice@example.org', 'oidc', 'operator', 'active', $1, 'sub-1')")
        .bind(&m.base).execute(&pool).await.unwrap();
    admin::upsert_admin(&pool, "alice.mail", PW).await.unwrap();
    sqlx::query(
        "UPDATE admin_users SET email = 'alice@example.org' WHERE username = 'alice@example.org'",
    )
    .execute(&pool)
    .await
    .unwrap();
    // Gleiche E-Mail, anderes sub: ein neues, getrenntes Konto ohne Rechte.
    let f = flow_with(&app, &m, None, |k| k.sub = "sub-2".into()).await;
    assert_eq!(f.callback.location(), "/login?error=oidc_pending");
    assert!(f.session_cookie().is_none());
    let (status, role): (String, String) =
        sqlx::query_as("SELECT status, role FROM admin_users WHERE oidc_subject = 'sub-2'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((status.as_str(), role.as_str()), ("pending", "viewer"));
    let role: String = sqlx::query_scalar("SELECT role FROM admin_users WHERE username = 'op'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "operator");
    // Das echte sub-1 meldet sich als Betreiber an.
    let ok = flow(&app, &m).await;
    let me = call(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        &[("cookie", &ok.session_cookie().unwrap())],
        None,
    )
    .await;
    assert_eq!(me.json["role"], "operator");
    // Anderer Issuer mit gleichem sub: kein Treffer (Konto ist an (iss, sub) gebunden).
    let other: Option<i64> = sqlx::query_scalar("SELECT id FROM admin_users WHERE oidc_issuer = 'https://anderer.example' AND oidc_subject = 'sub-1'").fetch_optional(&pool).await.unwrap();
    assert!(other.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn policies_roles_and_return_to(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, false)).unwrap());
    let adm = admin_session(&app, &pool).await;
    let r = put_settings(
        &app,
        &adm,
        settings_body(
            &m,
            json!({"new_account": "viewer", "allowed_domains": ["example.org"]}),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.json);
    assert_eq!(
        r.json["redirect_url"],
        "https://pw.example/api/v1/auth/oidc/callback"
    );
    let text = r.json.to_string();
    assert!(!text.contains(CLIENT_SECRET) && r.json["secret_set"] == true);

    // Policy "Nur Lesen": verifizierte E-Mail der erlaubten Domäne → sofort aktiv als Nur Lesen; return_to aus der Positivliste.
    let f = flow_with(&app, &m, Some("/cves"), |_| {}).await;
    assert_eq!(f.callback.location(), "/cves");
    assert!(f.session_cookie().is_some());
    // Fremdes Rücksprungziel wird verworfen.
    let f = flow_with(&app, &m, Some("//evil.example"), |_| {}).await;
    assert_eq!(f.callback.location(), "/");
    let f = flow_with(&app, &m, Some("https://evil.example"), |_| {}).await;
    assert_eq!(f.callback.location(), "/");
    // Unverifizierte E-Mail oder fremde Domäne: nur ausstehend.
    let f = flow_with(&app, &m, None, |k| {
        k.sub = "sub-u".into();
        k.verified = json!(false);
    })
    .await;
    assert_eq!(f.callback.location(), "/login?error=oidc_pending");
    let f = flow_with(&app, &m, None, |k| {
        k.sub = "sub-d".into();
        k.email = "x@fremd.org".into();
    })
    .await;
    assert_eq!(f.callback.location(), "/login?error=oidc_pending");
    // Policy "ablehnen".
    let r = put_settings(
        &app,
        &adm,
        settings_body(&m, json!({"new_account": "reject"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let n = count_oidc_users(&pool).await;
    let f = flow_with(&app, &m, None, |k| k.sub = "sub-r".into()).await;
    assert_eq!(f.callback.location(), "/login?error=oidc");
    assert_eq!(count_oidc_users(&pool).await, n);
    assert_eq!(last_audit(&pool).await, "neues_konto_abgelehnt");
    // Gesperrte Konten kommen nicht hinein.
    sqlx::query("UPDATE admin_users SET status = 'locked' WHERE oidc_subject = 'sub-1'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        flow(&app, &m).await.callback.location(),
        "/login?error=oidc"
    );
    assert_eq!(last_audit(&pool).await, "konto_gesperrt");
}

#[sqlx::test(migrations = "./migrations")]
async fn groups_map_to_roles_promotions_wait_demotions_apply(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, false)).unwrap());
    let adm = admin_session(&app, &pool).await;
    let mapping = json!({"group_roles": [{"group":"admins","role":"admin"},{"group":"ops","role":"operator"}]});
    // Neue Administrator-Zuordnung verlangt das eigene Passwort.
    let r = put_settings(&app, &adm, settings_body(&m, mapping.clone())).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.json);
    let mut with_pw = mapping.clone();
    with_pw["current_password"] = json!(PW);
    assert_eq!(
        put_settings(&app, &adm, settings_body(&m, with_pw))
            .await
            .status,
        StatusCode::OK
    );
    // Ungültige Rolle und Dubletten werden abgelehnt/bereinigt.
    let bad = put_settings(
        &app,
        &adm,
        settings_body(&m, json!({"group_roles": [{"group":"x","role":"root"}]})),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        put_settings(&app, &adm, settings_body(&m, mapping.clone()))
            .await
            .status,
        StatusCode::OK,
        "unveränderte Admin-Zuordnung braucht kein Passwort"
    );

    // Aktives Konto (Nur Lesen) wird vom Anbieter in "admins" geführt: Hochstufung wartet.
    sqlx::query("INSERT INTO admin_users (username, display_name, auth_kind, role, status, oidc_issuer, oidc_subject) VALUES ('g1', 'G1', 'oidc', 'viewer', 'active', $1, 'sub-1')")
        .bind(&m.base).execute(&pool).await.unwrap();
    let f = flow_with(&app, &m, None, |k| k.groups = vec!["admins".into()]).await;
    let c = f.session_cookie().unwrap();
    let me = call(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        &[("cookie", &c)],
        None,
    )
    .await;
    assert_eq!(me.json["role"], "viewer");
    let req: Option<String> =
        sqlx::query_scalar("SELECT requested_role FROM admin_users WHERE username = 'g1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(req.as_deref(), Some("admin"));
    // Ein Administrator bestätigt per Rollenwechsel; danach Gruppe entfernt → sofortige Herabstufung, alte Sitzung weg.
    sqlx::query(
        "UPDATE admin_users SET role = 'admin', requested_role = NULL WHERE username = 'g1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let f = flow_with(&app, &m, None, |k| k.groups = vec!["admins".into()]).await;
    let c_admin = f.session_cookie().unwrap();
    assert_eq!(
        call(
            &app,
            Method::GET,
            "/api/v1/users",
            &[("cookie", &c_admin)],
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    let f = flow_with(&app, &m, None, |k| k.groups = vec!["ops".into()]).await;
    assert_eq!(
        call(
            &app,
            Method::GET,
            "/api/v1/users",
            &[("cookie", &c_admin)],
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    let me = call(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        &[("cookie", &f.session_cookie().unwrap())],
        None,
    )
    .await;
    assert_eq!(me.json["role"], "operator");
    // Keine passende Gruppe bei eingerichteter Zuordnung: Nur Lesen.
    let f = flow_with(&app, &m, None, |k| k.groups = vec!["fremd".into()]).await;
    let me = call(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        &[("cookie", &f.session_cookie().unwrap())],
        None,
    )
    .await;
    assert_eq!(me.json["role"], "viewer");
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_key_refetch_is_limited_to_once_per_minute(pool: PgPool) {
    mock_or_skip!(m);
    let st = AppState::new(pool.clone(), cfg(&m, true)).unwrap();
    let app = router(st.clone());
    assert_eq!(
        flow(&app, &m).await.callback.location(),
        "/login?error=oidc_pending"
    );
    assert_eq!(m.jwks_hits.load(Ordering::SeqCst), 1);
    // Zweite Anmeldung: Schlüssel kommen aus dem Speicher.
    flow(&app, &m).await;
    assert_eq!(m.jwks_hits.load(Ordering::SeqCst), 1);
    // Schlüsselwechsel beim Anbieter: unbekannte kid, Speicher ist jung, also kein Neuabruf.
    let f = flow_with(&app, &m, None, |k| {
        k.publish = 1;
        k.sign = 1;
    })
    .await;
    assert_eq!(f.callback.location(), "/login?error=oidc");
    assert_eq!(last_audit(&pool).await, "kid_unbekannt");
    assert_eq!(m.jwks_hits.load(Ordering::SeqCst), 1);
    // Nach über einer Minute wird neu geholt und der Token ist gültig.
    st.jwks.age_for_tests(std::time::Duration::from_secs(61));
    let f = flow_with(&app, &m, None, |k| {
        k.publish = 1;
        k.sign = 1;
    })
    .await;
    assert_eq!(f.callback.location(), "/login?error=oidc_pending");
    assert_eq!(m.jwks_hits.load(Ordering::SeqCst), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn discovery_is_ssrf_protected_and_size_limited(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, false)).unwrap());
    let adm = admin_session(&app, &pool).await;
    let test = |app: Router, adm: (String, String)| async move {
        call(
            &app,
            Method::POST,
            "/api/v1/settings/oidc/test",
            &[("cookie", &adm.0), ("x-csrf-token", &adm.1)],
            None,
        )
        .await
    };
    // Ohne Einrichtung: klare Fehlermeldung statt Absturz.
    assert_eq!(
        test(app.clone(), adm.clone()).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put_settings(&app, &adm, settings_body(&m, json!({})))
            .await
            .status,
        StatusCode::OK
    );
    let ok = test(app.clone(), adm.clone()).await;
    assert_eq!(
        (ok.json["ok"].clone(), ok.json["keys"].clone()),
        (json!(true), json!(1)),
        "{:?}",
        ok.json
    );
    // Zu große Antwort.
    m.knobs.lock().unwrap().discovery = "huge";
    assert_eq!(
        test(app.clone(), adm.clone()).await.json["error"],
        "antwort_zu_gross"
    );
    // Endpunkt bei einem anderen Host als der Issuer.
    m.knobs.lock().unwrap().discovery = "foreign";
    assert_eq!(
        test(app.clone(), adm.clone()).await.json["error"],
        "discovery_ungueltig"
    );
    m.knobs.lock().unwrap().discovery = "ok";
    // Loopback und Metadatendienst sind auch mit Allowlist gesperrt; ein privater Host ohne Freigabe ebenfalls.
    for issuer in [
        "https://127.0.0.1:1",
        "https://169.254.169.254",
        "http://[::1]:1",
    ] {
        let st = AppState::new(pool.clone(), {
            let mut c = cfg(&m, false);
            c.notify_allowed_hosts.extend([
                "127.0.0.1".into(),
                "169.254.169.254".into(),
                "::1".into(),
            ]);
            c
        })
        .unwrap();
        let app2 = router(st);
        let adm2 = admin_session2(&app2, &pool).await;
        let r = put_settings(&app2, &adm2, settings_body(&m, json!({"issuer": issuer}))).await;
        assert_eq!(r.status, StatusCode::OK, "{issuer}: {:?}", r.json);
        let t = test(app2, adm2).await;
        assert_eq!(
            (t.json["ok"].clone(), t.json["error"].clone()),
            (json!(false), json!("url_nicht_erlaubt")),
            "{issuer}"
        );
    }
    // http:// zu einem nicht freigegebenen Host wird schon beim Speichern abgelehnt.
    let strict = Config::from_sources(None, &|k| {
        (k == "PATCHWATCH_TRUST_PROXY").then(|| "true".to_owned())
    })
    .unwrap();
    let app3 = router(AppState::new(pool.clone(), strict).unwrap());
    let adm3 = admin_session2(&app3, &pool).await;
    let r = put_settings(&app3, &adm3, json!({"enabled": true, "issuer": "http://10.1.1.1", "client_id": "c", "client_secret": "x"})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Der Verbindungstest verrät weder Geheimnis noch Token.
    assert!(!ok.json.to_string().contains(CLIENT_SECRET));
}

async fn admin_session2(app: &Router, _pool: &PgPool) -> (String, String) {
    let r = call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username":"root","password":PW})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    (
        r.cookies()[0].split(';').next().unwrap().to_owned(),
        r.json["csrf_token"].as_str().unwrap().to_owned(),
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn secrets_never_appear_in_responses_or_the_audit_log(pool: PgPool) {
    mock_or_skip!(m);
    let app = router(AppState::new(pool.clone(), cfg(&m, false)).unwrap());
    let adm = admin_session(&app, &pool).await;
    let put = put_settings(&app, &adm, settings_body(&m, json!({}))).await;
    let get = call(
        &app,
        Method::GET,
        "/api/v1/settings/oidc",
        &[("cookie", &adm.0)],
        None,
    )
    .await;
    // Fehlerhafte und gelungene Anmeldungen, danach das Aktivitätsprotokoll lesen.
    let ok = flow(&app, &m).await;
    let bad = flow_with(&app, &m, None, |k| k.nonce = Some("falsch".into())).await;
    let audit = call(
        &app,
        Method::GET,
        "/api/v1/audit?limit=200",
        &[("cookie", &adm.0)],
        None,
    )
    .await;
    assert_eq!(audit.status, StatusCode::OK);
    let id_token_marker = "eyJ";
    for (what, text) in [
        ("put", put.json.to_string()),
        ("get", get.json.to_string()),
        ("audit", audit.json.to_string()),
        (
            "cb-ok",
            format!("{:?}", ok.callback.headers.get(header::LOCATION)),
        ),
        (
            "cb-bad",
            format!("{:?}", bad.callback.headers.get(header::LOCATION)),
        ),
    ] {
        assert!(!text.contains(CLIENT_SECRET), "{what}");
        assert!(!text.contains(CODE), "{what}");
        assert!(
            !text.contains(id_token_marker),
            "{what}: sieht nach einem Token aus"
        );
        assert!(!text.contains("TESTWERT-at"), "{what}");
    }
    assert_eq!(get.json["secret_set"], true);
    // In der Datenbank liegt das Secret nur verschlüsselt.
    let stored: Value = sqlx::query_scalar("SELECT value FROM settings WHERE key = 'oidc'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!stored.to_string().contains(CLIENT_SECRET));
    // Ein Browser sieht bei Fehlern nur die allgemeine Fehlerseite, nie den Grund.
    assert_eq!(bad.callback.location(), "/login?error=oidc");
    assert!(m.token_calls.load(Ordering::SeqCst) >= 2);
}
