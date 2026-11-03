//! Tests zu den Funden des Security-Audits (Fund-Nummern wie in audits/patchwatch/REPORT.md).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::admin::{self, Bootstrap};
use patchwatch_server::config::Config;
use patchwatch_server::{router, security, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

fn state(pool: PgPool, env: &'static [(&'static str, &'static str)]) -> AppState {
    let cfg = Config::from_sources(None, &|k| {
        env.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| (*v).to_owned())
    })
    .unwrap();
    AppState::new(pool, cfg).unwrap()
}

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
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Resp {
        status: parts.status,
        headers: parts.headers,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

/// Meldet an und liefert (Cookie, CSRF-Token, Antwort).
async fn login_as(app: &Router, user: &str, pw: &str) -> (String, String, Resp) {
    let r = call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username": user, "password": pw})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "Login {user}");
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
    let csrf = r.json["csrf_token"].as_str().unwrap().to_owned();
    (cookie, csrf, r)
}

// ---------- Fund 1: kein Standard-Admin-Passwort ----------

/// Ohne gesetztes Passwort entsteht ein Zufallspasswort: lang, nur einmal sichtbar (Rückgabewert), nie im Klartext
/// gespeichert, und das Konto darf nur das Passwort ändern.
#[sqlx::test(migrations = "./migrations")]
async fn fund1_first_start_generates_random_password_and_forces_change(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let Bootstrap::Random(pw) = admin::bootstrap_admin(&pool, None).await.unwrap() else {
        panic!("Zufallspasswort erwartet");
    };
    assert!(pw.len() >= 24);
    assert!(!admin::KNOWN_DEFAULT_PASSWORDS.contains(&pw.as_str()));
    // Nie im Klartext in der Datenbank.
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM admin_users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(hash.starts_with("$argon2") && !hash.contains(&pw));
    let dump: String = sqlx::query_scalar("SELECT row_to_json(a)::text FROM admin_users a")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!dump.contains(&pw));

    // Zweiter Start: es gibt schon einen Admin, es entsteht nichts Neues.
    assert_eq!(
        admin::bootstrap_admin(&pool, None).await.unwrap(),
        Bootstrap::Existing
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM admin_users")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    let (cookie, csrf, r) = login_as(&app, "admin", &pw).await;
    assert_eq!(r.json["must_change_password"], true);
    let auth = [("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];

    // Bis zum Wechsel sind alle Endpunkte außer me/logout/Passwortwechsel gesperrt.
    for uri in ["/api/v1/hosts", "/api/v1/feeds", "/api/v1/cves"] {
        let r = call(&app, Method::GET, uri, &auth, None).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(r.json["code"], "password_change_required");
    }
    let me = call(&app, Method::GET, "/api/v1/auth/me", &auth, None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json["must_change_password"], true);

    // Der Wechsel verlangt Mindestlänge und verbietet das frühere Standardpasswort.
    let change = |new: &'static str| {
        let (app, pw, cookie, csrf) = (app.clone(), pw.clone(), cookie.clone(), csrf.clone());
        async move {
            call(
                &app,
                Method::POST,
                "/api/v1/auth/password",
                &[("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())],
                Some(json!({"current_password": pw, "new_password": new})),
            )
            .await
        }
    };
    assert_eq!(change("kurz").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        change(admin::KNOWN_DEFAULT_PASSWORDS[0]).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        change("ein-neues-langes-passwort").await.status,
        StatusCode::NO_CONTENT
    );
    // Danach ist alles freigegeben.
    let r = call(&app, Method::GET, "/api/v1/hosts", &auth, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let (_, _, r) = login_as(&app, "admin", "ein-neues-langes-passwort").await;
    assert_eq!(r.json["must_change_password"], false);
}

/// Explizit gesetztes Passwort: mindestens 12 Zeichen, kein bekannter Standardwert; sonst wird nichts angelegt.
#[sqlx::test(migrations = "./migrations")]
async fn fund1_explicit_password_is_validated(pool: PgPool) {
    for bad in ["kurz", admin::KNOWN_DEFAULT_PASSWORDS[0]] {
        assert!(
            admin::bootstrap_admin(&pool, Some(bad)).await.is_err(),
            "{bad}"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM admin_users")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0,
            "es darf kein Admin entstehen"
        );
    }
    assert_eq!(
        admin::bootstrap_admin(&pool, Some("ein-gutes-passwort-123"))
            .await
            .unwrap(),
        Bootstrap::FromEnv
    );
    let flag: bool = sqlx::query_scalar("SELECT must_change_password FROM admin_users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !flag,
        "vom Betreiber gewähltes Passwort braucht keinen Zwangswechsel"
    );
    // `create-admin` nutzt dieselbe Prüfung.
    assert!(
        admin::upsert_admin(&pool, "ops", admin::KNOWN_DEFAULT_PASSWORDS[0])
            .await
            .is_err()
    );
}

/// Altinstallation mit dem früheren Standardpasswort: beim Start per Argon2-Verify erkannt, Zwangswechsel,
/// offene Sitzungen enden. Andere Konten bleiben unberührt.
#[sqlx::test(migrations = "./migrations")]
async fn fund1_legacy_default_password_is_flagged_on_start(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    for (user, pw) in [
        ("admin", admin::KNOWN_DEFAULT_PASSWORDS[0]),
        ("ops", "ein-anderes-langes-passwort"),
    ] {
        sqlx::query("INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)")
            .bind(user)
            .bind(security::hash_password(pw).unwrap())
            .execute(&pool)
            .await
            .unwrap();
    }
    let (old_cookie, _, _) = login_as(&app, "admin", admin::KNOWN_DEFAULT_PASSWORDS[0]).await;
    assert_eq!(
        call(
            &app,
            Method::GET,
            "/api/v1/hosts",
            &[("cookie", old_cookie.as_str())],
            None
        )
        .await
        .status,
        StatusCode::OK,
        "ohne den Fix wäre das Konto offen"
    );

    let flagged = admin::flag_default_passwords(&pool).await.unwrap();
    assert_eq!(flagged, vec!["admin".to_owned()]);
    // Die alte Sitzung ist beendet; der Login erlaubt nur noch den Passwortwechsel.
    assert_eq!(
        call(
            &app,
            Method::GET,
            "/api/v1/hosts",
            &[("cookie", old_cookie.as_str())],
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    let (cookie, _, r) = login_as(&app, "admin", admin::KNOWN_DEFAULT_PASSWORDS[0]).await;
    assert_eq!(r.json["must_change_password"], true);
    assert_eq!(
        call(
            &app,
            Method::GET,
            "/api/v1/hosts",
            &[("cookie", cookie.as_str())],
            None
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let (_, _, r) = login_as(&app, "ops", "ein-anderes-langes-passwort").await;
    assert_eq!(r.json["must_change_password"], false);
    // Erneuter Lauf findet nichts Neues.
    assert!(admin::flag_default_passwords(&pool)
        .await
        .unwrap()
        .is_empty());
}

/// Login: Rate-Limit je Konto (auch bei wechselnden IPs) und je IP (auch bei wechselnden Konten),
/// mit Wartezeit (Retry-After). Bestätigt die schon vorhandene Sperre.
#[sqlx::test(migrations = "./migrations")]
async fn fund1_login_is_limited_per_account_and_per_ip(pool: PgPool) {
    let app = router(state(pool.clone(), &[("PATCHWATCH_TRUST_PROXY", "true")]));
    admin::upsert_admin(&pool, "admin", "ein-langes-test-passwort")
        .await
        .unwrap();
    let attempt = |user: &'static str, ip: String| {
        let app = app.clone();
        async move {
            call(
                &app,
                Method::POST,
                "/api/v1/auth/login",
                &[("x-forwarded-for", ip.as_str())],
                Some(json!({"username": user, "password": "falsch-falsch"})),
            )
            .await
        }
    };
    // Je Konto: 10 Fehlversuche von zehn verschiedenen IPs, der 11. wird gebremst -- auch mit dem richtigen Passwort.
    for i in 0..10 {
        assert_eq!(
            attempt("admin", format!("10.0.0.{i}")).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    let r = attempt("admin", "10.0.1.1".into()).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers.contains_key(header::RETRY_AFTER));
    let ok = call(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        &[("x-forwarded-for", "10.0.2.2")],
        Some(json!({"username": "admin", "password": "ein-langes-test-passwort"})),
    )
    .await;
    assert_eq!(ok.status, StatusCode::TOO_MANY_REQUESTS);

    // Je IP: eine IP, zehn verschiedene Konten, dann gesperrt.
    for i in 0..10 {
        let user: &'static str = Box::leak(format!("user{i}").into_boxed_str());
        assert_eq!(
            attempt(user, "10.9.9.9".into()).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        attempt("user99", "10.9.9.9".into()).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

// ---------- Fund 4: Panic bei Nicht-ASCII-Eingabe ----------

/// Prozentkodierung für Test-URIs (alles außer unreservierten Zeichen).
fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Eingaben, die Byte-Slices auf Zeichengrenzen brechen oder Parser überraschen: Umlaute und Akzente an jeder
/// Byte-Position, CJK, Emoji, sehr lang, Steuerzeichen, leer.
fn nasty_inputs() -> Vec<String> {
    vec![
        "café".into(),
        "cve-é".into(),
        "CVE-2024-é".into(),
        "cvé-2024".into(),
        "ééééééééé".into(),
        "日本語".into(),
        "CVE-日本語".into(),
        "😀😀😀😀".into(),
        "cve-😀".into(),
        "a".repeat(20_000),
        "é".repeat(4_000),
        "\u{0}\u{1}\u{7}\u{1b}[31m\r\n\t".into(),
        "cve-\u{0}".into(),
        "\u{202e}cve-2024-0001".into(),
        String::new(),
        " ".into(),
        "%".into(),
        "'; DROP TABLE cves; --".into(),
    ]
}

/// Jede Route mit Text-Parametern übersteht jede dieser Eingaben ohne 5xx, und der Server antwortet danach weiter.
#[sqlx::test(migrations = "./migrations")]
async fn fund4_text_parameters_never_panic_and_server_keeps_running(pool: PgPool) {
    let app = router(state(
        pool.clone(),
        &[(
            "PATCHWATCH_SECRET_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )],
    ));
    admin::upsert_admin(&pool, "admin", "ein-langes-passwort-123")
        .await
        .unwrap();
    let (cookie, csrf, _) = login_as(&app, "admin", "ein-langes-passwort-123").await;
    let h = [("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];

    let mut uris: Vec<(Method, String)> = Vec::new();
    for v in nasty_inputs() {
        let e = enc(&v);
        for key in ["q", "releases", "distro", "split", "debian", "ubuntu"] {
            uris.push((Method::GET, format!("/api/v1/cves?{key}={e}")));
        }
        uris.push((Method::GET, format!("/api/v1/cves?q={e}&watchlist=true")));
        uris.push((Method::GET, format!("/api/v1/cves/{e}")));
        uris.push((Method::GET, format!("/api/v1/matrix?cves={e}&hosts={e}")));
        uris.push((Method::PUT, format!("/api/v1/watchlist/{e}")));
        uris.push((Method::DELETE, format!("/api/v1/watchlist/{e}")));
        uris.push((Method::GET, format!("/api/v1/notifications/{e}")));
        uris.push((Method::PUT, format!("/api/v1/hosts/1/cves/{e}/review")));
        uris.push((Method::DELETE, format!("/api/v1/hosts/1/cves/{e}/review")));
        uris.push((Method::PUT, format!("/api/v1/feeds/{e}")));
        uris.push((Method::DELETE, format!("/api/v1/feeds/{e}")));
        uris.push((Method::GET, format!("/api/v1/hosts/1/history?limit={e}")));
        uris.push((Method::GET, format!("/api/v1/feeds/refresh?wait={e}")));
        uris.push((
            Method::GET,
            format!("/api/v1/auth/oidc/callback?code={e}&state={e}"),
        ));
    }
    for (m, uri) in &uris {
        let body = (*m == Method::PUT).then(|| json!({}));
        let r = call(&app, m.clone(), uri, &h, body).await;
        assert!(
            !r.status.is_server_error(),
            "{m} {} -> {}",
            uri.chars().take(80).collect::<String>(),
            r.status
        );
    }
    // JSON-Körper mit denselben Texten (Login, Hosts, Feeds, Einstellungen, Report).
    for v in nasty_inputs() {
        for (m, uri, body) in [
            (
                Method::POST,
                "/api/v1/auth/login",
                json!({"username": v, "password": v}),
            ),
            (Method::POST, "/api/v1/hosts", json!({"name": v})),
            (
                Method::POST,
                "/api/v1/feeds",
                json!({"type": v, "label": v, "base_url": v}),
            ),
            (
                Method::PUT,
                "/api/v1/settings",
                json!({"stale_hours": v, "timezone": v}),
            ),
            (
                Method::POST,
                "/api/v1/agent/checkin?token=x",
                json!({"token": v}),
            ),
        ] {
            let r = call(&app, m.clone(), uri, &h, Some(body)).await;
            assert!(!r.status.is_server_error(), "{m} {uri} -> {}", r.status);
        }
    }
    // Der Server läuft weiter und liefert echte Treffer.
    let r = call(&app, Method::GET, "/healthz", &[], None).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = call(&app, Method::GET, "/api/v1/cves?q=caf%C3%A9", &h, None).await;
    assert_eq!(r.status, StatusCode::OK, "q=café");
}

/// Die Regression selbst: `q=café` (das "é" überspannt die Byte-Grenze 4) darf nicht paniken und findet
/// "café" in einer Beschreibung.
#[sqlx::test(migrations = "./migrations")]
async fn fund4_cve_search_with_accent_at_byte_boundary_works(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    admin::upsert_admin(&pool, "admin", "ein-langes-passwort-123")
        .await
        .unwrap();
    sqlx::query("INSERT INTO cves (id, description, updated_at) VALUES ('CVE-2024-0001', 'Das Café-Problem', now())")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cve_source_status (cve_id, source, release, package, status, source_id) VALUES ('CVE-2024-0001', 'ubuntu', 'noble', 'linux', 'needed', 'ubuntu')")
        .execute(&pool)
        .await
        .unwrap();
    let (cookie, _, _) = login_as(&app, "admin", "ein-langes-passwort-123").await;
    let r = call(
        &app,
        Method::GET,
        "/api/v1/cves?q=caf%C3%A9&releases=all",
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.json);
    let text = r.json.to_string();
    assert!(text.contains("CVE-2024-0001"), "{text}");
}

/// Auch ein unerwarteter Panic in einem Handler beendet nur diese Anfrage: 500 ohne Eingabe oder Panic-Meldung im
/// Body, der Server antwortet weiter. (Das Profil nutzt unwind, nicht abort.)
#[tokio::test]
async fn fund4_panic_in_handler_becomes_500_and_server_survives() {
    use tower_http::catch_panic::CatchPanicLayer;
    async fn boom(axum::extract::Path(s): axum::extract::Path<String>) -> String {
        panic!("geheime Eingabe {s}");
    }
    let app = Router::new()
        .route("/boom/{s}", axum::routing::get(boom))
        .route("/ok", axum::routing::get(|| async { "ok" }))
        .layer(CatchPanicLayer::custom(
            patchwatch_server::routes::panic_response,
        ));
    for _ in 0..3 {
        let r = call(&app, Method::GET, "/boom/caf%C3%A9", &[], None).await;
        assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !r.json.to_string().contains("caf"),
            "keine Eingabe in der Antwort"
        );
        assert!(!r.json.to_string().contains("geheim"));
        let r = call(&app, Method::GET, "/ok", &[], None).await;
        assert_eq!(r.status, StatusCode::OK);
    }
}

/// Das Release-Profil muss unwinden, sonst beendet jeder Panic den Prozess trotz CatchPanicLayer.
#[test]
fn fund4_release_profile_unwinds() {
    let toml =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml")).unwrap();
    assert!(
        !toml.contains("panic = \"abort\""),
        "panic = abort würde CatchPanicLayer wirkungslos machen"
    );
}

// ---------- Niedrige Funde ----------

async fn long_poll(
    app: &Router,
    token: &str,
    wait: u32,
) -> (StatusCode, Value, std::time::Duration) {
    let t0 = std::time::Instant::now();
    let auth = format!("Bearer {token}");
    let r = call(
        app,
        Method::POST,
        &format!("/api/v1/agent/checkin?wait={wait}"),
        &[("authorization", &auth)],
        None,
    )
    .await;
    (r.status, r.json, t0.elapsed())
}

async fn host_with_token(pool: &PgPool, name: &str, token: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO hosts (name, token_hash) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(security::sha256(token))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn request_report(pool: &PgPool, id: i64) {
    sqlx::query("UPDATE hosts SET report_requested_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

/// Check-in-Long-Poll: je Host höchstens eine offene Anfrage; eine neue löst die alte ab.
#[sqlx::test(migrations = "./migrations")]
async fn low_checkin_long_poll_allows_one_open_request_per_host(pool: PgPool) {
    let st = state(pool.clone(), &[]);
    let app = router(st.clone());
    let id = host_with_token(&pool, "web1", "pw_token-eins-0123456789abcdef0123456789").await;

    let a = tokio::spawn({
        let app = app.clone();
        async move { long_poll(&app, "pw_token-eins-0123456789abcdef0123456789", 30).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(st.checkin_waiters.lock().unwrap().len(), 1);
    // Zweite Anfrage desselben Hosts: die erste endet ohne Report, es bleibt eine offen.
    let b = tokio::spawn({
        let app = app.clone();
        async move { long_poll(&app, "pw_token-eins-0123456789abcdef0123456789", 30).await }
    });
    let (status, body, took) = a.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["report_requested"], false);
    assert!(
        took < std::time::Duration::from_secs(8),
        "alte Anfrage wird abgelöst, nicht 30 s gehalten: {took:?}"
    );
    assert_eq!(
        st.checkin_waiters.lock().unwrap().len(),
        1,
        "genau eine offene Anfrage"
    );
    // Die neue Anfrage ist weiter gültig und bekommt den Report-Wunsch.
    request_report(&pool, id).await;
    let (_, body, _) = b.await.unwrap();
    assert_eq!(body["report_requested"], true);
    assert!(
        st.checkin_waiters.lock().unwrap().is_empty(),
        "nach dem Ende bleibt nichts hängen"
    );
    assert_eq!(
        st.checkin_slots.available_permits(),
        patchwatch_server::state::MAX_OPEN_CHECKINS
    );
}

/// Globale Grenze: ist sie erreicht, antwortet der Server weiteren Hosts sofort statt sie warten zu lassen.
#[sqlx::test(migrations = "./migrations")]
async fn low_checkin_long_poll_has_a_global_limit(pool: PgPool) {
    let mut st = state(pool.clone(), &[]);
    st.checkin_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
    let app = router(st.clone());
    let toks = [
        "pw_token-a-0123456789abcdef0123456789abcd",
        "pw_token-b-0123456789abcdef0123456789abcd",
        "pw_token-c-0123456789abcdef0123456789abcd",
    ];
    let mut ids = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        ids.push(host_with_token(&pool, &format!("h{i}"), t).await);
    }
    let mut open = Vec::new();
    for t in &toks[..2] {
        let app = app.clone();
        let t = (*t).to_owned();
        open.push(tokio::spawn(async move { long_poll(&app, &t, 30).await }));
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        st.checkin_slots.available_permits(),
        0,
        "beide Plätze belegt"
    );
    let (status, body, took) = long_poll(&app, toks[2], 30).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["report_requested"], false);
    assert!(
        took < std::time::Duration::from_secs(2),
        "dritte Anfrage wartet nicht: {took:?}"
    );
    assert_eq!(st.checkin_waiters.lock().unwrap().len(), 2);
    for id in &ids[..2] {
        request_report(&pool, *id).await;
    }
    for h in open {
        assert_eq!(h.await.unwrap().1["report_requested"], true);
    }
    assert_eq!(st.checkin_slots.available_permits(), 2);
}

/// NVD-Schlüssel (Header `apiKey`) darf bei einer Weiterleitung auf einen anderen Host nicht mitgehen.
#[tokio::test]
async fn low_nvd_key_header_is_not_sent_after_a_redirect() {
    use patchwatch_server::cve::nvd::Nvd;
    use patchwatch_server::cve::{CveSource, FeedState, FetchCtx};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Ziel der Weiterleitung (anderer Host-Name: localhost statt 127.0.0.1): merkt sich alle Anfragen.
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tport = target.local_addr().unwrap().port();
    let s2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = target.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let n = c.read(&mut buf).await.unwrap_or(0);
            s2.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).to_lowercase());
            let _ = c
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                .await;
        }
    });
    // "NVD": leitet jede Anfrage auf das Ziel um.
    let nvd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nport = nvd.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = nvd.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 302 Found\r\nlocation: http://localhost:{tport}/gestohlen\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            let _ = c.write_all(resp.as_bytes()).await;
        }
    });

    let cfg = Config::from_sources(None, &|_| None).unwrap();
    let source = Nvd::new(
        &cfg.cve,
        Some(format!("http://127.0.0.1:{nport}")),
        None,
        Some("geheimer-nvd-schluessel".into()),
    );
    let ctx = FetchCtx {
        enrich: vec!["CVE-2024-0001".into()],
        ..FetchCtx::default()
    };
    // Der gemeinsame Client folgt Redirects; der NVD-Quelle darf er nie als Ersatz dienen.
    let shared = reqwest::Client::new();
    let _ = source.fetch(&shared, &FeedState::default(), &ctx).await;
    let log = seen.lock().unwrap().join("\n");
    assert!(
        !log.contains("geheimer-nvd-schluessel"),
        "Schlüssel beim Redirect-Ziel angekommen: {log}"
    );
    assert!(seen.lock().unwrap().is_empty(), "Redirect wurde gefolgt");
}
