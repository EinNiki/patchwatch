//! Benachrichtigungskanäle: Geheimnisse, SSRF-Schutz, Sendeformate, Ereignis → Kanal → Job.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::notify::channels::{build, Http, KINDS};
use patchwatch_server::notify::{messages, store};
use patchwatch_server::{admin, router, worker, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const PASSWORD: &str = "ein-langes-test-passwort";
/// Base64 von 32 Bytes 0x01.
const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const SECRET: &str = "GEHEIMES-TOKEN-4711";

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
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        raw: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn login(app: &Router, pool: &PgPool) -> (String, String) {
    admin::upsert_admin(pool, "admin", PASSWORD).await.unwrap();
    let r = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"username": "admin", "password": PASSWORD}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(r).await.unwrap();
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let j: Value = serde_json::from_slice(&bytes).unwrap();
    (
        cookie.split(';').next().unwrap().to_owned(),
        j["csrf_token"].as_str().unwrap().to_owned(),
    )
}

type Seen = Arc<Mutex<Vec<(String, String, Vec<(String, String)>, String)>>>;

/// Lokaler Mock der Gegenseite: merkt sich Methode, Pfad, Header und Body und antwortet mit `status`/`body`.
async fn mock(addr: &str, status: u16, body: &'static str) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let app = Router::new().fallback(move |req: Request<Body>| {
        let log = log.clone();
        async move {
            let (parts, b) = req.into_parts();
            let bytes = b.collect().await.unwrap().to_bytes();
            let headers = parts
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
                .collect();
            log.lock().unwrap().push((
                parts.method.to_string(),
                parts.uri.to_string(),
                headers,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
            (StatusCode::from_u16(status).unwrap(), body)
        }
    });
    let listener = tokio::net::TcpListener::bind(format!("{addr}:0"))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

fn header_of(h: &[(String, String)], name: &str) -> Option<String> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn trusted() -> Http {
    Http {
        allowed_hosts: vec![],
        trusted: true,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn secrets_are_write_only_and_encrypted_at_rest(pool: PgPool) {
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    let app = router(st);
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];

    let put = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/gotify",
        &admin,
        Some(json!({
            "enabled": true, "config": {"url": "https://gotify.example.org"}, "secret": SECRET,
            "events": ["host_status", "feed_failing"],
        })),
    )
    .await;
    assert_eq!(put.status, StatusCode::OK, "{}", put.raw);
    assert_eq!(put.json["secret_set"], true);
    assert!(
        !put.raw.contains(SECRET),
        "PUT-Antwort darf das Geheimnis nicht enthalten"
    );

    for uri in ["/api/v1/notifications", "/api/v1/notifications/gotify"] {
        let r = call(&app, Method::GET, uri, &admin, None).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            !r.raw.contains(SECRET),
            "{uri} darf das Geheimnis nicht enthalten"
        );
        assert!(!r.raw.contains("\"secret\""), "{uri} hat kein secret-Feld");
    }
    let list = call(&app, Method::GET, "/api/v1/notifications", &admin, None).await;
    assert_eq!(list.json["secret_storage"], true);
    assert_eq!(list.json["channels"].as_array().unwrap().len(), KINDS.len());

    // In der Datenbank liegt nur Chiffretext.
    let blob: Vec<u8> =
        sqlx::query_scalar("SELECT secret FROM notification_channels WHERE kind = 'gotify'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!blob.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));
    let config: Value =
        sqlx::query_scalar("SELECT config FROM notification_channels WHERE kind = 'gotify'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!config.to_string().contains(SECRET));

    // Ohne Secret-Feld bleibt das gespeicherte Geheimnis erhalten ...
    let keep = call(&app, Method::PUT, "/api/v1/notifications/gotify", &admin, Some(json!({
        "enabled": true, "config": {"url": "https://gotify.example.org"}, "events": ["host_status"],
    }))).await;
    assert_eq!(keep.status, StatusCode::OK, "{}", keep.raw);
    assert_eq!(keep.json["secret_set"], true);
    assert_eq!(keep.json["events"], json!(["host_status"]));
    // ... und lässt sich ausdrücklich entfernen (dann braucht ein aktiver Kanal ein neues).
    let clear = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/gotify",
        &admin,
        Some(json!({
            "enabled": true, "config": {"url": "https://gotify.example.org"}, "clear_secret": true,
        })),
    )
    .await;
    assert_eq!(clear.status, StatusCode::BAD_REQUEST);
    let off = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/gotify",
        &admin,
        Some(json!({
            "enabled": false, "config": {"url": "https://gotify.example.org"}, "clear_secret": true,
        })),
    )
    .await;
    assert_eq!(off.status, StatusCode::OK, "{}", off.raw);
    assert_eq!(off.json["secret_set"], false);
}

#[sqlx::test(migrations = "./migrations")]
async fn secret_cannot_be_stored_without_server_key(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/gotify",
        &admin,
        Some(json!({
            "enabled": true, "config": {"url": "https://gotify.example.org"}, "secret": SECRET,
        })),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.raw.contains("PATCHWATCH_SECRET_KEY"));
    assert!(!r.raw.contains(SECRET));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_channels")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let l = call(&app, Method::GET, "/api/v1/notifications", &admin, None).await;
    assert_eq!(l.json["secret_storage"], false);
}

#[sqlx::test(migrations = "./migrations")]
async fn auth_csrf_and_validation(pool: PgPool) {
    let app = router(state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]));
    for (m, uri) in [
        (Method::GET, "/api/v1/notifications"),
        (Method::PUT, "/api/v1/notifications/ntfy"),
        (Method::POST, "/api/v1/notifications/ntfy/test"),
    ] {
        assert_eq!(
            call(&app, m, uri, &[], Some(json!({"enabled": false})))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    let (session, csrf) = login(&app, &pool).await;
    let cookie_only = [("cookie", session.as_str())];
    assert_eq!(
        call(
            &app,
            Method::PUT,
            "/api/v1/notifications/ntfy",
            &cookie_only,
            Some(json!({"enabled": false}))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let put = |kind: &'static str, body: Value| {
        let app = app.clone();
        let session = session.clone();
        let csrf = csrf.clone();
        async move {
            call(
                &app,
                Method::PUT,
                &format!("/api/v1/notifications/{kind}"),
                &[("cookie", &session), ("x-csrf-token", &csrf)],
                Some(body),
            )
            .await
        }
    };
    assert_eq!(
        call(
            &app,
            Method::GET,
            "/api/v1/notifications/pager",
            &admin,
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    for (kind, body) in [
        (
            "ntfy",
            json!({"enabled": true, "config": {"url": "ftp://x.example", "topic": "t"}}),
        ),
        (
            "ntfy",
            json!({"enabled": true, "config": {"url": "https://user:pw@x.example", "topic": "t"}}),
        ),
        (
            "ntfy",
            json!({"enabled": true, "config": {"url": "https://x.example?token=geheim", "topic": "t"}}),
        ),
        (
            "ntfy",
            json!({"enabled": true, "config": {"url": "https://x.example", "topic": "a b"}}),
        ),
        (
            "matrix",
            json!({"enabled": true, "config": {"homeserver": "https://m.example", "room_id": "kein-raum"}, "secret": "tok"}),
        ),
        (
            "matrix",
            json!({"enabled": true, "config": {"homeserver": "https://m.example", "room_id": "!r:m.example"}}),
        ),
        (
            "discord",
            json!({"enabled": true, "secret": "http://discord.com/api/webhooks/1/x"}),
        ),
        (
            "discord",
            json!({"enabled": true, "secret": "javascript:alert(1)"}),
        ),
        (
            "ntfy",
            json!({"enabled": false, "events": ["gibt_es_nicht"]}),
        ),
        ("ntfy", json!({"enabled": false, "timezone": "Mars/Base"})),
        ("ntfy", json!({"enabled": false, "summary_time": "8 Uhr"})),
        ("ntfy", json!({"enabled": false, "unbekanntes_feld": 1})),
    ] {
        let r = put(kind, body.clone()).await;
        assert!(r.status.is_client_error(), "{kind} {body} -> {}", r.status);
        assert!(
            !r.raw.contains("geheim"),
            "Fehlermeldung darf keine Eingabewerte spiegeln: {}",
            r.raw
        );
    }
    // Zusätzliche Felder in config werden verworfen (kein Versteck für Geheimnisse).
    let ok = put("ntfy", json!({"enabled": true, "config": {"url": "https://ntfy.example.org", "topic": "pw", "token": "SNEAKY"},
        "summary_time": "07:30", "timezone": "Europe/Berlin"})).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
    assert!(!ok.raw.contains("SNEAKY"));
    assert_eq!(ok.json["summary_time"], "07:30");
    assert_eq!(
        ok.json["config"],
        json!({"url": "https://ntfy.example.org", "topic": "pw"})
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn env_ntfy_is_default_and_ui_value_wins(pool: PgPool) {
    let st = state(
        pool.clone(),
        &[
            ("PATCHWATCH_NTFY_URL", "https://ntfy.env.example"),
            ("PATCHWATCH_NTFY_TOPIC", "envtopic"),
            ("PATCHWATCH_NTFY_TOKEN", "ENV-TOKEN"),
            ("PATCHWATCH_SECRET_KEY", KEY),
        ],
    );
    let app = router(st.clone());
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let g = call(
        &app,
        Method::GET,
        "/api/v1/notifications/ntfy",
        &admin,
        None,
    )
    .await;
    assert_eq!(g.json["from_env"], true);
    assert_eq!(g.json["enabled"], true);
    assert_eq!(g.json["secret_set"], true);
    assert_eq!(g.json["config"]["topic"], "envtopic");
    assert!(!g.raw.contains("ENV-TOKEN"));

    let saved = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/ntfy",
        &admin,
        Some(json!({
            "enabled": true, "config": {"url": "https://ntfy.ui.example", "topic": "uitopic"},
        })),
    )
    .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.raw);
    let eff = store::load(&st.pool, &st.cfg, "ntfy")
        .await
        .unwrap()
        .unwrap();
    assert!(!eff.from_env, "DB-Zeile hat Vorrang");
    assert_eq!(eff.config["topic"], "uitopic");
}

#[sqlx::test(migrations = "./migrations")]
async fn swapped_ciphertext_is_rejected_by_channel_binding(pool: PgPool) {
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    let app = router(st.clone());
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/notifications/discord",
        &admin,
        Some(json!({
            "enabled": true, "secret": "https://discord.com/api/webhooks/1/abc",
        })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    // Chiffretext des Discord-Kanals in die gotify-Zeile kopieren.
    sqlx::query("INSERT INTO notification_channels (kind, enabled, config, secret, events) \
        SELECT 'gotify', true, '{\"url\":\"https://g.example\"}', secret, '{host_status}' FROM notification_channels WHERE kind = 'discord'")
        .execute(&pool).await.unwrap();
    let t = call(
        &app,
        Method::POST,
        "/api/v1/notifications/gotify/test",
        &admin,
        None,
    )
    .await;
    assert_eq!(t.json["ok"], false);
    assert!(
        t.json["result"]
            .as_str()
            .unwrap()
            .contains("nicht entschlüsseln"),
        "{}",
        t.raw
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn loopback_and_metadata_targets_are_blocked_even_when_allowlisted(pool: PgPool) {
    let (url, seen) = mock("127.0.0.1", 200, "ok").await;
    let host = url
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap()
        .to_owned();
    let st = state(
        pool.clone(),
        &[
            ("PATCHWATCH_SECRET_KEY", KEY),
            (
                "PATCHWATCH_NOTIFY_ALLOWED_HOSTS",
                "127.0.0.1,localhost,169.254.169.254",
            ),
        ],
    );
    assert!(st.cfg.notify_allowed_hosts.contains(&host));
    let app = router(st);
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    for target in [
        url.clone(),
        "http://169.254.169.254".to_owned(),
        "http://localhost:9".to_owned(),
    ] {
        let r = call(
            &app,
            Method::PUT,
            "/api/v1/notifications/gotify",
            &admin,
            Some(json!({
                "enabled": true, "config": {"url": target}, "secret": "tok",
            })),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
        let t = call(
            &app,
            Method::POST,
            "/api/v1/notifications/gotify/test",
            &admin,
            None,
        )
        .await;
        assert_eq!(
            t.json,
            json!({"ok": false, "result": "nicht erreichbar"}),
            "{target}"
        );
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "es darf keine Anfrage an Loopback gegangen sein"
    );
}

/// Eine private, nicht-loopback IPv4 dieses Rechners (für den Allowlist-Test); `None` im reinen Loopback-Container.
fn private_local_ip() -> Option<std::net::Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("10.255.255.254:9").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if v4.is_private() => Some(v4),
        _ => None,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn private_target_needs_exact_allowlist_entry(pool: PgPool) {
    let Some(ip) = private_local_ip() else {
        eprintln!("übersprungen: keine private lokale IPv4-Adresse");
        return;
    };
    let (url, seen) = mock(&ip.to_string(), 200, "ok").await;
    let allowed: &'static str = Box::leak(ip.to_string().into_boxed_str());
    for (env, expect_ok) in [(allowed, true), ("10.99.99.99", false), ("", false)] {
        let env: &'static str = Box::leak(env.to_owned().into_boxed_str());
        let leaked: &'static [(&'static str, &'static str)] = Box::leak(Box::new([
            ("PATCHWATCH_SECRET_KEY", KEY),
            ("PATCHWATCH_NOTIFY_ALLOWED_HOSTS", env),
        ]));
        let app = router(state(pool.clone(), leaked));
        let (session, csrf) = login(&app, &pool).await;
        let admin = [
            ("cookie", session.as_str()),
            ("x-csrf-token", csrf.as_str()),
        ];
        let r = call(
            &app,
            Method::PUT,
            "/api/v1/notifications/gotify",
            &admin,
            Some(json!({"enabled": true, "config": {"url": url}, "secret": "tok"})),
        )
        .await;
        if !expect_ok {
            // Ein Schlüssel geht nie über http:// an einen Host außerhalb der Allowlist: schon das Speichern scheitert.
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "Allowlist {env:?}");
            assert!(!r.raw.contains("tok\""));
            continue;
        }
        assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
        let before = seen.lock().unwrap().len();
        let t = call(
            &app,
            Method::POST,
            "/api/v1/notifications/gotify/test",
            &admin,
            None,
        )
        .await;
        let after = seen.lock().unwrap().len();
        assert_eq!(t.json["ok"], expect_ok, "Allowlist {env:?}: {}", t.raw);
        assert_eq!(after - before, usize::from(expect_ok));
        // Rate-Limit der Testnachricht ist je Kanal; frischer Router = frischer Zähler.
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn test_message_endpoint_is_rate_limited(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let mut last = StatusCode::OK;
    for _ in 0..7 {
        last = call(
            &app,
            Method::POST,
            "/api/v1/notifications/browser/test",
            &admin,
            None,
        )
        .await
        .status;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test(migrations = "./migrations")]
async fn channel_formats_and_generic_errors(pool: PgPool) {
    let msg = messages::test_message();

    // ntfy: JSON-Publish an die Basis-URL, Bearer-Token.
    let (url, seen) = mock("127.0.0.1", 200, "").await;
    let ch = build(
        "ntfy",
        &json!({"url": url, "topic": "pw"}),
        Some("nt-tok".into()),
        trusted(),
        &pool,
    )
    .unwrap();
    ch.send(&msg).await.unwrap();
    {
        let s = seen.lock().unwrap();
        let (m, path, h, body) = &s[0];
        assert_eq!((m.as_str(), path.as_str()), ("POST", "/"));
        assert_eq!(
            header_of(h, "authorization").as_deref(),
            Some("Bearer nt-tok")
        );
        let b: Value = serde_json::from_str(body).unwrap();
        assert_eq!(b["topic"], "pw");
        assert_eq!(b["title"], "patchwatch: Testnachricht");
    }

    // Gotify: /message mit X-Gotify-Key (kein Token in der URL).
    let (url, seen) = mock("127.0.0.1", 200, "").await;
    build(
        "gotify",
        &json!({"url": format!("{url}/base/")}),
        Some("go-tok".into()),
        trusted(),
        &pool,
    )
    .unwrap()
    .send(&msg)
    .await
    .unwrap();
    {
        let s = seen.lock().unwrap();
        let (m, path, h, body) = &s[0];
        assert_eq!((m.as_str(), path.as_str()), ("POST", "/base/message"));
        assert_eq!(header_of(h, "x-gotify-key").as_deref(), Some("go-tok"));
        assert!(!path.contains("go-tok"));
        assert_eq!(serde_json::from_str::<Value>(body).unwrap()["priority"], 5);
    }

    // Matrix: PUT .../rooms/<prozentkodierte Raum-ID>/send/m.room.message/<txn> mit Bearer.
    let (url, seen) = mock("127.0.0.1", 200, "{}").await;
    build(
        "matrix",
        &json!({"homeserver": url, "room_id": "!abc:matrix.example.org"}),
        Some("mx-tok".into()),
        trusted(),
        &pool,
    )
    .unwrap()
    .send(&msg)
    .await
    .unwrap();
    {
        let s = seen.lock().unwrap();
        let (m, path, h, body) = &s[0];
        assert_eq!(m, "PUT");
        let room = path
            .strip_prefix("/_matrix/client/v3/rooms/")
            .and_then(|r| r.split("/send/m.room.message/").next())
            .unwrap_or_default();
        // `!` and `:` are legal in a path segment; encoded or not, the room id must survive intact.
        assert!(
            matches!(
                room,
                "!abc:matrix.example.org"
                    | "%21abc:matrix.example.org"
                    | "%21abc%3Amatrix.example.org"
            ),
            "{path}"
        );
        assert!(path.contains("/send/m.room.message/"), "{path}");
        assert_eq!(
            header_of(h, "authorization").as_deref(),
            Some("Bearer mx-tok")
        );
        let b: Value = serde_json::from_str(body).unwrap();
        assert_eq!(b["msgtype"], "m.text");
        assert!(b["body"].as_str().unwrap().contains("Testnachricht"));
    }

    // Discord: Webhook-URL ist das Geheimnis; Erwähnungen sind abgeschaltet. (https ist Pflicht, der Mock läuft auf http: Build schlägt fehl.)
    let (url, _) = mock("127.0.0.1", 200, "").await;
    let e = build(
        "discord",
        &json!({}),
        Some(format!("{url}/api/webhooks/1/abc")),
        trusted(),
        &pool,
    )
    .err()
    .unwrap();
    assert!(e.summary().contains("https"), "{}", e.summary());

    // Fehler der Gegenseite: nur der Statuscode, nie der Body.
    let (url, _) = mock("127.0.0.1", 500, "INTERNER-FEHLER-MIT-GEHEIMNIS").await;
    let err = build(
        "gotify",
        &json!({"url": url}),
        Some("t".into()),
        trusted(),
        &pool,
    )
    .unwrap()
    .send(&msg)
    .await
    .unwrap_err();
    assert_eq!(err.summary(), "HTTP 500");
    let (url, _) = mock("127.0.0.1", 401, "token abc ungültig").await;
    let err = build(
        "ntfy",
        &json!({"url": url, "topic": "pw"}),
        None,
        trusted(),
        &pool,
    )
    .unwrap()
    .send(&msg)
    .await
    .unwrap_err();
    assert_eq!(err.summary(), "HTTP 401");
    // Nicht erreichbar: generisch, ohne Host/Port.
    let err = build(
        "ntfy",
        &json!({"url": "http://127.0.0.1:1", "topic": "pw"}),
        None,
        trusted(),
        &pool,
    )
    .unwrap()
    .send(&msg)
    .await
    .unwrap_err();
    assert_eq!(err.summary(), "nicht erreichbar");
    // Redirects werden nicht verfolgt (kein Umweg zu internen Zielen).
    let (url, seen) = mock("127.0.0.1", 302, "").await;
    let err = build(
        "ntfy",
        &json!({"url": url, "topic": "pw"}),
        None,
        trusted(),
        &pool,
    )
    .unwrap()
    .send(&msg)
    .await
    .unwrap_err();
    assert_eq!(err.summary(), "HTTP 302");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

async fn put_channel(pool: &PgPool, st: &AppState, kind: &str, enabled: bool, events: &[&str]) {
    store::save(
        &st.pool,
        &st.cfg,
        kind,
        store::Update {
            enabled,
            config: match kind {
                "gotify" => json!({"url": "https://g.example"}),
                "ntfy" => json!({"url": "https://n.example", "topic": "t"}),
                _ => json!({}),
            },
            secret: (kind == "gotify").then(|| "tok".to_owned()),
            clear_secret: false,
            events: events.iter().map(|e| (*e).to_owned()).collect(),
            summary_time: None,
            timezone: None,
        },
    )
    .await
    .unwrap();
    let _ = pool;
}

async fn jobs_for(pool: &PgPool) -> Vec<(String, Value)> {
    sqlx::query_as("SELECT kind, payload FROM jobs WHERE kind = 'notify' ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn events_reach_only_subscribed_channels(pool: PgPool) {
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    put_channel(&pool, &st, "gotify", true, &["host_status"]).await;
    put_channel(&pool, &st, "ntfy", true, &["agent_silent", "fix_available"]).await;
    put_channel(&pool, &st, "discord", false, &["host_status"]).await; // abgeschaltet
    let ev = |kind: &str, payload: Value| {
        let pool = pool.clone();
        let kind = kind.to_owned();
        async move {
            sqlx::query("INSERT INTO events (kind, payload) VALUES ($1, $2)")
                .bind(kind)
                .bind(payload)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    ev(
        "host_status_changed",
        json!({"name": "web1", "from": "ok", "to": "security_updates"}),
    )
    .await;
    ev(
        "host_status_changed",
        json!({"name": "web2", "from": "ok", "to": "stale"}),
    )
    .await;
    ev("host_cve_status_changed", json!({"cve_id": "CVE-2024-1086", "host": "web1", "from": "vulnerable", "to": "fixed_installed_reboot_required", "watched": true})).await;
    // Proxmox/unklar: UNKNOWN erzeugt nie eine Meldung, auch wenn die CVE auf der Watchlist steht.
    ev("host_cve_status_changed", json!({"cve_id": "CVE-2024-1086", "host": "pve1", "from": null, "to": "unknown", "watched": true})).await;
    worker::process_events(&st).await.unwrap();

    let jobs = jobs_for(&pool).await;
    let summary: Vec<(String, String)> = jobs
        .iter()
        .map(|(_, p)| {
            (
                p["channel"].as_str().unwrap().to_owned(),
                p["title"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        summary.iter().filter(|(c, _)| c == "gotify").count(),
        1,
        "{summary:?}"
    );
    assert!(summary
        .iter()
        .any(|(c, t)| c == "gotify" && t.starts_with("web1:")));
    assert_eq!(
        summary.iter().filter(|(c, _)| c == "ntfy").count(),
        2,
        "{summary:?}"
    );
    assert!(
        summary
            .iter()
            .any(|(c, t)| c == "ntfy" && t.starts_with("web2:")),
        "stale geht an agent_silent"
    );
    assert!(summary
        .iter()
        .any(|(c, t)| c == "ntfy" && t.contains("CVE-2024-1086")));
    assert!(!summary.iter().any(|(c, _)| c == "discord"));
    assert!(
        summary.iter().all(|(_, t)| !t.contains("pve1")),
        "UNKNOWN löst keine Nachricht aus"
    );
    let open: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE processed_at IS NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(open, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn browser_channel_publishes_live_event_instead_of_a_job(pool: PgPool) {
    let st = state(pool.clone(), &[]);
    put_channel(&pool, &st, "browser", true, &["host_status"]).await;
    let mut listener = sqlx::postgres::PgListener::connect_with(&pool)
        .await
        .unwrap();
    listener.listen("patchwatch_live").await.unwrap();
    sqlx::query("INSERT INTO events (kind, payload) VALUES ('host_status_changed', $1)")
        .bind(json!({"name": "web1", "from": "ok", "to": "security_updates"}))
        .execute(&pool)
        .await
        .unwrap();
    worker::process_events(&st).await.unwrap();
    assert!(
        jobs_for(&pool).await.is_empty(),
        "Browser-Kanal braucht keinen Job"
    );
    // The worker also emits a plain `host_status` live event for the UI; wait for the notification.
    let p = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n = listener.recv().await.unwrap();
            let p: Value = serde_json::from_str(n.payload()).unwrap();
            if p["type"] == "notification" {
                return p;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(p["level"], "crit");
    assert!(p["title"].as_str().unwrap().starts_with("web1:"));
}

#[sqlx::test(migrations = "./migrations")]
async fn notify_job_delivers_and_records_generic_error(pool: PgPool) {
    let (url, seen) = mock("127.0.0.1", 200, "").await;
    // ntfy aus der Umgebung ist vertrauenswürdig (Loopback-Mock erreichbar).
    let env: &'static [(&'static str, &'static str)] = Box::leak(Box::new([
        (
            "PATCHWATCH_NTFY_URL",
            Box::leak(url.into_boxed_str()) as &'static str,
        ),
        ("PATCHWATCH_NTFY_TOPIC", "pw"),
    ]));
    let st = state(pool.clone(), env);
    sqlx::query("INSERT INTO events (kind, payload) VALUES ('host_status_changed', $1)")
        .bind(json!({"name": "web1", "from": "ok", "to": "security_updates"}))
        .execute(&pool)
        .await
        .unwrap();
    worker::tick(&st).await.unwrap();
    let s = seen.lock().unwrap();
    assert_eq!(s.len(), 1, "genau eine Nachricht an ntfy");
    assert!(serde_json::from_str::<Value>(&s[0].3).unwrap()["title"]
        .as_str()
        .unwrap()
        .starts_with("web1:"));
}

#[sqlx::test(migrations = "./migrations")]
async fn failing_channel_keeps_job_and_stores_only_generic_error(pool: PgPool) {
    let (url, _) = mock("127.0.0.1", 500, "GEHEIMER-BODY").await;
    // Als gespeicherter Kanal (nicht vertrauenswürdig) wäre Loopback gesperrt: das Ergebnis ist ebenfalls generisch.
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    store::save(
        &st.pool,
        &st.cfg,
        "gotify",
        store::Update {
            enabled: true,
            config: json!({"url": url}),
            secret: Some("tok".into()),
            clear_secret: false,
            events: vec!["host_status".into()],
            summary_time: None,
            timezone: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO events (kind, payload) VALUES ('host_status_changed', $1)")
        .bind(json!({"name": "web1", "from": "ok", "to": "security_updates"}))
        .execute(&pool)
        .await
        .unwrap();
    worker::tick(&st).await.unwrap();
    let (err, ok_at): (Option<String>, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT last_error, last_ok_at FROM notification_channels WHERE kind = 'gotify'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(err.as_deref(), Some("nicht erreichbar"));
    assert!(ok_at.is_none());
    let (attempts, job_err): (i32, Option<String>) =
        sqlx::query_as("SELECT attempts, last_error FROM jobs WHERE kind = 'notify'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(attempts, 1);
    let job_err = job_err.unwrap();
    assert!(
        !job_err.contains("GEHEIMER-BODY") && !job_err.contains("127.0.0.1"),
        "{job_err}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn daily_summary_is_scheduled_per_channel_with_own_time(pool: PgPool) {
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    let save = |kind: &'static str, time: Option<&'static str>, events: &'static [&'static str]| {
        let st = st.clone();
        async move {
            store::save(
                &st.pool,
                &st.cfg,
                kind,
                store::Update {
                    enabled: true,
                    config: if kind == "ntfy" {
                        json!({"url": "https://n.example", "topic": "t"})
                    } else {
                        json!({"url": "https://g.example"})
                    },
                    secret: (kind == "gotify").then(|| "tok".to_owned()),
                    clear_secret: false,
                    events: events.iter().map(|e| (*e).to_owned()).collect(),
                    summary_time: time
                        .map(|t| chrono::NaiveTime::parse_from_str(t, "%H:%M").unwrap()),
                    timezone: Some("UTC".into()),
                },
            )
            .await
            .unwrap();
        }
    };
    save("ntfy", Some("00:00"), &["daily_summary"]).await; // fällig
    save("gotify", Some("23:59"), &["daily_summary"]).await; // erst am Tagesende
    worker::schedule_once(&st).await.unwrap();
    let channels: Vec<Value> =
        sqlx::query_scalar("SELECT payload FROM jobs WHERE kind = 'daily_summary'")
            .fetch_all(&pool)
            .await
            .unwrap();
    let channels: Vec<&str> = channels
        .iter()
        .map(|p| p["channel"].as_str().unwrap())
        .collect();
    assert!(channels.contains(&"ntfy"));
    let now = chrono::Utc::now().time();
    if now < chrono::NaiveTime::from_hms_opt(23, 59, 0).unwrap() {
        assert!(!channels.contains(&"gotify"), "{channels:?}");
    }
    // Zweiter Durchlauf am selben Tag: kein Duplikat.
    worker::schedule_once(&st).await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs WHERE kind = 'daily_summary' AND payload->>'channel' = 'ntfy'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn new_channels_validate_and_never_echo_secrets(pool: PgPool) {
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    let app = router(st);
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let put = |kind: &'static str, body: Value| {
        let app = app.clone();
        let admin = admin.map(|(a, b)| (a.to_owned(), b.to_owned()));
        async move {
            let h: Vec<(&str, &str)> = admin
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            call(
                &app,
                Method::PUT,
                &format!("/api/v1/notifications/{kind}"),
                &h,
                Some(body),
            )
            .await
        }
    };

    // Telegram: Token nur im gültigen Format; weder gültiger noch ungültiger Wert kommt zurück.
    let token = "123456789:AAE_abcdefghijklmnopqrstuvwxyz012345";
    let r = put(
        "telegram",
        json!({"enabled": true, "config": {"chat_id": "42"}, "secret": token}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert_eq!(r.json["secret_set"], true);
    assert!(
        !r.raw.contains("AAE_") && !r.raw.contains("123456789:"),
        "{}",
        r.raw
    );
    let bad = put(
        "telegram",
        json!({"enabled": true, "config": {"chat_id": "42"}, "secret": "kaputt-GEHEIM"}),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(!bad.raw.contains("GEHEIM"));
    let bad = put(
        "telegram",
        json!({"enabled": true, "config": {"chat_id": "keine zahl"}, "secret": token}),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // Slack: nur hooks.slack.com, Fehlermeldung ohne die URL.
    let hook = "https://hooks.slack.com/services/T000/B000/GEHEIMSLACK";
    let r = put("slack", json!({"enabled": true, "secret": hook})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert!(!r.raw.contains("GEHEIMSLACK"));
    let bad = put(
        "slack",
        json!({"enabled": true, "secret": "https://evil.example/services/GEHEIMSLACK"}),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(!bad.raw.contains("GEHEIMSLACK"));

    // Webhook: SSRF-Prüfung der URL, Bearer-Token write-only.
    let r = put("webhook", json!({"enabled": true, "config": {"url": "https://hook.example.org/in"}, "secret": SECRET})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.raw);
    assert!(!r.raw.contains(SECRET));
    let bad = put(
        "webhook",
        json!({"enabled": true, "config": {"url": "ftp://hook.example.org/in"}}),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // SMTP: Port-Whitelist, Verschlüsselungspflicht, Header-Injection, Passwort write-only.
    let smtp = |port: &str, security: &str, from: &str, to: &str| {
        json!({"enabled": true, "secret": SECRET, "config": {
            "host": "mail.example.org", "port": port, "security": security,
            "username": "pw", "from": from, "to": to}})
    };
    let ok = put(
        "smtp",
        smtp("587", "starttls", "pw@example.org", "a@example.org"),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.raw);
    assert!(!ok.raw.contains(SECRET));
    assert_eq!(ok.json["config"]["port"], "587");
    for (port, sec, from, to) in [
        ("22", "starttls", "pw@example.org", "a@example.org"),
        ("587", "none", "pw@example.org", "a@example.org"),
        (
            "587",
            "starttls",
            "pw@example.org\r\nBcc: x@example.net",
            "a@example.org",
        ),
        (
            "587",
            "starttls",
            "pw@example.org",
            "a@example.org\nBcc: x@example.net",
        ),
    ] {
        let r = put("smtp", smtp(port, sec, from, to)).await;
        assert_eq!(
            r.status,
            StatusCode::BAD_REQUEST,
            "{port} {sec} {from:?} {to:?}"
        );
        assert!(!r.raw.contains(SECRET));
    }
    let list = call(&app, Method::GET, "/api/v1/notifications", &admin, None).await;
    for s in [SECRET, "AAE_", "GEHEIMSLACK"] {
        assert!(!list.raw.contains(s), "Liste enthält {s}");
    }
}

// ---------- F3: Geheimnis gehört zum gespeicherten Ziel ----------

async fn put_ch(
    app: &Router,
    admin: &[(&str, &str)],
    kind: &str,
    body: Value,
) -> (StatusCode, Value, String) {
    let r = call(
        app,
        Method::PUT,
        &format!("/api/v1/notifications/{kind}"),
        admin,
        Some(body),
    )
    .await;
    (r.status, r.json, r.raw)
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_channel_address_discards_the_stored_secret(pool: PgPool) {
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    let app = router(st);
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let stored = |kind: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT secret FROM notification_channels WHERE kind = $1",
            )
            .bind(kind)
            .fetch_one(&pool)
            .await
            .unwrap()
            .is_some()
        }
    };
    let gotify = |url: &str| json!({"enabled": true, "config": {"url": url}});
    let mut first = gotify("https://gotify.example.org");
    first["secret"] = json!(SECRET);
    assert_eq!(
        put_ch(&app, &admin, "gotify", first).await.0,
        StatusCode::OK
    );

    // Gleiches Ziel in anderer Schreibweise (Großbuchstaben, Port 443, Pfad): das Geheimnis bleibt.
    for same in [
        "https://GOTIFY.Example.org:443",
        "https://gotify.example.org/sub/path",
    ] {
        let (s, j, raw) = put_ch(&app, &admin, "gotify", gotify(same)).await;
        assert_eq!(s, StatusCode::OK, "{raw}");
        assert_eq!(j["secret_set"], true, "{same}");
        assert!(stored("gotify").await);
    }
    // Anderer Host oder anderer Port: Geheimnis wird verworfen. Ein aktiver Gotify-Kanal braucht den Schlüssel dann neu.
    for other in [
        "https://evil.example.net",
        "https://gotify.example.org:8443",
    ] {
        let (s, _, raw) = put_ch(&app, &admin, "gotify", gotify(other)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{other}: {raw}");
        assert!(!raw.contains(SECRET));
        assert!(
            stored("gotify").await,
            "abgelehntes Speichern ändert nichts"
        );
    }
    // Ausgeschaltet gespeichert: Adresse neu, Geheimnis weg.
    let mut off = gotify("https://evil.example.net");
    off["enabled"] = json!(false);
    let (s, j, raw) = put_ch(&app, &admin, "gotify", off).await;
    assert_eq!(s, StatusCode::OK, "{raw}");
    assert_eq!(j["secret_set"], false);
    assert!(!stored("gotify").await);
    assert!(!raw.contains(SECRET));
    // Mit neuem Schlüssel wieder aktiv.
    let mut again = gotify("https://evil.example.net");
    again["secret"] = json!("NEUER-SCHLUESSEL");
    assert_eq!(
        put_ch(&app, &admin, "gotify", again).await.0,
        StatusCode::OK
    );
    assert!(stored("gotify").await);
}

#[sqlx::test(migrations = "./migrations")]
async fn channel_secret_is_never_accepted_over_plain_http_unless_allowlisted(pool: PgPool) {
    let st = state(
        pool.clone(),
        &[
            ("PATCHWATCH_SECRET_KEY", KEY),
            ("PATCHWATCH_NOTIFY_ALLOWED_HOSTS", "gotify.lan"),
        ],
    );
    let app = router(st);
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let body = |url: &str| json!({"enabled": true, "config": {"url": url}, "secret": SECRET});
    let (s, _, raw) = put_ch(&app, &admin, "gotify", body("http://gotify.example.org")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{raw}");
    assert!(!raw.contains(SECRET));
    // Ausdrücklich erlaubter interner Host: wie bisher möglich.
    let (s, _, raw) = put_ch(&app, &admin, "gotify", body("http://gotify.lan:8080")).await;
    assert_eq!(s, StatusCode::OK, "{raw}");
    // Von dort auf einen anderen Host: Geheimnis wird verworfen, nicht mitgenommen.
    let off = json!({"enabled": false, "config": {"url": "https://other.example.org"}});
    let (_, j, _) = put_ch(&app, &admin, "gotify", off).await;
    assert_eq!(j["secret_set"], false);
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_smtp_and_webhook_targets_discard_their_secrets(pool: PgPool) {
    let st = state(pool.clone(), &[("PATCHWATCH_SECRET_KEY", KEY)]);
    let app = router(st);
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let smtp = |host: &str, port: &str| {
        json!({"enabled": true, "config": {"host": host, "port": port, "security": "starttls",
            "username": "u", "from": "a@example.org", "to": "b@example.org"}})
    };
    let mut first = smtp("mail.example.org", "587");
    first["secret"] = json!(SECRET);
    assert_eq!(put_ch(&app, &admin, "smtp", first).await.0, StatusCode::OK);
    let (_, j, _) = put_ch(&app, &admin, "smtp", smtp("MAIL.example.org", "587")).await;
    assert_eq!(j["secret_set"], true);
    for (h, p) in [("mail.evil.example", "587"), ("mail.example.org", "465")] {
        let (_, j, raw) = put_ch(&app, &admin, "smtp", smtp(h, p)).await;
        assert_eq!(j["secret_set"], false, "{h}:{p}");
        assert!(!raw.contains(SECRET));
        // Neu setzen für den nächsten Durchlauf.
        let mut again = smtp(h, p);
        again["secret"] = json!(SECRET);
        assert_eq!(put_ch(&app, &admin, "smtp", again).await.0, StatusCode::OK);
    }
    // Webhook mit Bearer-Token.
    let hook = |url: &str| json!({"enabled": true, "config": {"url": url}});
    let mut first = hook("https://hook.example.org/a");
    first["secret"] = json!(SECRET);
    assert_eq!(
        put_ch(&app, &admin, "webhook", first).await.0,
        StatusCode::OK
    );
    let (_, j, _) = put_ch(&app, &admin, "webhook", hook("https://hook.example.org/b")).await;
    assert_eq!(j["secret_set"], true);
    let (_, j, _) = put_ch(&app, &admin, "webhook", hook("https://other.example.org/a")).await;
    assert_eq!(j["secret_set"], false);
}
