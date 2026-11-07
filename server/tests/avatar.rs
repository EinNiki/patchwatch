//! Profilbild: Upload (PNG/WebP, streng geprüft), Auslieferung mit festen Headern, Entfernen, Zugriffsschutz.

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::avatar::{sample_png, sample_png_with_chunk, sample_webp};
use patchwatch_server::config::Config;
use patchwatch_server::{admin, router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const PASSWORD: &str = "ein-langes-test-passwort";

struct Raw {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn raw(
    app: &Router,
    method: Method,
    uri: &str,
    s: Option<&(String, String)>,
    ctype: Option<&str>,
    body: Vec<u8>,
    csrf: bool,
) -> Raw {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some((cookie, token)) = s {
        b = b.header("cookie", cookie);
        if csrf {
            b = b.header("x-csrf-token", token);
        }
    }
    if let Some(c) = ctype {
        b = b.header(header::CONTENT_TYPE, c);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    Raw {
        status: parts.status,
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes().to_vec(),
    }
}

async fn login(app: &Router) -> (String, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"username": "admin", "password": PASSWORD}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let cookie = parts
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let v: Value = serde_json::from_slice(&body.collect().await.unwrap().to_bytes()).unwrap();
    (cookie, v["csrf_token"].as_str().unwrap().to_owned())
}

async fn setup(pool: &PgPool) -> (Router, (String, String)) {
    let app = router(
        AppState::new(pool.clone(), Config::from_sources(None, &|_| None).unwrap()).unwrap(),
    );
    admin::upsert_admin(pool, "admin", PASSWORD).await.unwrap();
    let s = login(&app).await;
    (app, s)
}

const URI: &str = "/api/v1/auth/avatar";

#[sqlx::test(migrations = "./migrations")]
async fn upload_serve_and_remove_with_fixed_headers(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    // Zuerst gibt es keins.
    assert_eq!(
        raw(&app, Method::GET, URI, Some(&s), None, vec![], false)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let me = raw(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        Some(&s),
        None,
        vec![],
        false,
    )
    .await;
    assert!(serde_json::from_slice::<Value>(&me.body).unwrap()["avatar"].is_null());

    let png = sample_png(128, 128, 5);
    let r = raw(
        &app,
        Method::PUT,
        URI,
        Some(&s),
        Some("image/png"),
        png.clone(),
        true,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let me = raw(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        Some(&s),
        None,
        vec![],
        false,
    )
    .await;
    assert!(
        serde_json::from_slice::<Value>(&me.body).unwrap()["avatar"].is_number(),
        "Cache-Schlüssel in /auth/me"
    );

    let g = raw(&app, Method::GET, URI, Some(&s), None, vec![], false).await;
    assert_eq!(g.status, StatusCode::OK);
    assert_eq!(g.body, png, "genau die gespeicherten Bytes");
    let h = &g.headers;
    assert_eq!(h[header::CONTENT_TYPE], "image/png");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::CONTENT_SECURITY_POLICY], "default-src 'none'");
    assert!(h[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .starts_with("private"));

    // WebP ersetzt PNG und wird mit seinem Typ ausgeliefert.
    let webp = sample_webp(128, 128);
    assert_eq!(
        raw(
            &app,
            Method::PUT,
            URI,
            Some(&s),
            Some("image/webp"),
            webp.clone(),
            true
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let g = raw(&app, Method::GET, URI, Some(&s), None, vec![], false).await;
    assert_eq!(
        (g.headers[header::CONTENT_TYPE].to_str().unwrap(), g.body),
        ("image/webp", webp)
    );

    // Entfernen: danach 404, kein Cache-Schlüssel mehr.
    assert_eq!(
        raw(&app, Method::DELETE, URI, Some(&s), None, vec![], true)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        raw(&app, Method::GET, URI, Some(&s), None, vec![], false)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let me = raw(
        &app,
        Method::GET,
        "/api/v1/auth/me",
        Some(&s),
        None,
        vec![],
        false,
    )
    .await;
    assert!(serde_json::from_slice::<Value>(&me.body).unwrap()["avatar"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_bad_uploads_and_never_stores_them(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>".to_vec();
    let mut cases: Vec<(&str, &str, Vec<u8>)> = vec![
        ("SVG", "image/svg+xml", svg.clone()),
        ("SVG als PNG deklariert", "image/png", svg),
        (
            "GIF",
            "image/gif",
            b"GIF89a\x80\x00\x80\x00\x00\x00\x00;".to_vec(),
        ),
        (
            "JPEG",
            "image/jpeg",
            vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, b'J', b'F', b'I', b'F'],
        ),
        (
            "kaputt",
            "image/png",
            sample_png(128, 128, 1)[..40].to_vec(),
        ),
        ("falsche Größe", "image/png", sample_png(64, 64, 1)),
        (
            "Metadaten",
            "image/png",
            sample_png_with_chunk(b"tEXt", b"Author\0jemand"),
        ),
        (
            "Typ passt nicht zum Inhalt",
            "image/webp",
            sample_png(128, 128, 1),
        ),
        ("ohne Typ", "", sample_png(128, 128, 1)),
        ("leer", "image/png", vec![]),
    ];
    for (name, ctype, body) in cases {
        let r = raw(
            &app,
            Method::PUT,
            URI,
            Some(&s),
            (!ctype.is_empty()).then_some(ctype),
            body,
            true,
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{name}");
    }
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE avatar IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, 0, "nichts Ungültiges gespeichert");
}

#[sqlx::test(migrations = "./migrations")]
async fn needs_login_and_csrf(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    let png = sample_png(128, 128, 3);
    assert_eq!(
        raw(
            &app,
            Method::PUT,
            URI,
            Some(&s),
            Some("image/png"),
            png.clone(),
            true
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    // Ohne Anmeldung: weder lesen noch schreiben noch löschen.
    assert_eq!(
        raw(&app, Method::GET, URI, None, None, vec![], false)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        raw(
            &app,
            Method::PUT,
            URI,
            None,
            Some("image/png"),
            png.clone(),
            true
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        raw(&app, Method::DELETE, URI, None, None, vec![], true)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // Angemeldet, aber ohne CSRF-Token: Schreiben und Löschen verboten.
    assert_eq!(
        raw(
            &app,
            Method::PUT,
            URI,
            Some(&s),
            Some("image/png"),
            png,
            false
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        raw(&app, Method::DELETE, URI, Some(&s), None, vec![], false)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        raw(&app, Method::GET, URI, Some(&s), None, vec![], false)
            .await
            .status,
        StatusCode::OK,
        "das Bild blieb"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn upload_is_rate_limited(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    let png = sample_png(128, 128, 3);
    for _ in 0..10 {
        assert_eq!(
            raw(
                &app,
                Method::PUT,
                URI,
                Some(&s),
                Some("image/png"),
                png.clone(),
                true
            )
            .await
            .status,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        raw(
            &app,
            Method::PUT,
            URI,
            Some(&s),
            Some("image/png"),
            png,
            true
        )
        .await
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn too_large_files_are_rejected(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    let mut big = sample_png(128, 128, 1);
    big.resize(64 * 1024 + 1, 0);
    assert_eq!(
        raw(
            &app,
            Method::PUT,
            URI,
            Some(&s),
            Some("image/png"),
            big,
            true
        )
        .await
        .status,
        StatusCode::BAD_REQUEST,
        "65 KB"
    );
    // Sehr große Datei wird schon am Body-Limit abgewiesen.
    let r = raw(
        &app,
        Method::PUT,
        URI,
        Some(&s),
        Some("image/png"),
        vec![0; 2 * 1024 * 1024],
        true,
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_users WHERE avatar IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, 0);
}
