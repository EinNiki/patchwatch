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
