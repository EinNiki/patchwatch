//! API für UI v2: CVE-Distributionen und Filter, CVE-Detail, Passwort ändern, Einstellungen.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::{admin, router, worker, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const PASSWORD: &str = "ein-langes-test-passwort";

struct Resp {
    status: StatusCode,
    json: Value,
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    session: Option<&(String, String)>,
    body: Option<Value>,
) -> (Resp, Option<String>) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some((cookie, csrf)) = session {
        b = b.header("cookie", cookie).header("x-csrf-token", csrf);
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
    let cookie = parts
        .headers
        .get(header::SET_COOKIE)
        .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_owned());
    (
        Resp {
            status: parts.status,
            json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        },
        cookie,
    )
}

async fn login_with(app: &Router, password: &str) -> Option<(String, String)> {
    let (r, cookie) = call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({"username": "admin", "password": password})),
    )
    .await;
    (r.status == StatusCode::OK).then(|| {
        (
            cookie.unwrap(),
            r.json["csrf_token"].as_str().unwrap().to_owned(),
        )
    })
}

async fn setup(pool: &PgPool) -> (Router, (String, String)) {
    let app = router(
        AppState::new(pool.clone(), Config::from_sources(None, &|_| None).unwrap()).unwrap(),
    );
    admin::upsert_admin(pool, "admin", PASSWORD).await.unwrap();
    let s = login_with(&app, PASSWORD).await.unwrap();
    (app, s)
}

async fn host(pool: &PgPool, name: &str, codename: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO hosts (name, token_hash, os_id, os_codename) VALUES ($1, $2, 'ubuntu', $3) RETURNING id")
        .bind(name).bind(name.as_bytes()).bind(codename).fetch_one(pool).await.unwrap()
}

async fn src(
    pool: &PgPool,
    cve: &str,
    source: &str,
    release: &str,
    package: &str,
    status: &str,
    fix: Option<&str>,
) {
    sqlx::query("INSERT INTO cves (id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(cve)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cve_source_status (cve_id, source, release, package, status, fix_version) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(cve).bind(source).bind(release).bind(package).bind(status).bind(fix).execute(pool).await.unwrap();
}

fn ids(r: &Resp) -> Vec<String> {
    r.json
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect()
}

#[sqlx::test(migrations = "./migrations")]
async fn cve_list_shows_my_releases_by_default_and_filters(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    host(&pool, "web1", "noble").await;
    host(&pool, "db1", "bookworm").await;
    // A: Debian fixed on my release, Ubuntu still open on my release.
    src(
        &pool,
        "CVE-2024-0001",
        "debian",
        "bookworm",
        "linux",
        "fixed",
        Some("6.1.99-1"),
    )
    .await;
    src(
        &pool,
        "CVE-2024-0001",
        "debian",
        "trixie",
        "linux",
        "vulnerable",
        None,
    )
    .await;
    src(
        &pool,
        "CVE-2024-0001",
        "ubuntu",
        "noble",
        "linux",
        "vulnerable",
        None,
    )
    .await;
    src(
        &pool,
        "CVE-2024-0001",
        "ubuntu",
        "noble",
        "linux-signed",
        "fix_pending",
        Some("6.8.0-1"),
    )
    .await;
    // B: Ubuntu fixed on noble, Debian open on bookworm (the reverse).
    src(
        &pool,
        "CVE-2024-0002",
        "ubuntu",
        "noble",
        "openssl",
        "fixed",
        Some("3.0.13-1"),
    )
    .await;
    src(
        &pool,
        "CVE-2024-0002",
        "debian",
        "bookworm",
        "openssl",
        "vulnerable",
        None,
    )
    .await;
    // C: only a release no host runs.
    src(
        &pool,
        "CVE-2024-0003",
        "ubuntu",
        "focal",
        "bash",
        "vulnerable",
        None,
    )
    .await;

    let (all, _) = call(
        &app,
        Method::GET,
        "/api/v1/cves?releases=all",
        Some(&s),
        None,
    )
    .await;
    assert_eq!(all.status, StatusCode::OK);
    let a = all
        .json
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "CVE-2024-0001")
        .unwrap();
    assert_eq!(
        a["distros"].as_array().unwrap().len(),
        3,
        "debian/bookworm, debian/trixie, ubuntu/noble"
    );

    let (mine, _) = call(&app, Method::GET, "/api/v1/cves", Some(&s), None).await;
    let a = mine
        .json
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "CVE-2024-0001")
        .unwrap();
    let d = a["distros"].as_array().unwrap();
    assert_eq!(d.len(), 2, "trixie läuft auf keinem Host");
    assert_eq!(a["hidden_releases"], 1);
    assert!(d.iter().all(|x| x["mine"] == true));
    let ubuntu = d.iter().find(|x| x["source"] == "ubuntu").unwrap();
    assert_eq!(
        ubuntu["status"], "vulnerable",
        "ungünstigster Status über beide Pakete"
    );
    assert_eq!(ubuntu["packages"], 2);
    let c = mine
        .json
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "CVE-2024-0003")
        .unwrap();
    assert!(c["distros"].as_array().unwrap().is_empty());
    assert_eq!(c["hidden_releases"], 1);

    let (r, _) = call(
        &app,
        Method::GET,
        "/api/v1/cves?split=debian_fixed_ubuntu_open",
        Some(&s),
        None,
    )
    .await;
    assert_eq!(ids(&r), ["CVE-2024-0001"]);
    let (r, _) = call(
        &app,
        Method::GET,
        "/api/v1/cves?split=ubuntu_fixed_debian_open",
        Some(&s),
        None,
    )
    .await;
    assert_eq!(ids(&r), ["CVE-2024-0002"]);
    // trixie is not mine: with releases=mine the split ignores it, with all it counts as well.
    let (r, _) = call(
        &app,
        Method::GET,
        "/api/v1/cves?distro=ubuntu",
        Some(&s),
        None,
    )
    .await;
    let mut got = ids(&r);
    got.sort();
    assert_eq!(
        got,
        ["CVE-2024-0001", "CVE-2024-0002"],
        "focal ist nicht meins"
    );
    let (r, _) = call(
        &app,
        Method::GET,
        "/api/v1/cves?distro=ubuntu&releases=all",
        Some(&s),
        None,
    )
    .await;
    assert_eq!(ids(&r).len(), 3);
    let a = r
        .json
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "CVE-2024-0001")
        .unwrap();
    assert!(
        a["distros"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["source"] == "ubuntu"),
        "Chips folgen dem Distro-Filter"
    );

    for bad in [
        "releases=x",
        "distro=arch",
        "split=foo",
        "distro=ubuntu%27%3B--",
    ] {
        let (r, _) = call(
            &app,
            Method::GET,
            &format!("/api/v1/cves?{bad}"),
            Some(&s),
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (r, _) = call(&app, Method::GET, "/api/v1/cves", None, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn cve_detail_has_links_last_change_and_hosts(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    let h = host(&pool, "web1", "noble").await;
    src(
        &pool,
        "CVE-2024-1086",
        "ubuntu",
        "noble",
        "linux",
        "fixed",
        Some("6.8.0-35"),
    )
    .await;
    src(
        &pool,
        "CVE-2024-1086",
        "debian",
        "bookworm",
        "linux",
        "vulnerable",
        None,
    )
    .await;
    sqlx::query(
        "UPDATE cve_source_status SET updated_at = '2026-05-01T10:00:00Z' WHERE source = 'ubuntu'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE cve_source_status SET updated_at = '2026-06-02T11:00:00Z' WHERE source = 'debian'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE cves SET updated_at = '2026-01-01T00:00:00Z'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO host_cve_status (host_id, cve_id, status, reason) VALUES ($1, 'CVE-2024-1086', 'vulnerable', 'Kernel 6.8.0-1 < 6.8.0-35')")
        .bind(h).execute(&pool).await.unwrap();

    let (r, _) = call(
        &app,
        Method::GET,
        "/api/v1/cves/CVE-2024-1086",
        Some(&s),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["last_change_at"], "2026-06-02T11:00:00Z");
    let links: Vec<(String, String)> = r.json["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["source"].as_str().unwrap().into(),
                l["url"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        links,
        [
            (
                "debian".to_owned(),
                "https://security-tracker.debian.org/tracker/CVE-2024-1086".to_owned()
            ),
            (
                "ubuntu".to_owned(),
                "https://ubuntu.com/security/CVE-2024-1086".to_owned()
            ),
        ]
    );
    assert_eq!(r.json["distros"].as_array().unwrap().len(), 2);
    assert_eq!(r.json["hosts"][0]["name"], "web1");
    assert_eq!(r.json["hosts"][0]["status"], "vulnerable");
    assert_eq!(r.json["sources"].as_array().unwrap().len(), 2);
    let (r, _) = call(
        &app,
        Method::GET,
        "/api/v1/cves/CVE-1999-9999",
        Some(&s),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let (r, _) = call(&app, Method::GET, "/api/v1/cves/evil", Some(&s), None).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn password_change(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    let other = login_with(&app, PASSWORD).await.unwrap();
    let new = "ein-ganz-neues-passwort-42";
    let body = |cur: &str, new: &str| Some(json!({"current_password": cur, "new_password": new}));

    // Without CSRF token or session: refused.
    let (r, _) = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        None,
        body(PASSWORD, new),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let cookie_only = (s.0.clone(), String::new());
    let (r, _) = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        Some(&cookie_only),
        body(PASSWORD, new),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let (r, _) = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        Some(&s),
        body("falsch-falsch-falsch", new),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let (r, _) = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        Some(&s),
        body(PASSWORD, "kurz"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let (r, _) = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        Some(&s),
        body(PASSWORD, PASSWORD),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        login_with(&app, PASSWORD).await.is_some(),
        "Passwort unverändert"
    );

    let (r, _) = call(
        &app,
        Method::POST,
        "/api/v1/auth/password",
        Some(&s),
        body(PASSWORD, new),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(login_with(&app, PASSWORD).await.is_none());
    assert!(login_with(&app, new).await.is_some());
    let (r, _) = call(&app, Method::GET, "/api/v1/auth/me", Some(&s), None).await;
    assert_eq!(r.status, StatusCode::OK, "aktuelle Session bleibt");
    let (r, _) = call(&app, Method::GET, "/api/v1/auth/me", Some(&other), None).await;
    assert_eq!(
        r.status,
        StatusCode::UNAUTHORIZED,
        "andere Sessions werden beendet"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn settings_retention_is_validated_and_used_by_cleanup(pool: PgPool) {
    let (app, s) = setup(&pool).await;
    let (r, _) = call(&app, Method::GET, "/api/v1/settings", Some(&s), None).await;
    assert_eq!(r.json["report_retention_days"], 180);
    for bad in [
        json!({"report_retention_days": 6}),
        json!({"report_retention_days": 4000}),
        json!({"report_retention_days": "x"}),
        json!({"nope": 1}),
    ] {
        let (r, _) = call(
            &app,
            Method::PUT,
            "/api/v1/settings",
            Some(&s),
            Some(bad.clone()),
        )
        .await;
        assert!(r.status.is_client_error(), "{bad}");
    }
    let (r, _) = call(
        &app,
        Method::PUT,
        "/api/v1/settings",
        None,
        Some(json!({"report_retention_days": 30})),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let h = host(&pool, "web1", "noble").await;
    for days in [100, 20, 1] {
        sqlx::query("INSERT INTO reports (host_id, received_at, status, raw) VALUES ($1, now() - make_interval(days => $2), 'ok', '{}')")
            .bind(h).bind(days).execute(&pool).await.unwrap();
    }
    let (r, _) = call(
        &app,
        Method::PUT,
        "/api/v1/settings",
        Some(&s),
        Some(json!({"report_retention_days": 30})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let st = AppState::new(pool.clone(), Config::from_sources(None, &|_| None).unwrap()).unwrap();
    worker::cleanup(&st).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM reports")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        n, 2,
        "nur der 100 Tage alte Report fliegt raus (UI-Wert 30 schlägt Standard 180)"
    );
}
