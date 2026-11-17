//! Routen der Container-Ansicht, Anstoß der Prüfung, Ereignis „Neues Image verfügbar“ und die Einstellung des
//! Intervalls (Wegwerf-Datenbank je Test).
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::containers::announce::announce;
use patchwatch_server::containers::registry::Registries;
use patchwatch_server::{admin, router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const PW: &str = "TESTWERT-passwort-0001";
const REG: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LOCAL: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CFG: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn state(pool: PgPool) -> AppState {
    let cfg = Config::from_sources(None, &|k| {
        (k == "PATCHWATCH_TRUST_PROXY").then(|| "true".to_owned())
    })
    .unwrap();
    let mut st = AppState::new(pool, cfg).unwrap();
    // Nie eine echte Registry: Adresse ohne Dienst.
    st.registries = Registries::for_tests("http://127.0.0.1:9");
    st
}

struct Resp {
    status: StatusCode,
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
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Resp {
        status: parts.status,
        json,
    }
}

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

async fn login(app: &Router, pool: &PgPool, name: &str, role: &str, ip: &str) -> Sess {
    admin::upsert_admin(pool, name, PW).await.unwrap();
    sqlx::query("UPDATE admin_users SET role = $2, status = 'active' WHERE username = $1")
        .bind(name)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    let r = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header("x-forwarded-for", ip)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"username": name, "password": PW}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(r).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Anmeldung {name}");
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
    let bytes = body.collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    Sess {
        cookie,
        csrf: v["csrf_token"].as_str().unwrap().to_owned(),
    }
}

async fn host(pool: &PgPool, name: &str, docker: Option<&str>) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO hosts (name, token_hash, docker_state) VALUES ($1, decode(md5($1), 'hex'), $2) RETURNING id",
    )
    .bind(name)
    .bind(docker)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn container(pool: &PgPool, host_id: i64, name: &str, image: &str, service: Option<&str>) {
    sqlx::query(
        "INSERT INTO host_containers (host_id, container_id, name, state, image_ref, image_id, repo_digests, os, arch, \
         compose_service, first_seen, last_seen) VALUES ($1, $2, $2, 'running', $3, $4, $5, 'linux', 'amd64', $6, now(), now())",
    )
    .bind(host_id)
    .bind(name)
    .bind(image)
    .bind(CFG)
    .bind(vec![format!("app@{LOCAL}")])
    .bind(service)
    .execute(pool)
    .await
    .unwrap();
}

async fn registry_state(pool: &PgPool, digest: &str, age: Duration) {
    sqlx::query(
        "INSERT INTO container_image_checks (registry, repository, tag, platform, checked_at, status, registry_digest, \
         manifest_kind) VALUES ('docker.io', 'library/app', 'latest', '', $1, 'ok', $2, 'manifest') \
         ON CONFLICT (registry, repository, tag, platform) DO UPDATE SET checked_at = EXCLUDED.checked_at, \
         registry_digest = EXCLUDED.registry_digest",
    )
    .bind(Utc::now() - age)
    .bind(digest)
    .execute(pool)
    .await
    .unwrap();
}

/// Ein Host ohne aktivierte Docker-Erfassung zeigt keine Container, auch wenn noch Zeilen vorliegen.
#[sqlx::test]
async fn docker_off_host_shows_nothing(pool: PgPool) {
    let app = router(state(pool.clone()));
    let s = login(&app, &pool, "viewer1", "viewer", "10.0.0.1").await;
    let off = host(&pool, "off", None).await;
    container(&pool, off, "c1", "app:latest", Some("web")).await;
    let r = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{off}/containers"),
        &s.h(),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.json["docker"].is_null());
    assert_eq!(r.json["items"], json!([]));
    let all = call(&app, Method::GET, "/api/v1/containers", &s.h(), None).await;
    assert_eq!(all.json["total"], 0);
    let missing = call(
        &app,
        Method::GET,
        "/api/v1/hosts/99999/containers",
        &s.h(),
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

/// Bewertung, Kopierbefehl, Gruppierung, Filter und Suche.
#[sqlx::test]
async fn host_and_overview_show_verdicts(pool: PgPool) {
    let app = router(state(pool.clone()));
    let s = login(&app, &pool, "viewer1", "viewer", "10.0.0.1").await;
    let h1 = host(&pool, "web1", Some("ok")).await;
    let h2 = host(&pool, "web2", Some("ok")).await;
    container(&pool, h1, "shop", "app:latest", Some("web")).await;
    container(&pool, h2, "shop2", "app:latest", Some("evil; rm -rf /")).await;
    container(&pool, h2, "db", "registry.example.org/x/db:1.0.0", None).await;
    registry_state(&pool, REG, Duration::minutes(1)).await;

    let r = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{h1}/containers"),
        &s.h(),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["docker"]["state"], "ok");
    assert_eq!(r.json["outdated"], 1);
    let c = &r.json["items"][0];
    assert_eq!(c["verdict"]["status"], "update_available");
    assert_eq!(
        c["command"],
        "docker compose pull web && docker compose up -d web"
    );

    // Ein unsicherer Dienstname ergibt keinen Befehl.
    let r2 = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{h2}/containers"),
        &s.h(),
        None,
    )
    .await;
    let shop2 = r2.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "shop2")
        .unwrap();
    assert!(shop2["command"].is_null());

    let all = call(&app, Method::GET, "/api/v1/containers", &s.h(), None).await;
    assert_eq!(all.json["total"], 2, "zwei Images");
    assert_eq!(all.json["outdated_images"], 1);
    assert_eq!(
        all.json["items"][0]["image"], "app:latest",
        "Updates zuerst"
    );
    assert_eq!(all.json["items"][0]["updates"], 2);
    assert_eq!(all.json["items"][0]["hosts"], 2);
    let only = call(
        &app,
        Method::GET,
        "/api/v1/containers?update=1",
        &s.h(),
        None,
    )
    .await;
    assert_eq!(only.json["total"], 1);
    let q = call(
        &app,
        Method::GET,
        "/api/v1/containers?q=EXAMPLE.org",
        &s.h(),
        None,
    )
    .await;
    assert_eq!(q.json["total"], 1);
    assert_eq!(q.json["items"][0]["verdict"]["status"], "unsupported");
}

/// Anstoß: nur mit Recht und CSRF, Mindestabstand je Referenz, Begrenzung je Konto.
#[sqlx::test]
async fn check_needs_right_respects_spacing_and_rate_limit(pool: PgPool) {
    let app = router(state(pool.clone()));
    let viewer = login(&app, &pool, "viewer1", "viewer", "10.0.0.1").await;
    let op = login(&app, &pool, "op1", "operator", "10.0.0.2").await;
    let h = host(&pool, "web1", Some("ok")).await;
    container(&pool, h, "shop", "app:latest", Some("web")).await;

    let denied = call(
        &app,
        Method::POST,
        "/api/v1/containers/check",
        &viewer.h(),
        Some(json!({})),
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let no_csrf = call(
        &app,
        Method::POST,
        "/api/v1/containers/check",
        &[("cookie", op.cookie.as_str())],
        Some(json!({})),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);

    // Nie geprüft: wird angestoßen.
    let ok = call(
        &app,
        Method::POST,
        "/api/v1/containers/check",
        &op.h(),
        Some(json!({})),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.json["started"], 1);
    // Die Prüfung läuft im Hintergrund (gegen eine nicht erreichbare Adresse); erst danach den Stand setzen.
    for _ in 0..100 {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM container_image_checks")
            .fetch_one(&pool)
            .await
            .unwrap();
        if n > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Vor einer Minute geprüft: zu frisch, nichts angestoßen.
    registry_state(&pool, REG, Duration::minutes(1)).await;
    let recent = call(
        &app,
        Method::POST,
        "/api/v1/containers/check",
        &op.h(),
        Some(json!({})),
    )
    .await;
    assert_eq!(
        (
            recent.json["started"].as_i64(),
            recent.json["skipped_recent"].as_i64()
        ),
        (Some(0), Some(1))
    );

    // Vor einer Stunde geprüft: erlaubt.
    registry_state(&pool, REG, Duration::hours(1)).await;
    let again = call(
        &app,
        Method::POST,
        "/api/v1/containers/check",
        &op.h(),
        Some(json!({"host_id": h})),
    )
    .await;
    assert_eq!(again.json["started"], 1);

    // Insgesamt höchstens 6 Anstöße je Minute und Konto (3 sind verbraucht, 3 Abweisungen kommen vorher nicht dazu).
    let mut limited = false;
    for _ in 0..6 {
        let r = call(
            &app,
            Method::POST,
            "/api/v1/containers/check",
            &op.h(),
            Some(json!({})),
        )
        .await;
        limited |= r.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited);
}

/// Ereignis: einmal je Referenz und neuem Stand, nicht bei jeder Prüfung; ohne veralteten Container keines.
#[sqlx::test]
async fn announce_once_per_new_state(pool: PgPool) {
    let h = host(&pool, "web1", Some("ok")).await;
    container(&pool, h, "shop", "app:latest", Some("web")).await;
    let now = Utc::now();
    // Noch keine Prüfung: nichts zu melden.
    assert_eq!(announce(&pool, now).await.unwrap(), 0);
    registry_state(&pool, REG, Duration::minutes(1)).await;
    assert_eq!(announce(&pool, now).await.unwrap(), 1);
    assert_eq!(
        announce(&pool, now).await.unwrap(),
        0,
        "derselbe Stand wird nicht noch einmal gemeldet"
    );
    // Neuer Stand der Registry: wieder ein Ereignis.
    registry_state(
        &pool,
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        Duration::minutes(1),
    )
    .await;
    assert_eq!(announce(&pool, now).await.unwrap(), 1);
    let payloads: Vec<Value> =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind = 'image_update' ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(payloads.len(), 2);
    assert_eq!(payloads[0]["image"], "app:latest");
    assert_eq!(payloads[0]["hosts"], json!(["web1"]));
    // Ist der Container aktuell, gibt es keines.
    sqlx::query("UPDATE host_containers SET repo_digests = ARRAY['app@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd']")
        .execute(&pool)
        .await
        .unwrap();
    registry_state(
        &pool,
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        Duration::minutes(1),
    )
    .await;
    assert_eq!(
        announce(&pool, now).await.unwrap(),
        1,
        "wieder veraltet gegenüber dem neuen Stand"
    );
}

/// Intervall der Image-Prüfung: Standard 6, Grenzen 1 bis 168, nur mit Schreibrecht.
#[sqlx::test]
async fn interval_setting_is_validated(pool: PgPool) {
    let app = router(state(pool.clone()));
    let admin = login(&app, &pool, "adm", "admin", "10.0.0.3").await;
    let g = call(&app, Method::GET, "/api/v1/settings", &admin.h(), None).await;
    assert_eq!(g.json["container_interval_hours"], 6);
    for bad in [0, 169, -1] {
        let r = call(
            &app,
            Method::PUT,
            "/api/v1/settings",
            &admin.h(),
            Some(json!({"container_interval_hours": bad})),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/settings",
        &admin.h(),
        Some(json!({"container_interval_hours": 12})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let g = call(&app, Method::GET, "/api/v1/settings", &admin.h(), None).await;
    assert_eq!(g.json["container_interval_hours"], 12);
}

/// Hostliste: Zähler „veraltet“ nur bei aktiver Docker-Erfassung; ohne Erfassung keine Docker-Angaben.
#[sqlx::test]
async fn host_list_shows_outdated_count_only_with_docker(pool: PgPool) {
    let app = router(state(pool.clone()));
    let s = login(&app, &pool, "viewer1", "viewer", "10.0.0.1").await;
    let on = host(&pool, "on", Some("ok")).await;
    let off = host(&pool, "off", None).await;
    container(&pool, on, "shop", "app:latest", Some("web")).await;
    registry_state(&pool, REG, Duration::minutes(1)).await;
    let r = call(&app, Method::GET, "/api/v1/hosts", &s.h(), None).await;
    let rows = r.json.as_array().unwrap();
    let find = |id: i64| rows.iter().find(|h| h["id"] == id).unwrap();
    assert_eq!(find(on)["docker_state"], "ok");
    assert_eq!(find(on)["containers_outdated"], 1);
    assert!(find(off)["docker_state"].is_null());
    assert!(find(off)["containers_outdated"].is_null());
    let d = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{on}"),
        &s.h(),
        None,
    )
    .await;
    assert_eq!(d.json["containers_outdated"], 1);
}
