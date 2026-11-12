use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::{admin, hostops, jobs, router, security, worker, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const TOKEN: &str = "pw_test-token-nur-fuer-tests-0123456789abcdef";
const PASSWORD: &str = "ein-langes-test-passwort";

fn state(pool: PgPool, env: &'static [(&'static str, &'static str)]) -> AppState {
    let cfg = Config::from_sources(None, &|k| {
        env.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| (*v).to_owned())
    })
    .unwrap();
    AppState::new(pool, cfg).unwrap()
}

async fn add_host(pool: &PgPool, name: &str, token: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO hosts (name, token_hash) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(security::sha256(token))
        .fetch_one(pool)
        .await
        .unwrap()
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

fn report(
    hostname: &str,
    running_ver: &str,
    newest_ver: &str,
    security: i32,
    pending: i32,
) -> Value {
    json!({
        "schema_version": 1, "agent_version": "0.1.0", "hostname": hostname, "collected_at_unix": 1,
        "os": {"id": "ubuntu", "version_id": "24.04", "codename": "noble", "pretty_name": "Ubuntu 24.04.3 LTS"},
        "kernel": {
            "running_release": "6.8.0-31-generic",
            "running_package": {"name": "linux-image-6.8.0-31-generic", "version": running_ver,
                                "source": "linux-signed", "source_version": running_ver},
            "newest_installed_release": "6.8.0-35-generic",
            "newest_installed_package": {"name": "linux-image-6.8.0-35-generic", "version": newest_ver,
                                         "source": "linux-signed", "source_version": newest_ver},
            "reboot_needed_kernel": running_ver != newest_ver
        },
        "reboot_required_file": false,
        "updates": {"pending": pending, "security": security},
        "uptime_seconds": 1234, "proxmox": null, "packages": null
    })
}

fn bearer(t: &str) -> String {
    format!("Bearer {t}")
}

async fn login(app: &Router, pool: &PgPool) -> (String, String) {
    admin::upsert_admin(pool, "admin", PASSWORD).await.unwrap();
    let r = call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username": "admin", "password": PASSWORD})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let cookie = r
        .headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let session = cookie.split(';').next().unwrap().to_owned();
    (session, r.json["csrf_token"].as_str().unwrap().to_owned())
}

#[sqlx::test(migrations = "./migrations")]
async fn report_updates_host_and_stores_only_token_hash(pool: PgPool) {
    let st = state(pool.clone(), &[]);
    let app = router(st);
    let id = add_host(&pool, "web1", TOKEN).await;

    let auth = bearer(TOKEN);
    let r = call(
        &app,
        Method::POST,
        "/api/v1/report",
        &[("authorization", &auth)],
        Some(report("web1", "6.8.0-31.31", "6.8.0-35.35", 2, 5)),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    let (status, kernel, reboot, sec): (String, String, Option<bool>, i32) = sqlx::query_as(
        "SELECT status, running_kernel, reboot_needed_kernel, updates_security FROM hosts WHERE id = $1")
        .bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(status, "security_updates");
    assert_eq!(kernel, "6.8.0-31-generic");
    assert_eq!(reboot, Some(true));
    assert_eq!(sec, 2);

    // Der Klartext-Token darf nirgends in der Datenbank stehen.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM hosts WHERE name = $1 OR token_hash = convert_to($1, 'UTF8')",
    )
    .bind(TOKEN)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leaked, 0);
    let hash_len: i32 = sqlx::query_scalar("SELECT length(token_hash) FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(hash_len, 32, "erwartet SHA-256");
    let reports: i64 = sqlx::query_scalar("SELECT count(*) FROM reports WHERE host_id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reports, 1);
    // Statuswechsel pending -> security_updates erzeugt ein Event.
    let events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE kind = 'host_status_changed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(events, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn report_rejects_bad_token_and_invalid_input(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    add_host(&pool, "web1", TOKEN).await;
    let good = report("web1", "6.8.0-31.31", "6.8.0-31.31", 0, 0);

    let r = call(
        &app,
        Method::POST,
        "/api/v1/report",
        &[("authorization", "Bearer falsch")],
        Some(good.clone()),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = call(
        &app,
        Method::POST,
        "/api/v1/report",
        &[],
        Some(good.clone()),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let auth = bearer(TOKEN);
    let h = [("authorization", auth.as_str())];
    let mut bad = good.clone();
    bad["hostname"] = json!("evil host; drop table");
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(bad))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let mut bad = good.clone();
    bad["schema_version"] = json!(99);
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(bad))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let mut bad = good.clone();
    bad["updates"] = json!({"pending": 1, "security": 5});
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(bad))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // Zu großer Body wird abgelehnt.
    let huge = "x".repeat(5 * 1024 * 1024);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/report")
        .header("authorization", &auth)
        .body(Body::from(huge))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn package_list_is_replaced_and_kept_out_of_history(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    let auth = bearer(TOKEN);
    let h = [("authorization", auth.as_str())];

    let mut r1 = report("web1", "6.8.0-31.31", "6.8.0-31.31", 0, 0);
    r1["packages"] = json!([{"name": "bash", "version": "5.2-1", "source": "bash", "source_version": "5.2-1"},
                            {"name": "old-pkg", "version": "1.0", "source": null, "source_version": null}]);
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(r1))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let mut r2 = report("web1", "6.8.0-31.31", "6.8.0-31.31", 0, 0);
    r2["packages"] =
        json!([{"name": "bash", "version": "5.2-2", "source": "bash", "source_version": "5.2-2"}]);
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(r2))
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    let pk: Vec<(String, String)> =
        sqlx::query_as("SELECT name, version FROM host_packages WHERE host_id = $1 ORDER BY name")
            .bind(id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(pk, vec![("bash".to_owned(), "5.2-2".to_owned())]);
    let raw_has_pkgs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM reports WHERE raw ? 'packages'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(raw_has_pkgs, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_package_names_in_report_are_merged(pool: PgPool) {
    // Multiarch: the agent reports the same name once per architecture.
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    let auth = bearer(TOKEN);
    let h = [("authorization", auth.as_str())];
    let mut r = report("web1", "6.8.0-31.31", "6.8.0-31.31", 0, 0);
    r["packages"] = json!([
        {"name": "libc6", "version": "2.39-0ubuntu8.2", "source": "glibc", "source_version": "2.39-0ubuntu8.2"},
        {"name": "bash", "version": "5.2-1", "source": null, "source_version": null},
        {"name": "libc6", "version": "2.39-0ubuntu8.10", "source": "glibc", "source_version": "2.39-0ubuntu8.10"},
        {"name": "libc6", "version": "2.39-0ubuntu8.3", "source": "glibc", "source_version": "2.39-0ubuntu8.3"}]);
    let resp = call(&app, Method::POST, "/api/v1/report", &h, Some(r)).await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);
    let pk: Vec<(String, String)> =
        sqlx::query_as("SELECT name, version FROM host_packages WHERE host_id = $1 ORDER BY name")
            .bind(id)
            .fetch_all(&pool)
            .await
            .unwrap();
    // Exactly one row per name; the highest version wins regardless of order.
    assert_eq!(
        pk,
        vec![
            ("bash".to_owned(), "5.2-1".to_owned()),
            ("libc6".to_owned(), "2.39-0ubuntu8.10".to_owned())
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn auth_csrf_and_host_management(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));

    // Ohne Login kein Zugriff.
    assert_eq!(
        call(&app, Method::GET, "/api/v1/hosts", &[], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );

    let (session, csrf) = login(&app, &pool).await;
    let cookie = [("cookie", session.as_str())];
    assert_eq!(
        call(&app, Method::GET, "/api/v1/hosts", &cookie, None)
            .await
            .status,
        StatusCode::OK
    );

    // Verändernde Anfrage ohne bzw. mit falschem CSRF-Token wird abgelehnt.
    let body = json!({"name": "db1"});
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/hosts",
            &cookie,
            Some(body.clone())
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let wrong = [("cookie", session.as_str()), ("x-csrf-token", "falsch")];
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/hosts",
            &wrong,
            Some(body.clone())
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );

    let ok = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let r = call(&app, Method::POST, "/api/v1/hosts", &ok, Some(body.clone())).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let token = r.json["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("pw_"));
    // Doppelter Name -> 409, ungültiger Name -> 400.
    assert_eq!(
        call(&app, Method::POST, "/api/v1/hosts", &ok, Some(body))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/hosts",
            &ok,
            Some(json!({"name": "a b"}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );

    // Der neue Token funktioniert, nach Rotation nicht mehr.
    let id = r.json["id"].as_i64().unwrap();
    let rep = report("db1", "6.8.0-31.31", "6.8.0-31.31", 0, 0);
    let a = bearer(&token);
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/report",
            &[("authorization", &a)],
            Some(rep.clone())
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let rot = call(
        &app,
        Method::POST,
        &format!("/api/v1/hosts/{id}/rotate-token"),
        &ok,
        None,
    )
    .await;
    assert_eq!(rot.status, StatusCode::OK);
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/report",
            &[("authorization", &a)],
            Some(rep)
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );

    // Logout beendet die Session.
    assert_eq!(
        call(&app, Method::POST, "/api/v1/auth/logout", &ok, None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, Method::GET, "/api/v1/hosts", &cookie, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn login_cookie_flags_and_rate_limit(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    admin::upsert_admin(&pool, "admin", PASSWORD).await.unwrap();

    let r = call(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        &[],
        Some(json!({"username": "admin", "password": PASSWORD})),
    )
    .await;
    let c = r.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    for flag in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(c.contains(flag), "{flag} fehlt in {c}");
    }

    // Falsche Passwörter: erst 401, dann 429 mit Retry-After.
    let mut last = StatusCode::OK;
    let mut retry = None;
    for _ in 0..12 {
        let r = call(
            &app,
            Method::POST,
            "/api/v1/auth/login",
            &[],
            Some(json!({"username": "admin", "password": "falsch"})),
        )
        .await;
        last = r.status;
        retry = r.headers.get(header::RETRY_AFTER).cloned();
        if last == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        assert_eq!(last, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn matrix_never_reports_missing_data_as_ok(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    let (session, csrf) = login(&app, &pool).await;
    let ok = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];

    assert_eq!(
        call(
            &app,
            Method::PUT,
            "/api/v1/watchlist/CVE-2024-1086",
            &ok,
            Some(json!({"note": "wichtig"}))
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, Method::PUT, "/api/v1/watchlist/kaputt", &ok, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let wl = call(&app, Method::GET, "/api/v1/watchlist", &ok, None).await;
    assert_eq!(wl.json[0]["id"], "CVE-2024-1086");
    assert_eq!(wl.json[0]["watched"], true);

    let m = call(
        &app,
        Method::GET,
        &format!("/api/v1/matrix?cves=CVE-2024-1086&hosts={id}"),
        &ok,
        None,
    )
    .await;
    assert_eq!(m.status, StatusCode::OK);
    let cell = &m.json["cells"][0];
    assert_eq!(cell["status"], "unknown");
    assert!(cell["reason"]
        .as_str()
        .unwrap()
        .contains("Noch nicht bewertet"));

    // Standard ohne Parameter: Watchlist x alle Hosts.
    let m = call(&app, Method::GET, "/api/v1/matrix", &ok, None).await;
    assert_eq!(m.json["cells"].as_array().unwrap().len(), 1);
    assert_eq!(
        call(&app, Method::GET, "/api/v1/matrix?cves=nope", &ok, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_hosts_get_event_and_notification_job(pool: PgPool) {
    let st = state(
        pool.clone(),
        &[
            ("PATCHWATCH_NTFY_URL", "http://127.0.0.1:9"),
            ("PATCHWATCH_NTFY_TOPIC", "t"),
        ],
    );
    let id = add_host(&pool, "web1", TOKEN).await;
    sqlx::query("UPDATE hosts SET status = 'ok', last_report_at = $2 WHERE id = $1")
        .bind(id)
        .bind(Utc::now() - Duration::hours(27))
        .execute(&pool)
        .await
        .unwrap();

    let n = hostops::mark_stale_hosts(&pool, Duration::hours(26))
        .await
        .unwrap();
    assert_eq!(n, 1);
    let status: String = sqlx::query_scalar("SELECT status FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "stale");
    // Zweiter Lauf ändert nichts (kein Dauer-Alarm).
    assert_eq!(
        hostops::mark_stale_hosts(&pool, Duration::hours(26))
            .await
            .unwrap(),
        0
    );

    assert_eq!(worker::process_events(&st).await.unwrap(), 1);
    let (kind, payload): (String, Value) = sqlx::query_as("SELECT kind, payload FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kind, "notify");
    assert!(payload["title"].as_str().unwrap().starts_with("web1:"));
    assert_eq!(worker::process_events(&st).await.unwrap(), 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn no_notification_job_without_ntfy_config(pool: PgPool) {
    let st = state(pool.clone(), &[]);
    let id = add_host(&pool, "web1", TOKEN).await;
    let mut tx = pool.begin().await.unwrap();
    hostops::set_status(&mut tx, id, "stale").await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(worker::process_events(&st).await.unwrap(), 1);
    let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(jobs, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn cleanup_removes_only_old_reports(pool: PgPool) {
    let st = state(pool.clone(), &[]);
    let id = add_host(&pool, "web1", TOKEN).await;
    for days in [200, 181, 179, 1] {
        sqlx::query("INSERT INTO reports (host_id, received_at, status, raw) VALUES ($1, now() - make_interval(days => $2), 'ok', '{}')")
            .bind(id).bind(days).execute(&pool).await.unwrap();
    }
    worker::cleanup(&st).await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM reports")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn job_queue_dedupes_retries_with_backoff_and_gives_up(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        jobs::enqueue(&mut conn, "cleanup", json!({}), Utc::now(), Some("k1"))
            .await
            .unwrap()
    );
    assert!(
        !jobs::enqueue(&mut conn, "cleanup", json!({}), Utc::now(), Some("k1"))
            .await
            .unwrap()
    );
    drop(conn);

    // Ein Job kann nur einmal gleichzeitig geclaimt werden.
    let j = jobs::claim(&pool).await.unwrap().unwrap();
    assert_eq!(j.attempts, 1);
    assert!(jobs::claim(&pool).await.unwrap().is_none());

    // Fehlschlag: Job wird in die Zukunft verschoben.
    jobs::fail(&pool, &j, "boom").await.unwrap();
    assert!(jobs::claim(&pool).await.unwrap().is_none());
    let (done, err): (Option<chrono::DateTime<Utc>>, Option<String>) =
        sqlx::query_as("SELECT done_at, last_error FROM jobs WHERE id = $1")
            .bind(j.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(done.is_none());
    assert_eq!(err.as_deref(), Some("boom"));

    // Nach MAX_ATTEMPTS wird aufgegeben.
    let mut last = jobs::Job {
        id: j.id,
        kind: j.kind,
        payload: j.payload,
        attempts: jobs::MAX_ATTEMPTS,
    };
    last.attempts = jobs::MAX_ATTEMPTS;
    jobs::fail(&pool, &last, "endgültig").await.unwrap();
    let done: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT done_at FROM jobs WHERE id = $1")
            .bind(j.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(done.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn health_endpoints(pool: PgPool) {
    let app = router(state(pool, &[]));
    assert_eq!(
        call(&app, Method::GET, "/healthz", &[], None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, Method::GET, "/readyz", &[], None).await.status,
        StatusCode::OK
    );
}

/// Regression: bei sehr vielen Zeilen müssen die dringlichsten zuerst kommen und dürfen nie abgeschnitten werden.
#[sqlx::test(migrations = "./migrations")]
async fn host_cves_are_ordered_by_severity_before_limit(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    let (session, _) = login(&app, &pool).await;
    let cookie = [("cookie", session.as_str())];
    // 300 harmlosere Zeilen mit hohen IDs, eine verwundbare mit der niedrigsten ID.
    sqlx::query(
        "INSERT INTO cves (id) SELECT 'CVE-2026-' || (10000 + n) FROM generate_series(1, 300) n",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cves (id) VALUES ('CVE-2001-0001')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO host_cve_status (host_id, cve_id, status, reason) SELECT $1, 'CVE-2026-' || (10000 + n), 'fix_pending', 'x' FROM generate_series(1, 300) n")
        .bind(id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO host_cve_status (host_id, cve_id, status, reason) VALUES ($1, 'CVE-2001-0001', 'vulnerable', 'x')")
        .bind(id).execute(&pool).await.unwrap();

    let r = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{id}/cves?limit=5"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let list = r.json["items"].as_array().unwrap();
    assert_eq!(list.len(), 5);
    assert_eq!(r.json["total"], 301);
    assert_eq!(
        list[0]["cve_id"], "CVE-2001-0001",
        "verwundbare CVE muss trotz niedriger ID zuerst kommen"
    );
    assert_eq!(list[0]["status"], "vulnerable");
    // Standard-Limit begrenzt, ungültige Werte werden geklemmt.
    let r = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{id}/cves"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(
        r.json["items"].as_array().unwrap().len(),
        100,
        "Standardseite"
    );
    assert_eq!(r.json["total"], 301);
    let r = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{id}/cves?limit=0"),
        &cookie,
        None,
    )
    .await;
    assert_eq!(r.json["items"].as_array().unwrap().len(), 1);
}

async fn checkin(app: &Router, token: &str) -> Resp {
    let auth = bearer(token);
    call(
        app,
        Method::POST,
        "/api/v1/agent/checkin",
        &[("authorization", &auth)],
        None,
    )
    .await
}

#[sqlx::test(migrations = "./migrations")]
async fn checkin_without_request_does_nothing(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;

    let r = checkin(&app, TOKEN).await;
    assert_eq!(r.status, StatusCode::OK);
    // Die Antwort enthält ausschließlich dieses eine Feld: keine Befehle, keine Pfade.
    assert_eq!(r.json, json!({ "report_requested": false }));
    let (seen, reports): (Option<chrono::DateTime<Utc>>, i64) = sqlx::query_as(
        "SELECT last_checkin_at, (SELECT count(*) FROM reports WHERE host_id = $1) FROM hosts WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(seen.is_some(), "Check-in aktualisiert last_checkin_at");
    assert_eq!(reports, 0, "Check-in erzeugt keinen Report");
    // last_report_at bleibt unberührt (Check-in kaschiert keine veralteten Daten).
    let last_report: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_report_at FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(last_report.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn checkin_rejects_bad_or_missing_token(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    add_host(&pool, "web1", TOKEN).await;
    assert_eq!(
        checkin(&app, "pw_falsches-token").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, Method::POST, "/api/v1/agent/checkin", &[], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    // Auch das Admin-Cookie ersetzt kein Host-Token.
    let (session, _) = login(&app, &pool).await;
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/agent/checkin",
            &[("cookie", session.as_str())],
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    let seen: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_checkin_at FROM hosts WHERE name = 'web1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(seen.is_none(), "abgelehnter Check-in ändert nichts");
}

#[sqlx::test(migrations = "./migrations")]
async fn requested_report_is_dispatched_exactly_once(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let uri = format!("/api/v1/hosts/{id}/request-report");

    // Ohne CSRF-Token und ohne Login nicht erlaubt.
    assert_eq!(
        call(
            &app,
            Method::POST,
            &uri,
            &[("cookie", session.as_str())],
            None
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, Method::POST, &uri, &[], None).await.status,
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        call(&app, Method::POST, &uri, &admin, None).await.status,
        StatusCode::OK
    );
    // Rate-Limit: eine Anfrage je Host und Minute.
    let again = call(&app, Method::POST, &uri, &admin, None).await;
    assert_eq!(again.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(again.headers.contains_key(header::RETRY_AFTER));

    // Erster Check-in: ja, zweiter: nein (genau ein Report je Anfrage).
    assert_eq!(checkin(&app, TOKEN).await.json["report_requested"], true);
    assert_eq!(checkin(&app, TOKEN).await.json["report_requested"], false);

    // Der Report löscht die offene Anfrage; es gibt genau einen Report.
    let auth = bearer(TOKEN);
    let r = call(
        &app,
        Method::POST,
        "/api/v1/report",
        &[("authorization", &auth)],
        Some(report("web1", "6.8.0-31.31", "6.8.0-31.31", 0, 0)),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let (reports, pending, agent): (i64, Option<chrono::DateTime<Utc>>, Option<String>) =
        sqlx::query_as(
            "SELECT (SELECT count(*) FROM reports WHERE host_id = $1), report_requested_at, agent_version \
             FROM hosts WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reports, 1);
    assert!(pending.is_none());
    assert_eq!(agent.as_deref(), Some("0.1.0"));
    assert_eq!(checkin(&app, TOKEN).await.json["report_requested"], false);

    // Unbekannter Host: 404.
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/hosts/999999/request-report",
            &admin,
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn lost_request_is_retried_after_ten_minutes(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    sqlx::query("UPDATE hosts SET report_requested_at = now() WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(checkin(&app, TOKEN).await.json["report_requested"], true);
    assert_eq!(checkin(&app, TOKEN).await.json["report_requested"], false);
    // Der Agent hat "ja" gehört, aber nie einen Report geschickt.
    sqlx::query(
        "UPDATE hosts SET report_dispatched_at = now() - interval '11 minutes' WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(checkin(&app, TOKEN).await.json["report_requested"], true);
}

#[sqlx::test(migrations = "./migrations")]
async fn request_all_skips_hosts_in_cooldown(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    add_host(&pool, "a", "pw_token-a-0123456789abcdef-0123456789").await;
    let b = add_host(&pool, "b", "pw_token-b-0123456789abcdef-0123456789").await;
    add_host(&pool, "c", "pw_token-c-0123456789abcdef-0123456789").await;
    let (session, csrf) = login(&app, &pool).await;
    let admin = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];

    // Host b wurde gerade erst angefragt.
    let one = format!("/api/v1/hosts/{b}/request-report");
    assert_eq!(
        call(&app, Method::POST, &one, &admin, None).await.status,
        StatusCode::OK
    );
    let r = call(
        &app,
        Method::POST,
        "/api/v1/hosts/request-report",
        &admin,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json, json!({ "requested": 2, "skipped": 1 }));
    // Direkt danach sind alle im Cooldown.
    let r = call(
        &app,
        Method::POST,
        "/api/v1/hosts/request-report",
        &admin,
        None,
    )
    .await;
    assert_eq!(r.json, json!({ "requested": 0, "skipped": 3 }));
}

#[sqlx::test(migrations = "./migrations")]
async fn pending_update_list_is_stored_served_and_kept_out_of_history(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    let (session, _) = login(&app, &pool).await;
    let cookie = [("cookie", session.as_str())];
    let auth = bearer(TOKEN);
    let h = [("authorization", auth.as_str())];
    let url = format!("/api/v1/hosts/{id}/updates");

    // Älterer Agent ohne Liste: null.
    let old = report("web1", "6.8.0-31.31", "6.8.0-31.31", 0, 1);
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(old))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, Method::GET, &url, &cookie, None).await.json["items"],
        Value::Null
    );

    let mut r = report("web1", "6.8.0-31.31", "6.8.0-31.31", 1, 1);
    r["updates"]["items"] = json!([{"name": "libc6", "from": "2.35-1", "to": "2.35-2",
        "origin": "Ubuntu:22.04/jammy-security", "security": true}]);
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(r))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let got = call(&app, Method::GET, &url, &cookie, None).await;
    assert_eq!(got.json["items"][0]["name"], "libc6");
    assert_eq!(got.json["items"][0]["security"], true);
    let in_history: i64 =
        sqlx::query_scalar("SELECT count(*) FROM reports WHERE raw->'updates' ? 'items'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(in_history, 0);

    // Ungültige Paketnamen werden abgelehnt.
    let mut bad = report("web1", "6.8.0-31.31", "6.8.0-31.31", 0, 1);
    bad["updates"]["items"] = json!([{"name": "x; rm -rf", "from": null, "to": "1",
        "origin": "o", "security": false}]);
    assert_eq!(
        call(&app, Method::POST, "/api/v1/report", &h, Some(bad))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn cve_list_sorts_by_latest_by_default_and_by_level(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let (session, _) = login(&app, &pool).await;
    let cookie = [("cookie", session.as_str())];
    sqlx::query(
        "INSERT INTO cves (id, priority, published_at) VALUES \
        ('CVE-2026-0001', 'critical', '2026-01-01'), ('CVE-2026-0002', 'low', '2026-03-01'), \
        ('CVE-2026-0003', 'high', '2026-02-01')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let ids = |r: &Resp| -> Vec<String> {
        r.json
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let latest = call(
        &app,
        Method::GET,
        "/api/v1/cves?releases=all&affects=all&sort=latest",
        &cookie,
        None,
    )
    .await;
    assert_eq!(
        ids(&latest),
        ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"]
    );
    let level = call(
        &app,
        Method::GET,
        "/api/v1/cves?releases=all&affects=all&sort=level",
        &cookie,
        None,
    )
    .await;
    assert_eq!(
        ids(&level),
        ["CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0002"]
    );
    assert_eq!(level.json[0]["level"], 10);
    let oldest = call(
        &app,
        Method::GET,
        "/api/v1/cves?releases=all&affects=all&sort=latest&dir=asc",
        &cookie,
        None,
    )
    .await;
    assert_eq!(
        ids(&oldest),
        ["CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0002"]
    );
    assert_eq!(
        call(&app, Method::GET, "/api/v1/cves?sort=x", &cookie, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn long_poll_checkin_answers_as_soon_as_a_report_is_requested(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let id = add_host(&pool, "web1", TOKEN).await;
    let auth = bearer(TOKEN);
    let started = std::time::Instant::now();
    let headers = [("authorization", auth.as_str())];
    let poll = call(
        &app,
        Method::POST,
        "/api/v1/agent/checkin?wait=20",
        &headers,
        None,
    );
    let request = async {
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        sqlx::query("UPDATE hosts SET report_requested_at = now(), report_dispatched_at = NULL WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    };
    let (resp, ()) = tokio::join!(poll, request);
    assert_eq!(resp.json["report_requested"], true);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(8),
        "Antwort kam erst nach {:?}",
        started.elapsed()
    );

    // Ohne Anforderung endet der Long-Poll nach der Wartezeit mit „nein“.
    let t = std::time::Instant::now();
    let none = call(
        &app,
        Method::POST,
        "/api/v1/agent/checkin?wait=1",
        &[("authorization", &auth)],
        None,
    )
    .await;
    assert_eq!(none.json["report_requested"], false);
    assert!(t.elapsed() >= std::time::Duration::from_millis(900));
}

/// NUL (\u0000) in JSON-Textfeldern kann Postgres (text und jsonb) nicht speichern: das muss 400 ergeben, nie 500.
#[sqlx::test(migrations = "./migrations")]
async fn nul_in_login_username_is_400_and_still_rate_limited(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    admin::upsert_admin(&pool, "admin", PASSWORD).await.unwrap();
    let try_login = |name: &'static str| {
        let app = app.clone();
        async move {
            call(
                &app,
                Method::POST,
                "/api/v1/auth/login",
                &[],
                Some(json!({"username": name, "password": PASSWORD})),
            )
            .await
        }
    };
    // Gleiche Antwort für existierenden und nicht existierenden Namen.
    let a = try_login("ad\u{0}min").await;
    let b = try_login("gibt-es-nicht\u{0}").await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST);
    assert_eq!(b.status, StatusCode::BAD_REQUEST);
    // Versuche mit NUL zählen gegen das Rate-Limit je IP (8 weitere: insgesamt 10 erlaubt).
    let mut last = StatusCode::OK;
    for _ in 0..12 {
        last = try_login("ad\u{0}min").await.status;
        if last == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        assert_eq!(last, StatusCode::BAD_REQUEST);
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[sqlx::test(migrations = "./migrations")]
async fn nul_in_watchlist_note_is_400(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let (session, csrf) = login(&app, &pool).await;
    let h = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/watchlist/CVE-2024-1234",
        &h,
        Some(json!({"note": "a\u{0}b"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "Watchlist-Notiz");
}

#[sqlx::test(migrations = "./migrations")]
async fn nul_in_feed_interval_key_is_400(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let (session, csrf) = login(&app, &pool).await;
    let h = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/settings",
        &h,
        Some(json!({"feed_intervals": {"x\u{0}y": 60}})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "feed_intervals");
}

#[sqlx::test(migrations = "./migrations")]
async fn nul_in_oidc_settings_is_400(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let (session, csrf) = login(&app, &pool).await;
    let h = [
        ("cookie", session.as_str()),
        ("x-csrf-token", csrf.as_str()),
    ];
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/settings/oidc",
        &h,
        Some(json!({"enabled": false, "issuer": "https://i.example\u{0}", "client_id": "c", "redirect_url": "https://r.example/cb"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "OIDC");
}

/// Unbekannte Felder landen in `reports.raw` (jsonb): NUL darin ergab einen Datenbankfehler (500). Muss 400 sein, und es
/// darf nichts gespeichert werden. Vom Fuzz-Skript nicht erreichbar (braucht ein gültiges Host-Token).
#[sqlx::test(migrations = "./migrations")]
async fn nul_and_oversize_unknown_report_fields_are_400(pool: PgPool) {
    let app = router(state(pool.clone(), &[]));
    let host = add_host(&pool, "nul-host", TOKEN).await;
    let auth = bearer(TOKEN);
    let h = [("authorization", auth.as_str())];
    for (name, mutate) in [
        ("Zusatzfeld", json!({"x": "a\u{0}b"})),
        ("verschachtelt", json!({"x": {"y": ["a\u{0}"]}})),
        ("Schlüssel", json!({"k\u{0}": 1})),
    ] {
        let mut rep = report("nul-host", "6.8.0-31.31", "6.8.0-35.35", 0, 0);
        for (k, v) in mutate.as_object().unwrap() {
            rep[k] = v.clone();
        }
        let r = call(&app, Method::POST, "/api/v1/report", &h, Some(rep)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{name}");
    }
    // Beliebig große Zusatzfelder (hier 100 KB; das Body-Limit liegt bei 4 MiB) werden nicht in die Historie geschrieben.
    let mut big = report("nul-host", "6.8.0-31.31", "6.8.0-35.35", 0, 0);
    big["x"] = json!("y".repeat(100_000));
    let r = call(&app, Method::POST, "/api/v1/report", &h, Some(big)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "großes Zusatzfeld");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM reports WHERE host_id = $1")
        .bind(host)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "abgelehnte Reports werden nicht gespeichert");
}

/// Datenbank nicht erreichbar (Pool gegen einen geschlossenen Port): 503 mit deutschem Text, `Retry-After` und
/// eigenem Code statt 500 "interner Fehler"; nie interne Details. Gilt auch für die Anmeldeprüfung und den Login.
#[tokio::test]
async fn database_outage_is_503_without_details() {
    // Port 1 auf Loopback: Verbindungsaufbau scheitert sofort, der Pool gibt nach `acquire_timeout` auf.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(300))
        .connect_lazy("postgres://patchwatch:x@127.0.0.1:1/patchwatch")
        .unwrap();
    let app = router(state(pool, &[]));
    let session = "pw_session=abcdef0123456789";
    for (method, uri, headers, body) in [
        (
            Method::GET,
            "/api/v1/hosts",
            vec![("cookie", session)],
            None,
        ),
        (
            Method::GET,
            "/api/v1/auth/me",
            vec![("cookie", session)],
            None,
        ),
        (
            Method::POST,
            "/api/v1/auth/login",
            vec![],
            Some(json!({"username": "admin", "password": PASSWORD})),
        ),
    ] {
        let r = call(&app, method, uri, &headers, body).await;
        assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert_eq!(r.json["code"], "db_unavailable", "{uri}");
        let msg = r.json["error"].as_str().unwrap();
        assert!(msg.contains("Datenbank"), "{uri}: {msg}");
        let lower = msg.to_lowercase();
        for internal in ["sqlx", "pool", "postgres", "127.0.0.1", "timed out"] {
            assert!(!lower.contains(internal), "{uri}: interne Details: {msg}");
        }
        assert!(
            r.headers
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|s| s > 0),
            "{uri}: Retry-After fehlt"
        );
    }
}

