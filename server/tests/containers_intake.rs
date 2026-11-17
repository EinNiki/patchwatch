//! Docker-Block im Report: Annahme, Validierung, Speicherung, Migration 0028 (Wegwerf-Datenbank).
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::{router, security, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const TOKEN: &str = "pw_test-token-nur-fuer-tests-0123456789abcdef";
const DIG_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIG_B: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn state(pool: PgPool) -> AppState {
    AppState::new(pool, Config::from_sources(None, &|_| None).unwrap()).unwrap()
}

async fn add_host(pool: &PgPool) -> i64 {
    sqlx::query_scalar("INSERT INTO hosts (name, token_hash) VALUES ('web1', $1) RETURNING id")
        .bind(security::sha256(TOKEN))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn send(app: &Router, docker: Option<Value>) -> (StatusCode, Value) {
    let mut body = json!({
        "schema_version": 2, "agent_version": "0.3.0", "hostname": "web1", "collected_at_unix": 1,
        "os": {"id": "debian", "version_id": "13", "codename": "trixie", "pretty_name": "Debian 13"},
        "kernel": {"running_release": "6.12.0-1-amd64", "running_package": null, "newest_installed_release": null,
                   "newest_installed_package": null, "reboot_needed_kernel": null},
        "reboot_required_file": false, "updates": null, "uptime_seconds": 10, "proxmox": null
    });
    if let Some(d) = docker {
        body["docker"] = d;
    }
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/report")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn ctr(id: &str, name: &str) -> Value {
    json!({"id": id, "name": name, "state": "running", "created_unix": 1_731_500_000, "status_text": "Up 3 hours (healthy)",
           "image": "nginx:1.27", "image_id": DIG_A, "repo_digests": [format!("nginx@{DIG_B}")],
           "os": "linux", "arch": "arm64", "variant": "v8", "compose_project": "shop", "compose_service": "web"})
}

fn ok(containers: Vec<Value>) -> Value {
    json!({"state": "ok", "reason": null, "containers": containers})
}

#[sqlx::test(migrations = "./migrations")]
async fn docker_block_is_stored_in_its_own_tables_and_not_in_the_history(pool: PgPool) {
    let app = router(state(pool.clone()));
    let id = add_host(&pool).await;
    let (st, _) = send(
        &app,
        Some(ok(vec![
            ctr("b3f1c2d4e5f6", "web"),
            ctr("c4a2d3e5f607", "db"),
        ])),
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (state_, reason, checked): (Option<String>, Option<String>, bool) =
        sqlx::query_as("SELECT docker_state, docker_reason, docker_checked_at IS NOT NULL FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (state_.as_deref(), reason, checked),
        (Some("ok"), None, true)
    );
    let row: (String, String, Vec<String>, Option<String>, Option<String>, bool) = sqlx::query_as(
        "SELECT image_ref, state, repo_digests, arch, compose_service, created_at IS NOT NULL FROM host_containers \
         WHERE host_id = $1 AND name = 'web'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            "nginx:1.27".into(),
            "running".into(),
            vec![format!("nginx@{DIG_B}")],
            Some("arm64".into()),
            Some("web".into()),
            true
        )
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM reports WHERE raw ? 'docker'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "der Docker-Block gehört nicht in reports.raw");
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_containers_are_kept_unavailable_keeps_the_list_and_no_block_means_off(
    pool: PgPool,
) {
    let app = router(state(pool.clone()));
    let id = add_host(&pool).await;
    send(
        &app,
        Some(ok(vec![
            ctr("b3f1c2d4e5f6", "web"),
            ctr("c4a2d3e5f607", "db"),
        ])),
    )
    .await;
    let first: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT first_seen FROM host_containers WHERE container_id = 'b3f1c2d4e5f6'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    // Zweite Meldung ohne den Container `db`: nichts wird gelöscht, die erste Sichtung von `web` bleibt.
    send(&app, Some(ok(vec![ctr("b3f1c2d4e5f6", "web")]))).await;
    let rows: Vec<(
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT name, first_seen, last_seen FROM host_containers WHERE host_id = $1 ORDER BY name",
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].1, first);
    assert!(rows[1].2 > rows[0].2, "`db` wurde nicht erneut gesehen");

    // Docker nicht erreichbar: Zustand und Grund werden gespeichert, die Liste bleibt.
    send(
        &app,
        Some(json!({"state": "unavailable", "reason": "no_permission", "containers": []})),
    )
    .await;
    let (s, r): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT docker_state, docker_reason FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (s.as_deref(), r.as_deref()),
        (Some("unavailable"), Some("no_permission"))
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM host_containers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 2);

    // Kein Block (Docker aus): Zustand leer, Zeilen bleiben liegen.
    send(&app, None).await;
    let s: Option<String> = sqlx::query_scalar("SELECT docker_state FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(s, None);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM host_containers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_docker_fields_are_rejected_and_foreign_fields_never_stored(pool: PgPool) {
    let app = router(state(pool.clone()));
    add_host(&pool).await;
    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = ctr("b3f1c2d4e5f6", "web");
        f(&mut c);
        ok(vec![c])
    };
    let cases: Vec<(&str, Value)> = vec![
        ("id zu kurz", with(&|c| c["id"] = json!("abc"))),
        ("id nicht hex", with(&|c| c["id"] = json!("zzzzzzzzzzzz"))),
        ("name mit Pfad", with(&|c| c["name"] = json!("../etc"))),
        ("name mit Leerzeichen", with(&|c| c["name"] = json!("a b"))),
        ("state erfunden", with(&|c| c["state"] = json!("<script>"))),
        (
            "status mit Zeilenumbruch",
            with(&|c| c["status_text"] = json!("Up\nERROR")),
        ),
        (
            "status zu lang",
            with(&|c| c["status_text"] = json!("x".repeat(65))),
        ),
        (
            "image mit Leerzeichen",
            with(&|c| c["image"] = json!("evil image")),
        ),
        (
            "image_id kein Digest",
            with(&|c| c["image_id"] = json!("sha256:zz")),
        ),
        (
            "repo_digests ohne @",
            with(&|c| c["repo_digests"] = json!(["nginx"])),
        ),
        (
            "zu viele digests",
            with(&|c| {
                c["repo_digests"] =
                    json!((0..9).map(|_| format!("nginx@{DIG_B}")).collect::<Vec<_>>())
            }),
        ),
        (
            "compose_service mit Semikolon",
            with(&|c| c["compose_service"] = json!("web;rm")),
        ),
        (
            "compose_project zu lang",
            with(&|c| c["compose_project"] = json!("a".repeat(65))),
        ),
        ("os mit Leerzeichen", with(&|c| c["os"] = json!("li nux"))),
        (
            "Zeitpunkt unsinnig",
            with(&|c| c["created_unix"] = json!(99_999_999_999u64)),
        ),
        (
            "state unbekannt",
            json!({"state": "great", "reason": null, "containers": []}),
        ),
        (
            "unavailable ohne Grund",
            json!({"state": "unavailable", "reason": null, "containers": []}),
        ),
        (
            "unavailable mit freiem Grund",
            json!({"state": "unavailable", "reason": "weil ich will", "containers": []}),
        ),
        (
            "ok mit Grund",
            json!({"state": "ok", "reason": "timeout", "containers": []}),
        ),
    ];
    for (name, body) in cases {
        let (st, _) = send(&app, Some(body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{name}");
    }
    // 501 Container sind zu viel.
    let many: Vec<Value> = (0..501)
        .map(|i| ctr(&format!("{i:012x}"), &format!("c{i}")))
        .collect();
    assert_eq!(send(&app, Some(ok(many))).await.0, StatusCode::BAD_REQUEST);
    // Genau 500 gehen.
    let max: Vec<Value> = (0..500)
        .map(|i| ctr(&format!("{i:012x}"), &format!("c{i}")))
        .collect();
    assert_eq!(send(&app, Some(ok(max))).await.0, StatusCode::NO_CONTENT);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM host_containers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 500);

    // Fremde Felder werden nicht gespeichert und kommen nirgends an (auch nicht in die Historie).
    let mut c = ctr("aaaaaaaaaaaa", "extra");
    c["env"] = json!(["PASSWORT=GEHEIM"]);
    c["labels"] = json!({"x": "GEHEIM"});
    assert_eq!(
        send(&app, Some(ok(vec![c]))).await.0,
        StatusCode::NO_CONTENT
    );
    let leaked: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM host_containers WHERE host_containers::text LIKE '%GEHEIM%') + \
                (SELECT count(*) FROM reports WHERE raw::text LIKE '%GEHEIM%')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leaked, 0);
}

/// Die Migration ändert nichts Bestehendes: Zeilen aus dem Stand vor 0028 bleiben, neue Spalten sind leer.
#[sqlx::test(migrations = false)]
async fn migration_0028_keeps_existing_rows(pool: PgPool) {
    let all = sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .unwrap();
    let mut before = sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .unwrap();
    before.migrations = std::borrow::Cow::Owned(
        all.migrations
            .iter()
            .filter(|m| m.version <= 27)
            .cloned()
            .collect(),
    );
    before.run(&pool).await.unwrap();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO hosts (name, token_hash, updates_pending) VALUES ('alt', 'h', 3) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    all.run(&pool).await.unwrap();
    let (name, pending, state_, checked): (
        String,
        Option<i32>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "SELECT name, updates_pending, docker_state, docker_checked_at FROM hosts WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (name.as_str(), pending, state_, checked),
        ("alt", Some(3), None, None)
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM host_containers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
