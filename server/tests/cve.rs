//! Integrationstests des CVE-Moduls: echte Adapter gegen einen lokalen Mock-Feed-Server,
//! Fixtures stammen aus echten Antworten (siehe tests/fixtures).

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::cve::refresh::{self, Outcome};
use patchwatch_server::{admin, security, worker, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const TOKEN: &str = "pw_cve-test-token-0123456789abcdef0123456789";
const PASSWORD: &str = "ein-langes-test-passwort";

// ---------- Mock-Feeds ----------

#[derive(Default)]
struct Mock {
    ubuntu: Vec<Value>,
    ubuntu_single: HashMap<String, Value>,
    ubuntu_status: Option<u16>,
    ubuntu_garbage: bool,
    debian_body: String,
    debian_status: Option<u16>,
    osv_body: Value,
    log: Vec<String>,
}

type Shared = Arc<Mutex<Mock>>;

async fn ubuntu_list(
    State(m): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut m = m.lock().unwrap();
    let (offset, limit) = (
        q["offset"].parse::<usize>().unwrap(),
        q["limit"].parse::<usize>().unwrap(),
    );
    // Nur geprüfte Parameter dürfen vorkommen (die echte API antwortet bei anderen mit 422).
    for k in q.keys() {
        assert!(
            ["package", "limit", "offset", "order", "sort_by"].contains(&k.as_str()),
            "unbekannter Parameter {k}"
        );
    }
    m.log.push(format!("ubuntu offset={offset}"));
    if let Some(code) = m.ubuntu_status {
        return StatusCode::from_u16(code).unwrap().into_response();
    }
    if m.ubuntu_garbage {
        return Json(json!({"unexpected": true})).into_response();
    }
    let page: Vec<Value> = m.ubuntu.iter().skip(offset).take(limit).cloned().collect();
    Json(json!({"cves": page, "offset": offset, "limit": limit, "total_results": m.ubuntu.len()}))
        .into_response()
}

async fn ubuntu_one(State(m): State<Shared>, Path(id): Path<String>) -> Response {
    let mut m = m.lock().unwrap();
    let id = id.trim_end_matches(".json").to_owned();
    m.log.push(format!("ubuntu single {id}"));
    match m.ubuntu_single.get(&id) {
        Some(v) => Json(v.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

const DEBIAN_LM: &str = "Fri, 30 Oct 2026 21:23:06 GMT";

async fn debian(State(m): State<Shared>, headers: HeaderMap) -> Response {
    let mut m = m.lock().unwrap();
    let ims = headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    m.log
        .push(format!("debian ims={}", ims.as_deref().unwrap_or("-")));
    if let Some(code) = m.debian_status {
        return StatusCode::from_u16(code).unwrap().into_response();
    }
    if ims.as_deref() == Some(DEBIAN_LM) {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    (
        [
            (header::LAST_MODIFIED, DEBIAN_LM),
            (header::CONTENT_TYPE, "application/json"),
        ],
        m.debian_body.clone(),
    )
        .into_response()
}

async fn osv(State(m): State<Shared>, Json(body): Json<Value>) -> Response {
    let mut m = m.lock().unwrap();
    m.log.push(format!(
        "osv {} {} page={}",
        body["package"]["ecosystem"],
        body["version"],
        body.get("page_token").is_some()
    ));
    if body.get("page_token").is_some() {
        return Json(json!({"vulns": []})).into_response();
    }
    Json(m.osv_body.clone()).into_response()
}

async fn start_mock(mock: Shared) -> String {
    let app = Router::new()
        .route("/security/cves.json", get(ubuntu_list))
        .route("/security/cves/{id}", get(ubuntu_one))
        .route("/tracker/data/json", get(debian))
        .route("/v1/query", post(osv))
        .with_state(mock);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn ubuntu_cve(id: &str, updated: chrono::DateTime<Utc>, statuses: &[(&str, &str, &str)]) -> Value {
    let st: Vec<Value> = statuses
        .iter()
        .map(|(rel, status, desc)| json!({"release_codename": rel, "status": status, "description": desc, "component": null, "pocket": "security"}))
        .collect();
    json!({
        "id": id, "description": format!("Testbeschreibung {id}"), "priority": "high",
        "published": "2026-09-25T00:00:00", "updated_at": updated.to_rfc3339(),
        "packages": [
            {"name": "linux", "statuses": st},
            {"name": "openssl", "statuses": [{"release_codename": "noble", "status": "needed", "description": ""}]}
        ]
    })
}

fn load_fixture_cve(single: &str, id_override: Option<&str>) -> Value {
    let mut v: Value = serde_json::from_str(single).unwrap();
    if let Some(id) = id_override {
        v["id"] = json!(id);
    }
    v
}

// ---------- Helfer ----------

async fn setup(pool: PgPool, sources: &[&str], extra_toml: &str, base: &str) -> AppState {
    let list = sources
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(",");
    let toml = format!(
        "[cve]\nsources = [{list}]\nubuntu_url = \"{base}\"\ndebian_url = \"{base}/tracker/data/json\"\nosv_url = \"{base}\"\n\
         retries = 1\nretry_base_delay_ms = 10\nrequest_timeout_secs = 10\n{extra_toml}\n\
         [ntfy]\nurl = \"http://127.0.0.1:9\"\ntopic = \"t\"\n"
    );
    let cfg = Config::from_sources(Some(&toml), &|_| None).unwrap();
    AppState::new(pool, cfg).unwrap()
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
    Resp {
        status: parts.status,
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

async fn add_host(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO hosts (name, token_hash) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(security::sha256(&format!("{TOKEN}-{name}")))
        .fetch_one(pool)
        .await
        .unwrap()
}

struct K<'a> {
    host: &'a str,
    os_id: &'a str,
    os_version: &'a str,
    codename: &'a str,
    release: &'a str,
    package: &'a str,
    source: &'a str,
    version: &'a str,
    newest_release: &'a str,
    newest_version: &'a str,
    proxmox: bool,
}

async fn report(app: &Router, k: &K<'_>) -> StatusCode {
    let body = json!({
        "schema_version": 1, "agent_version": "0.1.0", "hostname": k.host, "collected_at_unix": 1,
        "os": {"id": k.os_id, "version_id": k.os_version, "codename": k.codename, "pretty_name": "Test OS"},
        "kernel": {
            "running_release": k.release,
            "running_package": {"name": k.package, "version": k.version, "source": k.source, "source_version": k.version},
            "newest_installed_release": k.newest_release,
            "newest_installed_package": {"name": k.package, "version": k.newest_version, "source": k.source, "source_version": k.newest_version},
            "reboot_needed_kernel": k.version != k.newest_version
        },
        "reboot_required_file": false, "updates": {"pending": 0, "security": 0}, "uptime_seconds": 10,
        "proxmox": if k.proxmox { json!({"version": "9.0.3"}) } else { Value::Null }, "packages": null
    });
    let auth = format!("Bearer {TOKEN}-{}", k.host);
    call(
        app,
        Method::POST,
        "/api/v1/report",
        &[("authorization", &auth)],
        Some(body),
    )
    .await
    .status
}

fn noble<'a>(host: &'a str, version: &'a str, newest: &'a str) -> K<'a> {
    K {
        host,
        os_id: "ubuntu",
        os_version: "24.04",
        codename: "noble",
        release: "6.8.0-31-generic",
        package: "linux-image-6.8.0-31-generic",
        source: "linux-signed",
        version,
        newest_release: "6.8.0-35-generic",
        newest_version: newest,
        proxmox: false,
    }
}

async fn host_status(pool: &PgPool, id: i64) -> String {
    sqlx::query_scalar("SELECT status FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn cve_status(pool: &PgPool, id: i64, cve: &str) -> Option<String> {
    sqlx::query_scalar("SELECT status FROM host_cve_status WHERE host_id = $1 AND cve_id = $2")
        .bind(id)
        .bind(cve)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

async fn login(app: &Router, pool: &PgPool) -> Vec<(String, String)> {
    admin::upsert_admin(pool, "admin", PASSWORD).await.unwrap();
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"username": "admin", "password": PASSWORD}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = r
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let v: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    vec![
        ("cookie".to_owned(), cookie),
        (
            "x-csrf-token".to_owned(),
            v["csrf_token"].as_str().unwrap().to_owned(),
        ),
    ]
}

fn hdr(h: &[(String, String)]) -> Vec<(&str, &str)> {
    h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

// ---------- Tests ----------

/// Kernstest: Feed liefert Änderung -> Event -> Host-Status ändert sich (-> Benachrichtigung).
#[sqlx::test(migrations = "./migrations")]
async fn feed_change_leads_to_event_and_host_status_change(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "web1").await;
    // Ubuntu 24.04: läuft 6.8.0-31.31, installiert ist bereits 6.8.0-35.35.
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-35.35")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(host_status(&pool, hid).await, "reboot_required");

    // 1. Feed: CVE ist für noble offen (needed) -> verwundbar.
    let now = Utc::now();
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-10001",
        now - Duration::minutes(10),
        &[("noble", "needed", ""), ("jammy", "needed", "")],
    )];
    let out = refresh::refresh_all(&st).await;
    assert_eq!(
        out[0].1,
        Outcome::Updated {
            changed_rows: 2,
            events: 0
        },
        "Erstimport erzeugt keine Event-Flut"
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");
    // Nur Kernel-Pakete werden gespeichert, nicht openssl.
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE package <> 'linux'"
        )
        .await,
        0
    );

    // 2. Feed meldet für noble jetzt "released 6.8.0-35.35": Änderung vulnerable -> fixed.
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-10001",
        now,
        &[
            ("noble", "released", "6.8.0-35.35"),
            ("jammy", "needed", ""),
        ],
    )];
    let out = refresh::refresh_all(&st).await;
    assert_eq!(
        out[0].1,
        Outcome::Updated {
            changed_rows: 1,
            events: 1
        }
    );
    let (kind, payload): (String, Value) =
        sqlx::query_as("SELECT kind, payload FROM events WHERE kind = 'cve_status_changed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(kind, "cve_status_changed");
    assert_eq!(payload["changes"][0]["from"], "vulnerable");
    assert_eq!(payload["changes"][0]["to"], "fixed");
    assert_eq!(payload["changes"][0]["fix_version"], "6.8.0-35.35");

    // Host neu bewertet: Fix ist installiert, läuft aber nicht -> "gefixt installiert, Neustart nötig".
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("fixed_installed_reboot_required")
    );
    assert_eq!(host_status(&pool, hid).await, "reboot_required");
    let ev: Value =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind = 'host_cve_status_changed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (ev["from"].as_str(), ev["to"].as_str()),
        (Some("vulnerable"), Some("fixed_installed_reboot_required"))
    );

    // Statuswechsel cve_vulnerable -> reboot_required wurde als Benachrichtigung eingereiht.
    while worker::process_events(&st).await.unwrap() > 0 {}
    let titles: Vec<String> =
        sqlx::query_scalar("SELECT payload->>'title' FROM jobs WHERE kind = 'notify' ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("web1:") && t.contains("verwundbar")),
        "{titles:?}"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.starts_with("web1:") && t.contains("Neustart nötig")),
        "{titles:?}"
    );

    // Host bootet den neuen Kernel: CVE gilt als behoben, Host ist wieder grün.
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-35.35", "6.8.0-35.35")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-10001").await,
        None,
        "behobene CVEs werden nicht gespeichert"
    );
    assert_eq!(host_status(&pool, hid).await, "ok");
}

/// Feed fällt aus oder ändert das Format: alter Stand bleibt, Fehler ist sichtbar, nie stillschweigend grün.
#[sqlx::test(migrations = "./migrations")]
async fn feed_failure_keeps_old_state_and_is_visible(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-10002",
        Utc::now(),
        &[("noble", "needed", "")],
    )];
    refresh::refresh_all(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");
    let success: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT last_success_at FROM feed_state WHERE source = 'ubuntu'")
            .fetch_one(&pool)
            .await
            .unwrap();

    // Server-Fehler (mit Retry): Fehler gespeichert, Daten und Host-Status unverändert.
    mock.lock().unwrap().ubuntu_status = Some(503);
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(&out[0].1, Outcome::Failed(m) if m.contains("503")),
        "{:?}",
        out[0].1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cve_source_status").await,
        1
    );
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");
    let (err, fails, still): (Option<String>, i32, chrono::DateTime<Utc>) =
        sqlx::query_as("SELECT last_error, consecutive_failures, last_success_at FROM feed_state WHERE source = 'ubuntu'").fetch_one(&pool).await.unwrap();
    assert!(err.unwrap().contains("503"));
    assert_eq!(
        (fails, still),
        (1, success),
        "letzter Erfolg bleibt der Stand von vorher"
    );
    // Mit retries=1 ist es genau ein Versuch je Abruf.
    assert_eq!(
        mock.lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| l.starts_with("ubuntu"))
            .count(),
        2
    );

    // Format geändert (kein `cves`-Feld): ebenfalls Fehler statt "leer = alles gut".
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu_status = None;
        m.ubuntu_garbage = true;
    }
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(&out[0].1, Outcome::Failed(m) if m.contains("Format")),
        "{:?}",
        out[0].1
    );
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");

    // UI/API: Quelle ist "veraltet seit" dem letzten Erfolg, nicht "ok".
    let cookies = login(&app, &pool).await;
    let feeds = call(&app, Method::GET, "/api/v1/feeds", &hdr(&cookies), None).await;
    assert_eq!(feeds.status, StatusCode::OK);
    let u = &feeds.json[0];
    assert_eq!(
        (
            u["source"].as_str(),
            u["state"].as_str(),
            u["healthy"].as_bool()
        ),
        (Some("ubuntu"), Some("stale"), Some(false))
    );
    assert!(u["stale_since"].is_string() && u["last_error"].as_str().unwrap().contains("Format"));

    // Nach dem 3. Fehlschlag in Folge genau ein Alarm-Event.
    refresh::refresh_all(&st).await;
    refresh::refresh_all(&st).await;
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM events WHERE kind = 'feed_failing'"
        )
        .await,
        1
    );

    // Erholung: Fehler und Zähler werden zurückgesetzt, Feed wieder "ok".
    mock.lock().unwrap().ubuntu_garbage = false;
    refresh::refresh_all(&st).await;
    let feeds = call(&app, Method::GET, "/api/v1/feeds", &hdr(&cookies), None).await;
    assert_eq!(feeds.json[0]["state"], "ok");
    assert_eq!(feeds.json[0]["consecutive_failures"], 0);
}

/// Ubuntu: Cursor-Paginierung lädt nicht jedes Mal alles; zu großer Rückstand ist ein sichtbarer Fehler.
#[sqlx::test(migrations = "./migrations")]
async fn ubuntu_stops_at_cursor_and_reports_backlog(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(
        pool.clone(),
        &["ubuntu"],
        "ubuntu_backfill_pages = 2\nubuntu_max_pages = 2",
        &base,
    )
    .await;
    let now = Utc::now();
    let make = |n: usize, newest_min_ago: i64| -> Vec<Value> {
        (0..n)
            .map(|i| {
                ubuntu_cve(
                    &format!("CVE-2026-2{:04}", 9000 - i),
                    now - Duration::minutes(newest_min_ago + i as i64),
                    &[("noble", "needed", "")],
                )
            })
            .collect()
    };
    // 45 CVEs, nur die neuesten 2 Seiten (40) werden im Erstabruf geladen.
    mock.lock().unwrap().ubuntu = make(45, 100);
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(
            out[0].1,
            Outcome::Updated {
                changed_rows: 40,
                ..
            }
        ),
        "{:?}",
        out[0].1
    );
    assert_eq!(
        mock.lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| l.starts_with("ubuntu offset"))
            .count(),
        2
    );

    // Unverändert: nur die erste Seite wird angefragt, dann Stopp am Cursor.
    mock.lock().unwrap().log.clear();
    assert_eq!(refresh::refresh_all(&st).await[0].1, Outcome::NotModified);
    assert_eq!(mock.lock().unwrap().log, vec!["ubuntu offset=0"]);

    // 3 neue CVEs: eine Seite genügt, nur die 3 neuen werden verarbeitet.
    {
        let mut m = mock.lock().unwrap();
        let mut new = make(3, 1);
        for (i, c) in new.iter_mut().enumerate() {
            c["id"] = json!(format!("CVE-2026-3{:04}", i));
        }
        new.extend(m.ubuntu.clone());
        m.ubuntu = new;
        m.log.clear();
    }
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(
            out[0].1,
            Outcome::Updated {
                changed_rows: 3,
                events: 3
            }
        ),
        "{:?}",
        out[0].1
    );
    assert_eq!(mock.lock().unwrap().log, vec!["ubuntu offset=0"]);

    // Mehr neue CVEs als max_pages*20: Cursor nicht erreichbar -> Fehler, Cursor bleibt, nichts geht verloren.
    let cursor_before: String =
        sqlx::query_scalar("SELECT cursor FROM feed_state WHERE source = 'ubuntu'")
            .fetch_one(&pool)
            .await
            .unwrap();
    {
        let mut m = mock.lock().unwrap();
        let mut flood = make(45, 0);
        for (i, c) in flood.iter_mut().enumerate() {
            c["id"] = json!(format!("CVE-2026-4{:04}", i));
            c["updated_at"] = json!((now + Duration::minutes(1 + (45 - i) as i64)).to_rfc3339());
        }
        flood.extend(m.ubuntu.clone());
        m.ubuntu = flood;
    }
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(&out[0].1, Outcome::Failed(m) if m.contains("Cursor")),
        "{:?}",
        out[0].1
    );
    let cursor_after: String =
        sqlx::query_scalar("SELECT cursor FROM feed_state WHERE source = 'ubuntu'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cursor_before, cursor_after);
}

/// Watchlist-CVEs außerhalb des neuesten Fensters werden gezielt nachgeladen.
#[sqlx::test(migrations = "./migrations")]
async fn watchlist_cve_is_fetched_individually(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let now = Utc::now();
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = vec![ubuntu_cve(
            "CVE-2026-50001",
            now,
            &[("noble", "needed", "")],
        )];
        // Echte Antwort für CVE-2024-1086 (Einzelabruf).
        m.ubuntu_single.insert(
            "CVE-2024-1086".into(),
            load_fixture_cve(include_str!("fixtures/ubuntu/cve_single_real.json"), None),
        );
    }
    sqlx::query("INSERT INTO cves (id) VALUES ('CVE-2024-1086'), ('CVE-2024-0000')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cve_watchlist (cve_id) VALUES ('CVE-2024-1086'), ('CVE-2024-0000')")
        .execute(&pool)
        .await
        .unwrap();
    refresh::refresh_all(&st).await;
    // CVE-2024-1086 kam per Einzelabruf, die unbekannte CVE-2024-0000 (404) bleibt ohne Daten.
    assert!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE cve_id = 'CVE-2024-1086'"
        )
        .await
            > 0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE cve_id = 'CVE-2024-0000'"
        )
        .await,
        0
    );
    let log = mock.lock().unwrap().log.clone();
    assert!(
        log.contains(&"ubuntu single CVE-2024-1086".to_owned())
            && log.contains(&"ubuntu single CVE-2024-0000".to_owned()),
        "{log:?}"
    );
}

/// Debian trixie: Last-Modified wird genutzt, bei 304 passiert nichts; echte Tracker-Daten.
#[sqlx::test(migrations = "./migrations")]
async fn debian_trixie_uses_if_modified_since(pool: PgPool) {
    let mock: Shared = Arc::default();
    mock.lock().unwrap().debian_body =
        include_str!("fixtures/debian/tracker_subset_real.json").to_owned();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["debian"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "deb1").await;
    let trixie = K {
        host: "deb1",
        os_id: "debian",
        os_version: "13",
        codename: "trixie",
        release: "6.12.48+deb13-amd64",
        package: "linux-image-6.12.48+deb13-amd64",
        source: "linux-signed-amd64",
        version: "6.12.48-1",
        newest_release: "6.12.48+deb13-amd64",
        newest_version: "6.12.48-1",
        proxmox: false,
    };
    assert_eq!(report(&app, &trixie).await, StatusCode::NO_CONTENT);

    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    // CVE-2004-0230 ist in trixie "open" -> verwundbar; CVE-2024-1086 (fixed in 6.6.15-1) ist behoben und nicht gespeichert.
    assert_eq!(
        cve_status(&pool, hid, "CVE-2004-0230").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(cve_status(&pool, hid, "CVE-2024-1086").await, None);
    assert_eq!(
        cve_status(&pool, hid, "CVE-2020-0347").await.as_deref(),
        Some("unknown"),
        "undetermined bleibt UNKNOWN"
    );
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cves WHERE id LIKE 'TEMP-%'").await,
        0
    );
    let lm: Option<String> =
        sqlx::query_scalar("SELECT last_modified FROM feed_state WHERE source = 'debian'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(lm.as_deref(), Some(DEBIAN_LM));

    // Zweiter Abruf: If-Modified-Since -> 304 -> keine Änderung, aber Erfolg wird verbucht.
    let out = refresh::refresh_all(&st).await;
    assert_eq!(out[0].1, Outcome::NotModified);
    assert_eq!(
        mock.lock().unwrap().log.last().unwrap(),
        &format!("debian ims={DEBIAN_LM}")
    );
    let fails: i32 =
        sqlx::query_scalar("SELECT consecutive_failures FROM feed_state WHERE source = 'debian'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(fails, 0);

    // Debian-Feed ohne `linux`-Eintrag (Formatänderung) ist ein Fehler, die Daten bleiben.
    mock.lock().unwrap().debian_body = "{\"openssl\":{}}".into();
    mock.lock().unwrap().debian_status = Some(200);
    sqlx::query("UPDATE feed_state SET last_modified = NULL WHERE source = 'debian'")
        .execute(&pool)
        .await
        .unwrap();
    mock.lock().unwrap().debian_status = None;
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(&out[0].1, Outcome::Failed(m) if m.contains("linux")),
        "{:?}",
        out[0].1
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2004-0230").await.as_deref(),
        Some("vulnerable")
    );
}

/// Proxmox 9: immer UNKNOWN mit "manuell prüfen", kein ntfy-Alarm, manuelle Prüfung verfällt bei Kernelwechsel.
#[sqlx::test(migrations = "./migrations")]
async fn proxmox_is_unknown_without_alert_and_review_expires(pool: PgPool) {
    let mock: Shared = Arc::default();
    mock.lock().unwrap().debian_body =
        include_str!("fixtures/debian/tracker_subset_real.json").to_owned();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["debian"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "pve1").await;
    let pve = |version: &'static str, release: &'static str| K {
        host: "pve1",
        os_id: "debian",
        os_version: "13",
        codename: "trixie",
        release,
        version,
        package: "proxmox-kernel-6.14.11-2-pve-signed",
        source: "proxmox-kernel-6.14",
        newest_release: release,
        newest_version: version,
        proxmox: true,
    };
    assert_eq!(
        report(&app, &pve("6.14.11-2", "6.14.11-2-pve")).await,
        StatusCode::NO_CONTENT
    );
    let cookies = login(&app, &pool).await;
    let h = hdr(&cookies);
    assert_eq!(
        call(
            &app,
            Method::PUT,
            "/api/v1/watchlist/CVE-2024-1086",
            &h,
            None
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    refresh::refresh_all(&st).await;

    // Egal, was Debian zu `linux` sagt: für den -pve-Kernel nur UNKNOWN.
    let (status, reason): (String, String) = sqlx::query_as("SELECT status, reason FROM host_cve_status WHERE host_id = $1 AND cve_id = 'CVE-2024-1086'").bind(hid).fetch_one(&pool).await.unwrap();
    assert_eq!(status, "unknown");
    assert!(
        reason.contains("Manuell prüfen")
            && reason.contains("forum.proxmox.com/forums/security-advisories"),
        "{reason}"
    );
    // Nicht-Watchlist-CVEs erscheinen für Proxmox gar nicht erst als "behoben" oder "verwundbar".
    assert_eq!(count(&pool, "SELECT count(*) FROM host_cve_status WHERE status IN ('fixed', 'vulnerable', 'not_affected')").await, 0);
    assert_ne!(host_status(&pool, hid).await, "cve_vulnerable");

    // Kein ntfy-Alarm wegen UNKNOWN: weder host_cve- noch Watchlist-Meldung.
    while worker::process_events(&st).await.unwrap() > 0 {}
    let titles: Vec<String> =
        sqlx::query_scalar("SELECT payload->>'title' FROM jobs WHERE kind = 'notify'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        titles
            .iter()
            .all(|t| !t.contains("CVE-2024-1086") || !t.contains("unbekannt")),
        "{titles:?}"
    );
    assert!(
        !titles
            .iter()
            .any(|t| t.contains("pve1") && t.contains("Watchlist")),
        "{titles:?}"
    );

    // API: Host zeigt cve_unknown = 1; Matrix-Zelle ist unknown, nie grün.
    let hosts = call(&app, Method::GET, "/api/v1/hosts", &h, None).await;
    assert_eq!(hosts.json[0]["cve_unknown"], 1);
    let m = call(
        &app,
        Method::GET,
        &format!("/api/v1/matrix?cves=CVE-2024-1086&hosts={hid}"),
        &h,
        None,
    )
    .await;
    assert_eq!(m.json["cells"][0]["status"], "unknown");
    assert!(m.json["cells"][0]["manual_review"].is_null());

    // "Geprüft am …" setzen: Status bleibt UNKNOWN, Markierung ist sichtbar.
    let r = call(
        &app,
        Method::PUT,
        &format!("/api/v1/hosts/{hid}/cves/CVE-2024-1086/review"),
        &h,
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let m = call(
        &app,
        Method::GET,
        &format!("/api/v1/matrix?cves=CVE-2024-1086&hosts={hid}"),
        &h,
        None,
    )
    .await;
    assert_eq!(m.json["cells"][0]["status"], "unknown");
    assert_eq!(m.json["cells"][0]["manual_review"]["reviewed_by"], "admin");
    let list = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{hid}/cves"),
        &h,
        None,
    )
    .await;
    assert!(list.json[0]["reviewed_at"].is_string());

    // Neuer Proxmox-Kernel: die manuelle Prüfung gilt nicht mehr.
    assert_eq!(
        report(&app, &pve("6.14.11-4", "6.14.11-4-pve")).await,
        StatusCode::NO_CONTENT
    );
    let m = call(
        &app,
        Method::GET,
        &format!("/api/v1/matrix?cves=CVE-2024-1086&hosts={hid}"),
        &h,
        None,
    )
    .await;
    assert!(m.json["cells"][0]["manual_review"].is_null(), "{}", m.json);
    assert_eq!(m.json["cells"][0]["status"], "unknown");
}

/// Ubuntu 22.04 (jammy) und 24.04 (noble) mit echten Daten: gleiche CVE, unterschiedliche Releases.
#[sqlx::test(migrations = "./migrations")]
async fn real_cve_2024_1086_for_jammy_and_noble(pool: PgPool) {
    let mock: Shared = Arc::default();
    let single = load_fixture_cve(include_str!("fixtures/ubuntu/cve_single_real.json"), None);
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = vec![single.clone()];
    }
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let (jammy, noble_id) = (add_host(&pool, "j1").await, add_host(&pool, "n1").await);
    let j = K {
        host: "j1",
        os_id: "ubuntu",
        os_version: "22.04",
        codename: "jammy",
        release: "5.15.0-60-generic",
        package: "linux-image-5.15.0-60-generic",
        source: "linux-signed",
        version: "5.15.0-60.66",
        newest_release: "5.15.0-60-generic",
        newest_version: "5.15.0-60.66",
        proxmox: false,
    };
    assert_eq!(report(&app, &j).await, StatusCode::NO_CONTENT);
    assert_eq!(
        report(&app, &noble("n1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    sqlx::query("INSERT INTO cve_watchlist (cve_id) VALUES ('CVE-2024-1086')")
        .execute(&pool)
        .await
        .unwrap();
    refresh::refresh_all(&st).await;

    // Echte Daten: jammy hat den Fix in 5.15.0-101.111; noble ist laut Ubuntu gar nicht betroffen
    // (24.04 enthielt den Fix schon im Basiskernel).
    let fix_jammy: Option<String> = sqlx::query_scalar("SELECT fix_version FROM cve_source_status WHERE cve_id = 'CVE-2024-1086' AND package = 'linux' AND release = 'jammy'").fetch_one(&pool).await.unwrap();
    assert_eq!(fix_jammy.as_deref(), Some("5.15.0-101.111"));
    assert_eq!(
        cve_status(&pool, jammy, "CVE-2024-1086").await.as_deref(),
        Some("vulnerable"),
        "5.15.0-60.66 < 5.15.0-101.111"
    );
    assert_eq!(
        cve_status(&pool, noble_id, "CVE-2024-1086")
            .await
            .as_deref(),
        Some("not_affected")
    );

    // jammy-Kernel über die Fix-Version hinaus aktualisiert: behoben (Watchlist: Status bleibt gespeichert).
    let upd = K {
        version: "5.15.0-101.111",
        newest_version: "5.15.0-101.111",
        release: "5.15.0-101-generic",
        package: "linux-image-5.15.0-101-generic",
        newest_release: "5.15.0-101-generic",
        ..j
    };
    assert_eq!(report(&app, &upd).await, StatusCode::NO_CONTENT);
    assert_eq!(
        cve_status(&pool, jammy, "CVE-2024-1086").await.as_deref(),
        Some("fixed")
    );
    let (reason,): (String,) = sqlx::query_as(
        "SELECT reason FROM host_cve_status WHERE host_id = $1 AND cve_id = 'CVE-2024-1086'",
    )
    .bind(jammy)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        reason.contains("ubuntu (jammy/linux)") && reason.contains("5.15.0-101.111"),
        "{reason}"
    );
}

/// OSV (optionale dritte Quelle): echte Antwort, Ökosystem-Filter, Paginierung, kein Dauer-Abruf.
#[sqlx::test(migrations = "./migrations")]
async fn osv_third_source(pool: PgPool) {
    let mock: Shared = Arc::default();
    mock.lock().unwrap().osv_body =
        serde_json::from_str(include_str!("fixtures/osv/query_ubuntu_real.json")).unwrap();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["osv"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "n1").await;
    assert_eq!(
        report(&app, &noble("n1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );

    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    let fix: Option<String> = sqlx::query_scalar("SELECT fix_version FROM cve_source_status WHERE source = 'osv' AND cve_id = 'CVE-2020-12351'").fetch_one(&pool).await.unwrap();
    assert_eq!(fix.as_deref(), Some("6.8.0-35.35"));
    // OSV allein genügt, wenn kein Distributions-Tracker Daten hat: 6.8.0-31.31 < Fix -> verwundbar.
    assert_eq!(
        cve_status(&pool, hid, "CVE-2020-12351").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2012-4542").await.as_deref(),
        Some("vulnerable"),
        "ohne Fix-Event: verwundbar"
    );
    assert!(mock
        .lock()
        .unwrap()
        .log
        .iter()
        .any(|l| l.contains("Ubuntu:24.04:LTS") && l.contains("6.8.0-31.31")));

    // Gleiche Abfrage im 6-Stunden-Fenster: kein erneuter Abruf.
    let before = mock.lock().unwrap().log.len();
    assert_eq!(refresh::refresh_all(&st).await[0].1, Outcome::NotModified);
    assert_eq!(mock.lock().unwrap().log.len(), before);
}
