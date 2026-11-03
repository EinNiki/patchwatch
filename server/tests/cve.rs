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
    /// Seite ab diesem Offset antwortet mit HTTP 500 (Netz-/Serverfehler mitten im Lauf).
    ubuntu_fail_offset: Option<usize>,
    debian_body: String,
    debian_status: Option<u16>,
    osv_body: Value,
    kev_body: Value,
    kev_status: Option<u16>,
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
    // Einzelabfragen (limit=1) dienen nur der Seitenschätzung des Erstabrufs und zählen nicht als Seite.
    m.log.push(if limit == 20 {
        format!("ubuntu offset={offset}")
    } else {
        format!("ubuntu probe={offset}")
    });
    if let Some(code) = m.ubuntu_status {
        return StatusCode::from_u16(code).unwrap().into_response();
    }
    if m.ubuntu_fail_offset == Some(offset) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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

async fn nvd(
    State(m): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut m = m.lock().unwrap();
    let id = q["cveId"].clone();
    let key = headers
        .get("apikey")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();
    m.log.push(format!("nvd {id} key={key}"));
    Json(json!({"vulnerabilities": [{"cve": {
        "id": id, "published": "2026-01-01T00:00:00.000", "lastModified": "2026-02-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": format!("NVD-Beschreibung {id}")}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}
    }}]}))
    .into_response()
}

async fn kev(State(m): State<Shared>) -> Response {
    let mut m = m.lock().unwrap();
    m.log.push("kev".into());
    if let Some(code) = m.kev_status {
        return StatusCode::from_u16(code).unwrap().into_response();
    }
    Json(m.kev_body.clone()).into_response()
}

async fn start_mock(mock: Shared) -> String {
    let app = Router::new()
        .route("/security/cves.json", get(ubuntu_list))
        .route("/security/cves/{id}", get(ubuntu_one))
        .route("/tracker/data/json", get(debian))
        .route("/v1/query", post(osv))
        .route("/nvd", get(nvd))
        .route("/kev", get(kev))
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
        "[cve]\nsources = [{list}]\nubuntu_url = \"{base}\"\ndebian_url = \"{base}/tracker/data/json\"\nosv_url = \"{base}\"\nnvd_url = \"{base}/nvd\"\nkev_url = \"{base}/kev\"\n\
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

/// Ubuntu: Cursor-Paginierung lädt nicht jedes Mal alles; zu großer Rückstand ist sichtbar unvollständig.
#[sqlx::test(migrations = "./migrations")]
async fn ubuntu_stops_at_cursor_and_reports_backlog(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "ubuntu_max_pages = 2", &base).await;
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
    // 45 CVEs bei 2 Seiten pro Lauf: der Erstabruf ist erst nach 2 Läufen vollständig (nie nach nur 40).
    mock.lock().unwrap().ubuntu = make(45, 100);
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(
            out[0].1,
            Outcome::Incomplete {
                changed_rows: 40,
                ..
            }
        ),
        "{:?}",
        out[0].1
    );
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 45);

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
        matches!(&out[0].1, Outcome::Incomplete { .. }),
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

// ---------- Ubuntu: Rückstand größer als das Seitenlimit ----------

/// `n` CVEs mit absteigenden Zeitstempeln ab `newest`; IDs `CVE-2026-{prefix}NNNN`.
fn ubuntu_batch(prefix: u32, n: usize, newest: chrono::DateTime<Utc>) -> Vec<Value> {
    (0..n)
        .map(|i| {
            ubuntu_cve(
                &format!("CVE-2026-{prefix}{i:04}"),
                newest - Duration::seconds(i as i64),
                &[("noble", "needed", "")],
            )
        })
        .collect()
}

async fn ubuntu_feed(app: &Router, cookies: &[(String, String)]) -> Value {
    let r = call(app, Method::GET, "/api/v1/feeds", &hdr(cookies), None).await;
    assert_eq!(r.status, StatusCode::OK);
    r.json[0].clone()
}

async fn ubuntu_cursor(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT cursor FROM feed_state WHERE source = 'ubuntu'")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn offsets(mock: &Shared) -> Vec<usize> {
    mock.lock()
        .unwrap()
        .log
        .iter()
        .filter_map(|l| l.strip_prefix("ubuntu offset=")?.parse().ok())
        .collect()
}

/// Rückstand > Seitenlimit über mehrere Läufe: Fortschritt wird gespeichert, der Abruf setzt dort fort (nicht bei
/// Seite 1), der bestätigte Cursor springt nie über die Lücke, die Quelle ist bis zum Schluss nie "ok", und am Ende
/// sind alle Records da. Währenddessen neu eintreffende Änderungen am Listenkopf gehen nicht verloren.
#[sqlx::test(migrations = "./migrations")]
async fn ubuntu_backlog_larger_than_page_limit_is_worked_off_over_runs(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "ubuntu_max_pages = 2", &base).await;
    let app = patchwatch_server::router(st.clone());
    let cookies = login(&app, &pool).await;
    let now = Utc::now();

    // Erstabruf: 20 alte CVEs, Cursor = neueste davon.
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 20, now - Duration::hours(10));
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(ubuntu_feed(&app, &cookies).await["state"], "ok");
    let confirmed = ubuntu_cursor(&pool).await;

    // Rückstand: 130 neue CVEs = 6,5 Seiten bei 2 Seiten pro Lauf (netto 20 je Lauf wegen der Überlappung).
    let flood_newest = now - Duration::hours(1);
    {
        let mut m = mock.lock().unwrap();
        let mut list = ubuntu_batch(2, 130, flood_newest);
        list.extend(m.ubuntu.clone());
        m.ubuntu = list;
        m.log.clear();
    }
    let expected_pending = flood_newest.to_rfc3339();

    let mut runs = 0;
    let mut late_head_added = false;
    loop {
        runs += 1;
        assert!(runs <= 12, "Rückstand wird nicht abgebaut");
        mock.lock().unwrap().log.clear();
        let out = refresh::refresh_all(&st).await;
        let first_offset = offsets(&mock)[0];
        if runs == 1 {
            assert_eq!(first_offset, 0);
        } else if matches!(
            out[0].1,
            Outcome::Incomplete { .. } | Outcome::Updated { .. }
        ) {
            // Wiederaufsetzen: nie wieder bei Seite 1 beginnen.
            assert!(first_offset > 0, "Lauf {runs} begann wieder bei Seite 1");
        }
        let feed = ubuntu_feed(&app, &cookies).await;
        match &out[0].1 {
            Outcome::Incomplete { .. } => {
                // Bestätigter Cursor bleibt stehen, Quelle ist unvollständig und nie grün, Fortschritt sichtbar.
                assert_eq!(
                    ubuntu_cursor(&pool).await,
                    confirmed,
                    "Cursor sprang in Lauf {runs}"
                );
                assert_eq!(feed["state"], "incomplete", "Lauf {runs}");
                assert_eq!(feed["healthy"], false);
                assert_eq!(feed["backfill"]["runs"], runs);
                assert_eq!(feed["backfill"]["pages_per_run"], 2);
                assert!(feed["backfill"]["progress"]
                    .as_str()
                    .unwrap()
                    .contains("Rückstand wird abgebaut"));
                assert!(feed["stale_since"].is_string());
                assert_eq!(
                    feed["consecutive_failures"], 0,
                    "Fortschritt ist kein Fehlschlag"
                );
                // Neue Änderungen am Listenkopf mitten im Abbau (verschiebt alle Offsets nach hinten).
                if runs == 2 && !late_head_added {
                    late_head_added = true;
                    let mut m = mock.lock().unwrap();
                    let mut list = ubuntu_batch(3, 3, now);
                    list.extend(m.ubuntu.clone());
                    m.ubuntu = list;
                }
            }
            Outcome::Updated { .. } => {
                assert_eq!(feed["state"], "ok");
                assert!(feed["backfill"].is_null());
                break;
            }
            other => panic!("Lauf {runs}: {other:?}"),
        }
    }
    assert_eq!(
        runs, 6,
        "20 Seiten Netto je Lauf: 130 CVEs brauchen 6 Läufe"
    );

    // Der Cursor ist erst jetzt vorgerückt, und zwar auf den neuesten Stand zu BEGINN des Abbaus.
    assert_eq!(ubuntu_cursor(&pool).await, expected_pending);
    // Alle 20 + 130 CVEs sind da; die 3 nachträglichen Änderungen sind noch nicht geladen (neuer als der Cursor).
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 150);

    // Nächster Lauf holt genau die 3 Änderungen, die während des Abbaus am Kopf eintrafen.
    mock.lock().unwrap().log.clear();
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(
            out[0].1,
            Outcome::Updated {
                changed_rows: 3,
                ..
            }
        ),
        "{:?}",
        out[0].1
    );
    assert_eq!(offsets(&mock), vec![0], "normaler Lauf stoppt am Cursor");
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 153);
    assert_eq!(ubuntu_feed(&app, &cookies).await["state"], "ok");
}

/// Ein Lauf bricht mittendrin ab (Netzfehler): bereits geladene Seiten bleiben gespeichert, der Cursor bleibt, der
/// Fehler ist sichtbar und der nächste Lauf macht dort weiter. Ein Fehler schon auf der ersten Seite verliert
/// den gespeicherten Fortschritt nicht.
#[sqlx::test(migrations = "./migrations")]
async fn ubuntu_run_interrupted_midway_keeps_progress(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "ubuntu_max_pages = 4", &base).await;
    let app = patchwatch_server::router(st.clone());
    let cookies = login(&app, &pool).await;
    let now = Utc::now();

    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 20, now - Duration::hours(10));
    refresh::refresh_all(&st).await;
    let confirmed = ubuntu_cursor(&pool).await;
    {
        let mut m = mock.lock().unwrap();
        let mut list = ubuntu_batch(2, 100, now - Duration::hours(1));
        list.extend(m.ubuntu.clone());
        m.ubuntu = list;
        m.ubuntu_fail_offset = Some(40); // dritte Seite schlägt fehl
        m.log.clear();
    }

    // Lauf 1: Seiten 0 und 1 sind da, Seite 2 bricht ab.
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(
            out[0].1,
            Outcome::Incomplete {
                changed_rows: 40,
                ..
            }
        ),
        "{:?}",
        out[0].1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cves").await,
        60,
        "40 neue + 20 alte"
    );
    assert_eq!(
        ubuntu_cursor(&pool).await,
        confirmed,
        "Cursor darf nicht vorrücken"
    );
    let feed = ubuntu_feed(&app, &cookies).await;
    assert_eq!(feed["state"], "incomplete");
    assert!(feed["last_error"]
        .as_str()
        .unwrap()
        .contains("unterbrochen"));
    assert_eq!(feed["consecutive_failures"], 0);
    assert_eq!(
        feed["backfill"]["next_offset"], 20,
        "eine Seite Überlappung"
    );

    // Lauf 2: Fehler schon auf der ersten Seite (Offset 20) -> Fehlschlag, Fortschritt bleibt erhalten.
    mock.lock().unwrap().ubuntu_fail_offset = Some(20);
    mock.lock().unwrap().log.clear();
    let out = refresh::refresh_all(&st).await;
    assert!(matches!(&out[0].1, Outcome::Failed(_)), "{:?}", out[0].1);
    assert_eq!(offsets(&mock)[0], 20, "setzt bei gespeichertem Offset fort");
    assert_eq!(ubuntu_cursor(&pool).await, confirmed);
    let feed = ubuntu_feed(&app, &cookies).await;
    assert_eq!(feed["state"], "incomplete");
    assert_eq!(feed["consecutive_failures"], 1);
    assert_eq!(
        feed["backfill"]["next_offset"], 20,
        "Fortschritt unverändert"
    );

    // Läufe 3 und 4: Quelle wieder erreichbar, Rückstand wird fertig abgebaut.
    mock.lock().unwrap().ubuntu_fail_offset = None;
    let mut last = Outcome::NotModified;
    for _ in 0..3 {
        last = refresh::refresh_all(&st).await.remove(0).1;
        if matches!(last, Outcome::Updated { .. }) {
            break;
        }
        assert!(matches!(last, Outcome::Incomplete { .. }), "{last:?}");
        assert_ne!(ubuntu_feed(&app, &cookies).await["state"], "ok");
    }
    assert!(matches!(last, Outcome::Updated { .. }), "{last:?}");
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 120);
    let feed = ubuntu_feed(&app, &cookies).await;
    assert_eq!(feed["state"], "ok");
    assert!(feed["last_error"].is_null() && feed["backfill"].is_null());
    assert_eq!(
        ubuntu_cursor(&pool).await,
        (now - Duration::hours(1)).to_rfc3339()
    );
}

/// Wurde der Cursor von Hand geändert, passt ein offener Rückstandsabbau nicht mehr dazu: der Abruf beginnt wieder
/// bei Seite 1, statt mit einem veralteten Offset über eine neue Lücke hinwegzulesen.
#[sqlx::test(migrations = "./migrations")]
async fn ubuntu_backfill_is_dropped_when_cursor_changed_manually(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "ubuntu_max_pages = 2", &base).await;
    let now = Utc::now();
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 20, now - Duration::hours(10));
    refresh::refresh_all(&st).await;
    {
        let mut m = mock.lock().unwrap();
        let mut list = ubuntu_batch(2, 100, now - Duration::hours(1));
        list.extend(m.ubuntu.clone());
        m.ubuntu = list;
    }
    refresh::refresh_all(&st).await;
    refresh::refresh_all(&st).await;
    let nxt: i64 = sqlx::query_scalar(
        "SELECT (backfill->>'next_offset')::bigint FROM feed_state WHERE source = 'ubuntu'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(nxt > 0);
    sqlx::query("UPDATE feed_state SET cursor = $1 WHERE source = 'ubuntu'")
        .bind((now - Duration::hours(5)).to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
    mock.lock().unwrap().log.clear();
    refresh::refresh_all(&st).await;
    assert_eq!(offsets(&mock)[0], 0);
}

// ---------- Fund 2: Erstabruf ist ein fortsetzbarer Abbau, nie "vollständig" nach wenigen Seiten ----------

async fn ubuntu_feed_row(app: &Router, h: &[(String, String)]) -> Value {
    feed(&feeds(app, h).await, "ubuntu").clone()
}

async fn ubuntu_cursor_opt(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT cursor FROM feed_state WHERE source = 'ubuntu'")
        .fetch_optional(pool)
        .await
        .unwrap()
        .flatten()
}

/// Erstabruf mit mehr CVEs als Seitenlimit: mehrere Läufe, am Ende ist alles da, dazwischen ist die Quelle nie
/// "ok", der Cursor fehlt bis zum Schluss, die Anzeige nennt "Erstabruf läuft, N von M Seiten".
#[sqlx::test(migrations = "./migrations")]
async fn fund2_initial_import_larger_than_page_limit_is_built_up_over_runs(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed_extra(pool.clone(), &["ubuntu"], &base, "ubuntu_max_pages = 2").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let now = Utc::now();
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 130, now - Duration::hours(1));

    let mut runs = 0;
    loop {
        runs += 1;
        assert!(runs <= 12, "Erstabruf wird nicht fertig");
        mock.lock().unwrap().log.clear();
        let out = refresh::refresh_all(&st).await;
        let row = ubuntu_feed_row(&app, &h).await;
        match &out[0].1 {
            Outcome::Incomplete { .. } => {
                assert_eq!(row["state"], "incomplete", "Lauf {runs}");
                assert_eq!(row["healthy"], false);
                assert_eq!(row["backfill"]["initial"], true);
                assert_eq!(row["backfill"]["est_pages"], 7, "130 CVEs = 7 Seiten");
                let text = row["backfill"]["progress"].as_str().unwrap();
                assert!(
                    text.starts_with("Erstabruf läuft, ") && text.contains(" von ca. 7 Seiten"),
                    "{text}"
                );
                assert!(
                    ubuntu_cursor_opt(&pool).await.is_none(),
                    "kein Cursor vor dem Ende"
                );
            }
            Outcome::Updated { .. } => {
                assert_eq!(row["state"], "ok");
                break;
            }
            other => panic!("Lauf {runs}: {other:?}"),
        }
        if runs == 1 {
            assert!(
                mock.lock()
                    .unwrap()
                    .log
                    .iter()
                    .any(|l| l.starts_with("ubuntu probe=")),
                "Seitenschätzung fehlt"
            );
        }
    }
    assert_eq!(runs, 6);
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 130);
    assert!(ubuntu_cursor_opt(&pool).await.is_some());
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM feed_state WHERE source = 'ubuntu' AND covered_since IS NOT NULL"
        )
        .await,
        1
    );
    // Danach normal: nur die erste Seite, Stopp am Cursor.
    mock.lock().unwrap().log.clear();
    assert_eq!(refresh::refresh_all(&st).await[0].1, Outcome::NotModified);
    assert_eq!(mock.lock().unwrap().log, vec!["ubuntu offset=0"]);
}

/// Horizont: der Erstabruf endet beim ersten Eintrag, der älter ist; die Quelle gilt dann als vollständig.
#[sqlx::test(migrations = "./migrations")]
async fn fund2_initial_import_stops_at_the_horizon(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed_extra(pool.clone(), &["ubuntu"], &base, "ubuntu_horizon_days = 1").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let now = Utc::now();
    {
        let mut m = mock.lock().unwrap();
        let mut list = ubuntu_batch(1, 25, now - Duration::minutes(5));
        let mut old = ubuntu_batch(2, 25, now - Duration::days(3));
        for c in &mut old {
            c["id"] = json!(c["id"]
                .as_str()
                .unwrap()
                .replace("CVE-2026-2", "CVE-2026-8"));
        }
        list.extend(old);
        m.ubuntu = list;
    }
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cves").await,
        25,
        "nur innerhalb des Horizonts"
    );
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "ok");
}

/// Ein Erstabruf, der mittendrin abbricht, gilt nie als vollständig; ein Fehler schon auf der ersten Seite auch nicht.
#[sqlx::test(migrations = "./migrations")]
async fn fund2_interrupted_initial_import_is_never_complete(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed_extra(pool.clone(), &["ubuntu"], &base, "ubuntu_max_pages = 4").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let now = Utc::now();
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 100, now - Duration::hours(1));

    // Allererster Abruf scheitert auf der ersten Seite: nichts wird als vollständig vermerkt.
    mock.lock().unwrap().ubuntu_status = Some(500);
    let out = refresh::refresh_all(&st).await;
    assert!(matches!(&out[0].1, Outcome::Failed(_)), "{:?}", out[0].1);
    assert!(ubuntu_cursor_opt(&pool).await.is_none());
    assert_ne!(ubuntu_feed_row(&app, &h).await["state"], "ok");
    mock.lock().unwrap().ubuntu_status = None;

    // Dritte Seite bricht ab: die beiden ersten bleiben, kein Cursor, "unvollständig".
    mock.lock().unwrap().ubuntu_fail_offset = Some(40);
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Incomplete { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 40);
    assert!(ubuntu_cursor_opt(&pool).await.is_none());
    let row = ubuntu_feed_row(&app, &h).await;
    assert_eq!(row["state"], "incomplete");
    assert!(row["last_error"].as_str().unwrap().contains("unterbrochen"));

    // Weiter ohne Fehler: am Ende vollständig.
    mock.lock().unwrap().ubuntu_fail_offset = None;
    let mut last = Outcome::NotModified;
    for _ in 0..4 {
        last = refresh::refresh_all(&st).await.remove(0).1;
        if matches!(last, Outcome::Updated { .. }) {
            break;
        }
        assert_ne!(ubuntu_feed_row(&app, &h).await["state"], "ok");
    }
    assert!(matches!(last, Outcome::Updated { .. }), "{last:?}");
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 100);
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "ok");
}

/// Löschen und Neuanlegen der Quelle startet den Abbau neu: neue ID, leerer Zustand, wieder "unvollständig".
#[sqlx::test(migrations = "./migrations")]
async fn fund2_deleting_and_recreating_the_source_restarts_the_import(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed_extra(pool.clone(), &["ubuntu"], &base, "ubuntu_max_pages = 2").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 60, Utc::now() - Duration::hours(1));
    for _ in 0..6 {
        refresh::refresh_all(&st).await;
    }
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "ok");

    let r = call(&app, Method::DELETE, "/api/v1/feeds/ubuntu", &hdr(&h), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = call(
        &app,
        Method::POST,
        "/api/v1/feeds",
        &hdr(&h),
        Some(json!({"type": "ubuntu"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    let new_id = r.json["source"]
        .as_str()
        .or(r.json["id"].as_str())
        .unwrap()
        .to_owned();
    assert_ne!(new_id, "ubuntu", "neue Quelle hat eine neue ID");

    mock.lock().unwrap().log.clear();
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Incomplete { .. }),
        "{:?}",
        out[0].1
    );
    assert!(
        mock.lock()
            .unwrap()
            .log
            .iter()
            .any(|l| l.starts_with("ubuntu probe=")),
        "neuer Erstabruf beginnt mit der Seitenschätzung"
    );
    let row = feed(&feeds(&app, &h).await, &new_id).clone();
    assert_eq!(
        row["state"], "incomplete",
        "neue Quelle ist erst nach dem Abbau vollständig"
    );
    assert_eq!(row["backfill"]["initial"], true);
}

/// Altbestand: ein Cursor ohne bestätigten Horizont (früher: nach 5 Seiten "vollständig") wird beim Start wieder
/// zum Erstabruf; bis zum Ende ist die Quelle unvollständig, danach vollständig und alle Einträge sind da.
#[sqlx::test(migrations = "./migrations")]
async fn fund2_legacy_truncated_import_is_reopened_on_start(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed_extra(pool.clone(), &["ubuntu"], &base, "ubuntu_max_pages = 3").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let now = Utc::now();
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 80, now - Duration::hours(1));
    patchwatch_server::cve::sources::ensure_seeded(&st)
        .await
        .unwrap();
    // Zustand der alten Version: Cursor gesetzt, Daten nur vom Kopf der Liste, nie bis zu einem Horizont geladen.
    sqlx::query("INSERT INTO feed_state (source, cursor, last_success_at, usable_until) VALUES ('ubuntu', $1, now(), now() + interval '6 hours')")
        .bind((now - Duration::hours(1)).to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        ubuntu_feed_row(&app, &h).await["state"],
        "ok",
        "so sah es vorher aus"
    );

    let n = patchwatch_server::cve::ubuntu::reopen_legacy_imports(&pool, 365)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        patchwatch_server::cve::ubuntu::reopen_legacy_imports(&pool, 365)
            .await
            .unwrap(),
        0
    );
    let row = ubuntu_feed_row(&app, &h).await;
    assert_eq!(row["state"], "incomplete");
    assert_eq!(row["backfill"]["initial"], true);

    let mut done = false;
    for _ in 0..6 {
        let out = refresh::refresh_all(&st).await;
        if matches!(out[0].1, Outcome::Updated { .. }) {
            done = true;
            break;
        }
        assert_ne!(ubuntu_feed_row(&app, &h).await["state"], "ok");
    }
    assert!(done);
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 80);
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "ok");
    assert_eq!(
        patchwatch_server::cve::ubuntu::reopen_legacy_imports(&pool, 365)
            .await
            .unwrap(),
        0
    );
}

// ---------- Fund 3: Host nur grün, wenn alle zuständigen Quellen nutzbar sind ----------

async fn host_issue(app: &Router, h: &[(String, String)], id: i64) -> Option<String> {
    let r = call(
        app,
        Method::GET,
        &format!("/api/v1/hosts/{id}"),
        &hdr(h),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    r.json["cve_source_issue"].as_str().map(str::to_owned)
}

async fn gate(st: &AppState) {
    patchwatch_server::hostops::recompute_cve_gated_hosts(&st.pool, None, Duration::hours(26))
        .await
        .unwrap();
}

/// Quelle nie geladen, nur teilweise, zuletzt fehlerhaft, veraltet, abgeschaltet, gelöscht: Host nie grün,
/// mit Begründung. Quelle in Ordnung: grün wie bisher.
#[sqlx::test(migrations = "./migrations")]
async fn fund3_host_is_never_green_unless_the_source_is_complete_and_fresh(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed_extra(pool.clone(), &["ubuntu"], &base, "ubuntu_max_pages = 1").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    patchwatch_server::cve::sources::ensure_seeded(&st)
        .await
        .unwrap();
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    // Nur Fixes, die der Host schon hat: bei vollständigen Daten ist er "ok".
    mock.lock().unwrap().ubuntu = (0..45)
        .map(|i| {
            ubuntu_cve(
                &format!("CVE-2026-1{i:04}"),
                Utc::now() - Duration::minutes(i as i64 + 1),
                &[("noble", "released", "6.8.0-20.20")],
            )
        })
        .collect();

    // 1. Nie geladen.
    gate(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_unknown", "nie geladen");
    assert!(host_issue(&app, &h, hid)
        .await
        .unwrap()
        .contains("noch nie"));

    // 2. Nur teilweise (1 Seite pro Lauf): unvollständig, nie grün; Report ändert daran nichts.
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Incomplete { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(host_status(&pool, hid).await, "cve_unknown");
    assert!(host_issue(&app, &h, hid)
        .await
        .unwrap()
        .contains("unvollständig"));
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        host_status(&pool, hid).await,
        "cve_unknown",
        "ein neuer Report macht nicht grün"
    );

    // 3. Vollständig: grün wie bisher, keine Begründung.
    for _ in 0..4 {
        refresh::refresh_all(&st).await;
    }
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "ok");
    assert_eq!(host_status(&pool, hid).await, "ok");
    assert!(host_issue(&app, &h, hid).await.is_none());

    // 4. Zuletzt fehlerhaft: ein oder zwei Fehlschläge sind noch kein Dauerfehler, der dritte schon.
    mock.lock().unwrap().ubuntu_status = Some(500);
    for _ in 0..2 {
        refresh::refresh_all(&st).await;
    }
    assert_eq!(
        host_status(&pool, hid).await,
        "ok",
        "gelegentlicher Fehler: noch nutzbar"
    );
    refresh::refresh_all(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_unknown", "Dauerfehler");
    assert!(host_issue(&app, &h, hid)
        .await
        .unwrap()
        .contains("fehlerhaft"));
    mock.lock().unwrap().ubuntu_status = None;
    refresh::refresh_all(&st).await;
    assert_eq!(host_status(&pool, hid).await, "ok", "Erholung");

    // 5. Veraltet: ohne neuen Abruf läuft die Frische ab (max(3 x Intervall, 6 h)).
    sqlx::query(
        "UPDATE feed_state SET usable_until = now() - interval '1 minute' WHERE source = 'ubuntu'",
    )
    .execute(&pool)
    .await
    .unwrap();
    gate(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_unknown", "veraltet");
    assert!(host_issue(&app, &h, hid)
        .await
        .unwrap()
        .contains("veraltet"));
    refresh::refresh_all(&st).await;
    assert_eq!(host_status(&pool, hid).await, "ok");
    let until: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT usable_until FROM feed_state WHERE source = 'ubuntu'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        until > Utc::now() + Duration::hours(5) && until < Utc::now() + Duration::hours(7),
        "Frist ist max(3 x 60 min, 6 h) = 6 h: {until}"
    );

    // 6. Rot bleibt rot: bekannte verwundbare CVE bleibt sichtbar, auch wenn die Quelle veraltet.
    mock.lock().unwrap().ubuntu.insert(
        0,
        ubuntu_cve("CVE-2026-99001", Utc::now(), &[("noble", "needed", "")]),
    );
    refresh::refresh_all(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");
    sqlx::query(
        "UPDATE feed_state SET usable_until = now() - interval '1 minute' WHERE source = 'ubuntu'",
    )
    .execute(&pool)
    .await
    .unwrap();
    gate(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-99001").await.as_deref(),
        Some("vulnerable")
    );
    mock.lock().unwrap().ubuntu.remove(0);

    // 7. Abgeschaltet und 8. gelöscht: nie grün.
    sqlx::query("DELETE FROM host_cve_status")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE feed_state SET usable_until = now() + interval '6 hours', cursor = cursor WHERE source = 'ubuntu'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE cve_sources SET enabled = false WHERE id = 'ubuntu'")
        .execute(&pool)
        .await
        .unwrap();
    gate(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_unknown", "abgeschaltet");
    assert!(host_issue(&app, &h, hid)
        .await
        .unwrap()
        .contains("keine aktive"));
    sqlx::query("UPDATE cve_sources SET enabled = true WHERE id = 'ubuntu'")
        .execute(&pool)
        .await
        .unwrap();
    gate(&st).await;
    assert_eq!(host_status(&pool, hid).await, "ok");
    sqlx::query("UPDATE cve_sources SET deleted_at = now() WHERE id = 'ubuntu'")
        .execute(&pool)
        .await
        .unwrap();
    gate(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_unknown", "gelöscht");
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

    // OSV reichert nur bereits bekannte CVEs an (aus Debian/Ubuntu oder der Watchlist), es importiert nie voll.
    sqlx::query("INSERT INTO cves (id) VALUES ('CVE-2020-12351'), ('CVE-2012-4542')")
        .execute(&pool)
        .await
        .unwrap();
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    let osv_cves: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT cve_id) FROM cve_source_status WHERE source = 'osv'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        osv_cves, 2,
        "unbekannte CVEs aus der OSV-Antwort werden nicht importiert"
    );
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM cves")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(total, 2);
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

// ---------- Quellenverwaltung (NVD, CISA KEV, an/aus) ----------

const SECRET_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

async fn setup_keyed(pool: PgPool, sources: &[&str], base: &str) -> AppState {
    setup_keyed_extra(pool, sources, base, "").await
}

async fn setup_keyed_extra(pool: PgPool, sources: &[&str], base: &str, extra: &str) -> AppState {
    let list = sources
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(",");
    let toml = format!(
        "[cve]\nsources = [{list}]\nubuntu_url = \"{base}\"\ndebian_url = \"{base}/tracker/data/json\"\nosv_url = \"{base}\"\n\
         nvd_url = \"{base}/nvd\"\nkev_url = \"{base}/kev\"\nretries = 1\nretry_base_delay_ms = 10\nrequest_timeout_secs = 10\n{extra}\n"
    );
    let cfg = Config::from_sources(Some(&toml), &|k| {
        (k == "PATCHWATCH_SECRET_KEY").then(|| SECRET_B64.to_owned())
    })
    .unwrap();
    AppState::new(pool, cfg).unwrap()
}

async fn feeds(app: &Router, h: &[(String, String)]) -> Vec<Value> {
    let r = call(app, Method::GET, "/api/v1/feeds", &hdr(h), None).await;
    assert_eq!(r.status, StatusCode::OK);
    r.json.as_array().unwrap().clone()
}

fn feed<'a>(list: &'a [Value], name: &str) -> &'a Value {
    list.iter()
        .find(|f| f["source"] == name || f["type"] == name)
        .unwrap_or_else(|| panic!("Quelle {name} fehlt"))
}

#[sqlx::test(migrations = "./migrations")]
async fn nvd_enriches_only_known_watchlist_cves_within_batch_and_never_leaks_the_key(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;

    // 12 bekannte, beobachtete CVEs (ohne Beschreibung) und eine unbekannte.
    for i in 0..12 {
        let id = format!("CVE-2026-{:04}", 1000 + i);
        sqlx::query("INSERT INTO cves (id) VALUES ($1)")
            .bind(&id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO cve_watchlist (cve_id) VALUES ($1)")
            .bind(&id)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO cves (id, description, priority) VALUES ('CVE-2026-0999', 'aus Ubuntu', 'high')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cve_watchlist (cve_id) VALUES ('CVE-2026-0999')")
        .execute(&pool)
        .await
        .unwrap();

    // Quelle hinzufügen, Schlüssel ist nur schreibend.
    let r = call(
        &app,
        Method::POST,
        "/api/v1/feeds",
        &hdr(&h),
        Some(json!({"type": "nvd", "secret": "geheimer-nvd-schluessel"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let list = feeds(&app, &h).await;
    assert_eq!(feed(&list, "nvd")["secret_set"], true);
    assert!(!serde_json::to_string(&list)
        .unwrap()
        .contains("geheimer-nvd-schluessel"));
    let nvd_id: String = sqlx::query_scalar("SELECT id FROM cve_sources WHERE kind = 'nvd'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let blob: Vec<u8> = sqlx::query_scalar("SELECT secret FROM cve_sources WHERE kind = 'nvd'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !blob.windows(10).any(|w| w == b"geheimer-n"),
        "Geheimnis liegt verschlüsselt in der DB"
    );
    // Die stabile Quellen-ID ist die AAD: für eine andere Quelle lässt sich das Geheimnis nicht entschlüsseln.
    let key = st.cfg.secret_key.as_ref().unwrap();
    assert_eq!(
        patchwatch_server::notify::crypto::decrypt(
            key.bytes(),
            &format!("cve_source:{nvd_id}"),
            &blob
        )
        .unwrap(),
        "geheimer-nvd-schluessel"
    );
    assert!(
        patchwatch_server::notify::crypto::decrypt(key.bytes(), "cve_source:osv", &blob).is_err()
    );
    // Der Anzeigename oder Typ als AAD taugt nicht.
    assert!(
        patchwatch_server::notify::crypto::decrypt(key.bytes(), "cve_source:nvd", &blob).is_err()
    );

    let out = refresh::refresh_all(&st).await;
    let nvd_out = out.iter().find(|(n, _)| *n == nvd_id).unwrap();
    assert!(
        matches!(nvd_out.1, Outcome::Updated { .. }),
        "{:?}",
        nvd_out.1
    );
    let log = mock.lock().unwrap().log.clone();
    let nvd_calls: Vec<&String> = log.iter().filter(|l| l.starts_with("nvd ")).collect();
    // Mit Schlüssel bis zu 50 je Lauf: alle 12 offenen, nicht die bereits beschriebene (Quelle hat sie noch nicht -> auch sie).
    assert_eq!(nvd_calls.len(), 13, "{nvd_calls:?}");
    assert!(
        nvd_calls
            .iter()
            .all(|l| l.ends_with("key=geheimer-nvd-schluessel")),
        "Schlüssel geht als Header mit"
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cves").await,
        13,
        "kein Vollimport, keine neuen CVEs"
    );
    let (d, p): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT description, priority FROM cves WHERE id = 'CVE-2026-1000'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (d.as_deref(), p.as_deref()),
        (Some("NVD-Beschreibung CVE-2026-1000"), Some("critical"))
    );
    let (d, p): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT description, priority FROM cves WHERE id = 'CVE-2026-0999'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (d.as_deref(), p.as_deref()),
        (Some("aus Ubuntu"), Some("high")),
        "vorhandene Daten bleiben"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM events WHERE kind IN ('cve_status_changed', 'cve_new')"
        )
        .await,
        0,
        "Anreicherung löst keine Meldungen aus"
    );

    // Zweiter Lauf: alles angereichert, keine weitere Anfrage.
    let before = mock.lock().unwrap().log.len();
    refresh::refresh_all(&st).await;
    assert_eq!(
        mock.lock()
            .unwrap()
            .log
            .iter()
            .skip(before)
            .filter(|l| l.starts_with("nvd "))
            .count(),
        0
    );
    // Die Anreicherung erzeugt weder Distro-Chips noch einen Host-Status.
    let r = call(
        &app,
        Method::GET,
        "/api/v1/cves/CVE-2026-1000",
        &hdr(&h),
        None,
    )
    .await;
    assert!(r.json["distros"].as_array().unwrap().is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn nvd_without_key_is_limited_to_ten_per_run(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    for i in 0..25 {
        let id = format!("CVE-2026-{:04}", 2000 + i);
        sqlx::query("INSERT INTO cves (id) VALUES ($1)")
            .bind(&id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO cve_watchlist (cve_id) VALUES ($1)")
            .bind(&id)
            .execute(&pool)
            .await
            .unwrap();
    }
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/feeds",
            &hdr(&h),
            Some(json!({"type": "nvd"}))
        )
        .await
        .status,
        StatusCode::CREATED
    );
    refresh::refresh_all(&st).await;
    let n = |m: &Shared| {
        m.lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| l.starts_with("nvd "))
            .count()
    };
    assert_eq!(
        n(&mock),
        10,
        "ohne Schlüssel höchstens 10 je Lauf (5 Anfragen/30 s)"
    );
    assert!(mock
        .lock()
        .unwrap()
        .log
        .iter()
        .all(|l| !l.starts_with("nvd ") || l.ends_with("key=-")));
    refresh::refresh_all(&st).await;
    assert_eq!(n(&mock), 20, "der Rest folgt in den nächsten Läufen");
}

#[sqlx::test(migrations = "./migrations")]
async fn kev_flags_only_known_cves_and_failure_is_never_green(pool: PgPool) {
    let mock: Shared = Arc::default();
    mock.lock().unwrap().kev_body = json!({"vulnerabilities": [
        {"cveID": "CVE-2024-1086", "vulnerabilityName": "Linux Kernel UAF", "dateAdded": "2024-05-30", "dueDate": "2024-06-20", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-9999", "vulnerabilityName": "Irgendwas"},
    ]});
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    sqlx::query("INSERT INTO cves (id) VALUES ('CVE-2024-1086')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/feeds",
            &hdr(&h),
            Some(json!({"type": "cisa_kev"}))
        )
        .await
        .status,
        StatusCode::CREATED
    );

    refresh::refresh_all(&st).await;
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cves").await,
        1,
        "unbekannte KEV-CVE wird nicht importiert"
    );
    let r = call(
        &app,
        Method::GET,
        "/api/v1/cves?releases=all",
        &hdr(&h),
        None,
    )
    .await;
    assert_eq!(r.json[0]["exploited"], true);
    let list = feeds(&app, &h).await;
    assert_eq!(feed(&list, "cisa_kev")["state"], "ok");

    // Ausfall: weder "ok" noch gesund, Fehler sichtbar, alter Stand bleibt.
    mock.lock().unwrap().kev_status = Some(500);
    refresh::refresh_all(&st).await;
    let list = feeds(&app, &h).await;
    let k = feed(&list, "cisa_kev");
    assert_eq!(
        (k["state"].as_str(), k["healthy"].as_bool()),
        (Some("stale"), Some(false))
    );
    assert!(k["last_error"].as_str().unwrap().contains("500"));
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE source = 'cisa_kev'"
        )
        .await,
        1
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn disabled_source_is_not_fetched_not_green_and_ignored_in_evaluation(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-10001",
        Utc::now(),
        &[("noble", "needed", "")],
    )];
    refresh::refresh_all(&st).await;
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(feed(&feeds(&app, &h).await, "ubuntu")["state"], "ok");

    // Abschalten: nicht mehr abgerufen, nie "ok", Daten der Quelle zählen in der Bewertung nicht mehr.
    let r = call(
        &app,
        Method::PUT,
        "/api/v1/feeds/ubuntu",
        &hdr(&h),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let list = feeds(&app, &h).await;
    let u = feed(&list, "ubuntu");
    assert_eq!(
        (
            u["state"].as_str(),
            u["healthy"].as_bool(),
            u["enabled"].as_bool()
        ),
        (Some("disabled"), Some(false), Some(false))
    );
    let before = mock.lock().unwrap().log.len();
    assert!(refresh::refresh_all(&st).await.is_empty());
    assert_eq!(
        mock.lock().unwrap().log.len(),
        before,
        "abgeschaltete Quelle wird nicht abgerufen"
    );
    // Neubewertung läuft im Hintergrund; hier synchron anstoßen.
    patchwatch_server::cve::reeval::reevaluate_all(&st)
        .await
        .unwrap();
    let status = cve_status(&pool, hid, "CVE-2026-10001").await;
    assert!(
        status.as_deref() != Some("vulnerable") && status.as_deref() != Some("fixed"),
        "ohne aktive Quelle kein belastbarer Stand, war: {status:?}"
    );

    // Wieder einschalten: Daten gelten wieder.
    call(
        &app,
        Method::PUT,
        "/api/v1/feeds/ubuntu",
        &hdr(&h),
        Some(json!({"enabled": true})),
    )
    .await;
    patchwatch_server::cve::reeval::reevaluate_all(&st)
        .await
        .unwrap();
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("vulnerable")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn source_management_validates_input_and_ssrf(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu", "debian"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let post = |body: Value| {
        let (app, h) = (app.clone(), h.clone());
        async move {
            call(&app, Method::POST, "/api/v1/feeds", &hdr(&h), Some(body))
                .await
                .status
        }
    };
    // Nur bekannte Typen, keine freien URLs.
    assert_eq!(post(json!({"type": "evil"})).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        post(json!({"type": "osv", "url": "http://x"})).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Spiegel-URL geht durch die SSRF-Prüfung: Loopback, Link-Local, Metadaten, Zugangsdaten in der URL.
    for bad in [
        "http://127.0.0.1:8080/",
        "http://169.254.169.254/latest",
        "http://[::1]/",
        "http://user:pw@example.com/",
        "ftp://example.com/",
        "http://localhost/",
    ] {
        assert_eq!(
            post(json!({"type": "osv", "base_url": bad})).await,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    // Schlüssel nur dort, wo es einen gibt; keine Steuerzeichen; nicht für Debian/Ubuntu-Tracker-URLs.
    assert_eq!(
        post(json!({"type": "osv", "secret": "x"})).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(json!({"type": "nvd", "secret": "a\nb"})).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            Method::PUT,
            "/api/v1/feeds/debian",
            &hdr(&h),
            Some(json!({"base_url": "https://example.com/"}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    // Doppelt (gleicher Name bzw. gleiche Konfiguration), unbekannt.
    assert_eq!(post(json!({"type": "osv"})).await, StatusCode::CREATED);
    assert_eq!(post(json!({"type": "osv"})).await, StatusCode::CONFLICT);
    assert_eq!(
        post(json!({"type": "osv", "label": "Zweite"})).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            Method::PUT,
            "/api/v1/feeds/gibtsnicht",
            &hdr(&h),
            Some(json!({"enabled": false}))
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let osv_id = feed(&feeds(&app, &h).await, "osv")["source"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(
            &app,
            Method::DELETE,
            &format!("/api/v1/feeds/{osv_id}"),
            &hdr(&h),
            None
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert!(feeds(&app, &h).await.iter().all(|f| f["type"] != "osv"));
    // Zweites Löschen: die Quelle ist weg.
    assert_eq!(
        call(
            &app,
            Method::DELETE,
            &format!("/api/v1/feeds/{osv_id}"),
            &hdr(&h),
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    // Ohne Sitzung/CSRF geht nichts.
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/v1/feeds",
            &[],
            Some(json!({"type": "nvd"}))
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    // Ohne Schlüssel in der Konfiguration lässt sich kein Geheimnis speichern.
    let st2 = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let app2 = patchwatch_server::router(st2);
    let r = call(
        &app2,
        Method::POST,
        "/api/v1/feeds",
        &hdr(&h),
        Some(json!({"type": "nvd", "secret": "x"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn deleting_a_default_source_makes_hosts_unknown_and_readding_restores_them(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-10001",
        Utc::now(),
        &[("noble", "needed", "")],
    )];
    refresh::refresh_all(&st).await;
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");

    // Löschen (Ubuntu ist eine Standardquelle): die Quelle verschwindet, der Host ist nie "grün".
    let r = call(&app, Method::DELETE, "/api/v1/feeds/ubuntu", &hdr(&h), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    patchwatch_server::cve::reeval::reevaluate_all(&st)
        .await
        .unwrap();
    assert!(feeds(&app, &h).await.iter().all(|f| f["type"] != "ubuntu"));
    assert_eq!(
        host_status(&pool, hid).await,
        "cve_unknown",
        "ohne aktive Quelle: CVE-Lage unbekannt"
    );
    assert_ne!(
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("vulnerable")
    );
    // Die Daten bleiben liegen (30 Tage), zählen aber nicht; ein Neustart legt die Quelle nicht wieder an.
    assert!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE source = 'ubuntu'"
        )
        .await
            > 0
    );
    assert!(refresh::refresh_all(&st).await.is_empty());
    assert!(feeds(&app, &h).await.iter().all(|f| f["type"] != "ubuntu"));

    // Wieder hinzufügen: nach dem nächsten Abruf kommt der Stand zurück.
    let r = call(
        &app,
        Method::POST,
        "/api/v1/feeds",
        &hdr(&h),
        Some(json!({"type": "ubuntu"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    assert!(r.json["id"].as_str().unwrap().starts_with("ubuntu-"));
    refresh::refresh_all(&st).await;
    patchwatch_server::cve::reeval::reevaluate_all(&st)
        .await
        .unwrap();
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");

    // Nach 30 Tagen räumt der Cleanup die Daten einer gelöschten Quelle weg.
    sqlx::query("INSERT INTO cve_sources (id, kind, label, deleted_at) VALUES ('debian', 'debian', 'Debian', now() - interval '31 days')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cves (id) VALUES ('CVE-2026-20001')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cve_source_status (cve_id, source, release, package, status, source_id) VALUES ('CVE-2026-20001', 'debian', 'trixie', 'linux', 'vulnerable', 'debian')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        patchwatch_server::cve::sources::purge_deleted(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE source_id = 'debian'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_sources WHERE id = 'debian'"
        )
        .await,
        0
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_create_stores_nothing_and_errors_are_concrete(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu", "debian"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    feeds(&app, &h).await; // seeds the defaults
    let before = count(&pool, "SELECT count(*) FROM cve_sources").await;
    let post = |body: Value| {
        let (app, h) = (app.clone(), h.clone());
        async move { call(&app, Method::POST, "/api/v1/feeds", &hdr(&h), Some(body)).await }
    };

    // Reproduktion des gemeldeten Falls: eine normale Webseite ist kein Feed. Konkreter Fehler, nichts angelegt.
    let r = post(
        json!({"type": "osv", "label": "Test", "base_url": "https://ubuntu.com/security/cves"}),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.json["error"]
            .as_str()
            .unwrap()
            .contains("Webseite von Ubuntu"),
        "{}",
        r.json
    );
    assert!(r.json["error"].as_str().unwrap().contains("Typ „Ubuntu“"));
    let r = post(json!({"type": "ubuntu", "label": "Ubuntu 2", "base_url": "https://ubuntu.com/security/cves"})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        r.json["error"].as_str().unwrap().contains("Webseite"),
        "{}",
        r.json
    );
    let r = post(json!({"type": "nvd", "label": "N", "base_url": "https://security-tracker.debian.org/tracker/"})).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.json["error"].as_str().unwrap().contains("Debian"));
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cve_sources").await,
        before,
        "ein Fehler legt nichts an"
    );

    // Name: 1–40 Zeichen, keine Steuerzeichen.
    for bad in ["", "   ", "a\nb", "a\u{0}b", &"x".repeat(41)] {
        let r = post(json!({"type": "osv", "label": bad})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cve_sources").await,
        before
    );

    // Mehrere Quellen desselben Typs mit unterschiedlicher Konfiguration; Name und Konfiguration sind eindeutig.
    let r = post(json!({"type": "osv", "label": "OSV Debian", "ecosystem": "Debian:13"})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    let r = post(json!({"type": "osv", "label": "OSV Ubuntu", "ecosystem": "Ubuntu:24.04"})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    let r = post(json!({"type": "osv", "label": "osv debian", "ecosystem": "Debian:12"})).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.json["error"], "Name bereits vergeben");
    let r = post(json!({"type": "osv", "label": "Noch eine", "ecosystem": "Debian:13"})).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(r.json["error"].as_str().unwrap().contains("Konfiguration"));
    for bad in ["Debian 13; DROP", "x".repeat(41).as_str(), "<b>"] {
        assert_eq!(
            post(json!({"type": "osv", "label": "E", "ecosystem": bad}))
                .await
                .status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    assert_eq!(
        post(json!({"type": "debian", "label": "D2", "ecosystem": "Debian:13"}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // Doppelklick: zwei gleichzeitige Anfragen erzeugen genau eine Quelle.
    let (a, b) = tokio::join!(
        post(json!({"type": "cisa_kev", "label": "KEV"})),
        post(json!({"type": "cisa_kev", "label": "KEV"}))
    );
    let mut codes = [a.status.as_u16(), b.status.as_u16()];
    codes.sort_unstable();
    assert_eq!(codes, [201, 409]);
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_sources WHERE kind = 'cisa_kev'"
        )
        .await,
        1
    );

    // Sonderzeichen und HTML im Namen werden unverändert gespeichert und nur als JSON-Text ausgeliefert (das UI escaped sie).
    let evil = "<img src=x onerror=alert(1)>&\"q\"'${x}";
    let r = post(json!({"type": "nvd", "label": evil, "secret": "geheim-123"})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.json);
    let id = r.json["id"].as_str().unwrap().to_owned();
    let list = feeds(&app, &h).await;
    assert_eq!(
        list.iter().find(|f| f["source"] == id.as_str()).unwrap()["label"],
        evil
    );

    // Umbenennen: die stabile ID bleibt, das Geheimnis bleibt entschlüsselbar (AAD = ID, nicht Name).
    let r = call(
        &app,
        Method::PUT,
        &format!("/api/v1/feeds/{id}"),
        &hdr(&h),
        Some(json!({"label": "Mein NVD"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let blob: Vec<u8> = sqlx::query_scalar("SELECT secret FROM cve_sources WHERE id = $1")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let key = st.cfg.secret_key.as_ref().unwrap();
    assert_eq!(
        patchwatch_server::notify::crypto::decrypt(key.bytes(), &format!("cve_source:{id}"), &blob)
            .unwrap(),
        "geheim-123"
    );
    let r = call(
        &app,
        Method::PUT,
        &format!("/api/v1/feeds/{id}"),
        &hdr(&h),
        Some(json!({"label": "OSV Debian"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
}

#[sqlx::test(migrations = false)]
async fn migration_0005_keeps_existing_sources_data_and_secrets(pool: PgPool) {
    for sql in [
        include_str!("../migrations/0001_init.sql"),
        include_str!("../migrations/0002_ui_v2.sql"),
        include_str!("../migrations/0003_cve_sources.sql"),
        include_str!("../migrations/0004_channels.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }
    // Bestand vor der Migration: Quellen mit altem Namen als Schlüssel, ein verschlüsselter NVD-Schlüssel,
    // Zeilen, Feed-Zustand und ein Intervall.
    let key = [7u8; 32];
    let blob =
        patchwatch_server::notify::crypto::encrypt(&key, "cve_source:nvd", "alter-schluessel")
            .unwrap();
    for name in ["debian", "ubuntu"] {
        sqlx::query("INSERT INTO cve_sources (name) VALUES ($1)")
            .bind(name)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO cve_sources (name, enabled, base_url, secret) VALUES ('nvd', false, 'https://nvd.example.org', $1)")
        .bind(&blob)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cves (id) VALUES ('CVE-2026-1')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cve_source_status (cve_id, source, release, package, status) VALUES ('CVE-2026-1', 'debian', 'trixie', 'linux', 'fixed')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO feed_state (source, last_success_at) VALUES ('debian', now())")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO settings (key, value) VALUES ('schedule.feeds.interval_minutes.nvd', '30'::jsonb)")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::raw_sql(include_str!("../migrations/0005_cve_source_names.sql"))
        .execute(&pool)
        .await
        .unwrap();

    // IDs, Typen und Namen: nichts verloren, Zustand (aus/URL) unverändert.
    let rows: Vec<(String, String, String, bool, Option<String>)> =
        sqlx::query_as("SELECT id, kind, label, enabled, base_url FROM cve_sources ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![
            (
                "debian".into(),
                "debian".into(),
                "Debian".into(),
                true,
                None
            ),
            (
                "nvd".into(),
                "nvd".into(),
                "NVD".into(),
                false,
                Some("https://nvd.example.org".into())
            ),
            (
                "ubuntu".into(),
                "ubuntu".into(),
                "Ubuntu".into(),
                true,
                None
            ),
        ]
    );
    // Verweise laufen über die ID und bleiben gültig: Zeilen, Feed-Zustand, Intervall.
    let sid: String =
        sqlx::query_scalar("SELECT source_id FROM cve_source_status WHERE cve_id = 'CVE-2026-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sid, "debian");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM feed_state WHERE source = 'debian'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM settings WHERE key = 'schedule.feeds.interval_minutes.nvd'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    // Die AAD des Geheimnisses (`cve_source:<id>`) ist für bestehende Quellen identisch: es muss nichts neu verschlüsselt werden.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT secret FROM cve_sources WHERE id = 'nvd'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        patchwatch_server::notify::crypto::decrypt(&key, "cve_source:nvd", &stored).unwrap(),
        "alter-schluessel"
    );
    // Neue Regeln gelten sofort: eindeutiger Name, ungültiger Typ abgelehnt.
    assert!(sqlx::query(
        "INSERT INTO cve_sources (id, kind, label) VALUES ('x1', 'osv', 'debian')"
    )
    .execute(&pool)
    .await
    .is_err());
    assert!(
        sqlx::query("INSERT INTO cve_sources (id, kind, label) VALUES ('x2', 'evil', 'E')")
            .execute(&pool)
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn list_shortens_descriptions_and_search_finds_ids_and_text(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let long = format!("Pufferueberlauf {}", "x".repeat(990));
    sqlx::query("INSERT INTO cves (id, description) VALUES ('CVE-2026-77701', $1), ('CVE-2026-77702', 'kurz')")
        .bind(&long)
        .execute(&pool)
        .await
        .unwrap();

    let list = call(
        &app,
        Method::GET,
        "/api/v1/cves?q=cve-2026-777",
        &hdr(&h),
        None,
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    let rows = list.json.as_array().unwrap();
    assert_eq!(
        rows.len(),
        2,
        "ID-Suche (auch in Kleinbuchstaben und als Teil) findet beide"
    );
    let long_row = rows.iter().find(|r| r["id"] == "CVE-2026-77701").unwrap();
    assert_eq!(
        long_row["description"].as_str().unwrap().chars().count(),
        300,
        "Liste kürzt die Beschreibung"
    );

    let detail = call(
        &app,
        Method::GET,
        "/api/v1/cves/CVE-2026-77701",
        &hdr(&h),
        None,
    )
    .await;
    assert_eq!(
        detail.json["cve"]["description"].as_str().unwrap(),
        long,
        "Detail liefert die volle Beschreibung"
    );

    // Volltext: Treffer in der Beschreibung, Zähler und Watchlist bleiben je Zeile korrekt.
    let text = call(
        &app,
        Method::GET,
        "/api/v1/cves?q=Pufferueberlauf&limit=5",
        &hdr(&h),
        None,
    )
    .await;
    assert_eq!(text.json.as_array().unwrap().len(), 1);
    assert_eq!(text.json[0]["hosts_vulnerable"], 0);
    // LIKE-Metazeichen und SQL-Anführungszeichen in der Suche bleiben Text.
    let evil = call(
        &app,
        Method::GET,
        "/api/v1/cves?q=%25%27%3B--",
        &hdr(&h),
        None,
    )
    .await;
    assert_eq!(evil.status, StatusCode::OK);
    assert!(evil.json.as_array().unwrap().is_empty());
}

/// Regression: der Distributions-Chip zeigte "verwundbar", weil ein Paket, das der Host nicht nutzt (linux-nvidia),
/// den Release rot färbte, obwohl die Bewertung des Hosts auf `linux` ("Fix angekündigt") beruht.
#[sqlx::test(migrations = "./migrations")]
async fn distro_chip_only_counts_packages_the_hosts_use(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let host = add_host(&pool, "res-01").await;
    sqlx::query("UPDATE hosts SET os_codename = 'resolute' WHERE id = $1")
        .bind(host)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cves (id, description) VALUES ('CVE-2026-77801', 'x')")
        .execute(&pool)
        .await
        .unwrap();
    for (pkg, status, fix) in [
        ("linux", "fix_pending", Some("7.0.0-43.43")),
        ("linux-nvidia", "vulnerable", None),
    ] {
        sqlx::query(
            "INSERT INTO cve_source_status (cve_id, source, release, package, status, fix_version, raw, source_id) \
             VALUES ('CVE-2026-77801', 'ubuntu', 'resolute', $1, $2, $3, '{}', 'ubuntu')",
        )
        .bind(pkg)
        .bind(status)
        .bind(fix)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO host_cve_status (host_id, cve_id, status, reason, sources) VALUES ($1, 'CVE-2026-77801', 'fix_pending', 'r', \
         '[{\"source\":\"ubuntu\",\"release\":\"resolute\",\"package\":\"linux\",\"status\":\"fix_pending\",\"fix_version\":\"7.0.0-43.43\"}]')",
    )
    .bind(host)
    .execute(&pool)
    .await
    .unwrap();

    for path in [
        "/api/v1/cves?q=CVE-2026-77801",
        "/api/v1/cves/CVE-2026-77801",
    ] {
        let r = call(&app, Method::GET, path, &hdr(&h), None).await;
        let distros = if r.json.is_array() {
            &r.json[0]["distros"]
        } else {
            &r.json["distros"]
        };
        let d = distros.as_array().unwrap();
        assert_eq!(d.len(), 1, "{path}");
        assert_eq!(
            d[0]["status"], "fix_pending",
            "{path}: Chip folgt dem Paket des Hosts"
        );
        assert_eq!(d[0]["package"], "linux", "{path}");
    }
}
