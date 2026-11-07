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
    /// Wert des Headers `Retry-After` zur Antwort mit `ubuntu_status`.
    ubuntu_retry_after: Option<String>,
    /// Antwort kommt nie (hängende Quelle).
    ubuntu_hang: bool,
    /// Seite ab diesem Offset bricht mitten im Body ab (Verbindungsabbruch).
    ubuntu_drop_offset: Option<usize>,
    ubuntu_garbage: bool,
    /// Hybridtests: Seiten (limit, offset) in Reihenfolge der Anfragen; Antworten mit `limit` über der Grenze
    /// schlagen mit 503 bzw. 422 fehl.
    pages: Vec<(usize, usize)>,
    ubuntu_503_above: Option<usize>,
    ubuntu_422_above: Option<usize>,
    /// OVAL-Dateien je Release (Dateiname `com.ubuntu.<release>.cve.oval.xml.bz2`).
    oval: HashMap<String, OvalFile>,
    user_agents: Vec<String>,
    /// Seite ab diesem Offset antwortet mit HTTP 500 (Netz-/Serverfehler mitten im Lauf).
    ubuntu_fail_offset: Option<usize>,
    debian_body: String,
    debian_status: Option<u16>,
    osv_body: Value,
    kev_body: Value,
    kev_status: Option<u16>,
    log: Vec<String>,
}

#[derive(Clone, Default)]
struct OvalFile {
    body: Vec<u8>,
    etag: String,
    /// Ersetzt die Antwort durch diesen Statuscode (z. B. 503) samt `Retry-After`.
    status: Option<u16>,
    retry_after: Option<String>,
    /// Körper bricht nach so vielen Bytes ab (Verbindungsabbruch bei angekündigter Länge).
    cut_at: Option<usize>,
}

type Shared = Arc<Mutex<Mock>>;

/// Statische Dateien der Massendaten mit `ETag`/`If-None-Match` (304 bei unverändertem Stand).
async fn oval_file(
    State(m): State<Shared>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let mut g = m.lock().unwrap();
    let inm = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    g.log.push(format!(
        "oval {name}{}",
        if inm.is_some() { " conditional" } else { "" }
    ));
    let Some(f) = g.oval.get(&name).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(code) = f.status {
        let mut r = StatusCode::from_u16(code).unwrap().into_response();
        if let Some(v) = &f.retry_after {
            r.headers_mut()
                .insert(header::RETRY_AFTER, v.parse().unwrap());
        }
        return r;
    }
    if inm.as_deref() == Some(f.etag.as_str()) {
        return Response::builder().status(304).body(Body::empty()).unwrap();
    }
    let len = f.body.len();
    let body = match f.cut_at {
        Some(n) => {
            let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![
                Ok(f.body[..n].to_vec()),
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "abgerissen",
                )),
            ];
            Body::from_stream(futures_util::stream::iter(chunks))
        }
        None => Body::from(f.body),
    };
    Response::builder()
        .header(header::CONTENT_LENGTH, len.to_string())
        .header(header::ETAG, f.etag)
        .header(header::LAST_MODIFIED, "Thu, 05 Nov 2026 22:44:49 GMT")
        .body(body)
        .unwrap()
}

async fn ubuntu_list(
    State(m): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Some(ua) = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
    {
        m.lock().unwrap().user_agents.push(ua.to_owned());
    }
    let hang = m.lock().unwrap().ubuntu_hang;
    if hang {
        m.lock().unwrap().log.push("ubuntu hang".into());
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
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
    m.pages.push((limit, offset));
    if m.ubuntu_422_above.is_some_and(|max| limit > max) {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    if m.ubuntu_503_above.is_some_and(|max| limit > max) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if let Some(code) = m.ubuntu_status {
        let mut r = StatusCode::from_u16(code).unwrap().into_response();
        if let Some(v) = &m.ubuntu_retry_after {
            r.headers_mut()
                .insert(header::RETRY_AFTER, v.parse().unwrap());
        }
        return r;
    }
    if m.ubuntu_drop_offset == Some(offset) {
        // Verspricht 1 MB, liefert ein paar Bytes und reißt dann die Verbindung ab.
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![
            Ok(b"{\"cves\": [".to_vec()),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "abgerissen",
            )),
        ];
        return Response::builder()
            .header(header::CONTENT_LENGTH, "1048576")
            .body(Body::from_stream(futures_util::stream::iter(chunks)))
            .unwrap();
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
        .route("/oval/{name}", get(oval_file))
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
         retries = 1\nretry_base_delay_ms = 10\nrequest_timeout_secs = 10\nubuntu_page_pause_ms = 0\nubuntu_mode = \"api\"\n{extra_toml}\n\
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
        cve_status(&pool, hid, "CVE-2026-10001").await.as_deref(),
        Some("fixed"),
        "behobene CVEs werden als gefixt gespeichert (Host-Ansicht), sind aber kein Handlungsbedarf"
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
/// "ok", der Cursor fehlt bis zum Schluss, die Anzeige nennt "Erstabruf läuft: Seite N von etwa M".
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
                    text.starts_with("Erstabruf läuft: Seite ")
                        && text.contains(" von etwa 7 (Schätzung)"),
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

/// Fund (niedrig): Feed-Abrufe sind über Instanzen hinweg gesperrt. Hält eine andere Instanz (hier: eine zweite
/// Verbindung mit demselben Sperrschlüssel) die Sperre, wird der Lauf ausgelassen und es geht keine Anfrage raus.
#[sqlx::test(migrations = "./migrations")]
async fn low_feed_fetch_is_locked_across_instances(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_keyed(pool.clone(), &["ubuntu"], &base).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 5, Utc::now() - Duration::hours(1));

    // "Andere Instanz": eine zweite Verbindung hält die Sperre dieser Quelle (Sitzungssperren sind je Verbindung).
    let mut other = pool.acquire().await.unwrap();
    let got: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_lock(hashtextextended('patchwatch.feed:ubuntu', 0))",
    )
    .fetch_one(&mut *other)
    .await
    .unwrap();
    assert!(got);

    let out = refresh::refresh_all(&st).await;
    assert_eq!(out[0].1, Outcome::Skipped);
    assert!(
        mock.lock().unwrap().log.is_empty(),
        "keine Anfrage bei gehaltener Sperre"
    );
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 0);

    // Sperre frei: der nächste Lauf holt die Daten, und danach ist die Sperre wieder frei (kein Hängenbleiben).
    sqlx::query("SELECT pg_advisory_unlock(hashtextextended('patchwatch.feed:ubuntu', 0))")
        .execute(&mut *other)
        .await
        .unwrap();
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 5);
    let free: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_lock(hashtextextended('patchwatch.feed:ubuntu', 0))",
    )
    .fetch_one(&mut *other)
    .await
    .unwrap();
    assert!(free, "Sperre wurde nach dem Lauf freigegeben");
}

/// Bewertungsregel (eval.rs, seit fd5ed39): Ein nur angekündigter Fix ("pending") lässt den Host verwundbar, nicht
/// "Fix angekündigt". Wirkt auf Host-Status, Host-Liste, CVE-Liste (Fix-Filter) und die Begründung.
#[sqlx::test(migrations = "./migrations")]
async fn rule_announced_fix_counts_as_vulnerable_everywhere(pool: PgPool) {
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
        "CVE-2026-50001",
        Utc::now() - Duration::minutes(5),
        &[("noble", "pending", "6.8.0-99.99")],
    )];
    refresh::refresh_all(&st).await;

    // Host-Status und Bewertung: verwundbar, Begründung nennt "Fix in Arbeit" und die erwartete Version.
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-50001").await.as_deref(),
        Some("vulnerable")
    );
    let reason: String = sqlx::query_scalar(
        "SELECT reason FROM host_cve_status WHERE host_id = $1 AND cve_id = 'CVE-2026-50001'",
    )
    .bind(hid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        reason.contains("verwundbar, Fix in Arbeit") && reason.contains("6.8.0-99.99"),
        "{reason}"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM host_cve_status WHERE status = 'fix_pending'"
        )
        .await,
        0
    );
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");

    // Host-Liste: als verwundbar gezählt, nie als "Fix angekündigt".
    let r = call(&app, Method::GET, "/api/v1/hosts", &hdr(&h), None).await;
    assert_eq!(r.json[0]["cve_vulnerable"], 1);
    assert_eq!(r.json[0]["cve_fix_pending"], 0);
    // CVE-Liste: Host-Zähler und Fix-Filter "offen" (verwundbar oder angekündigt).
    let r = call(
        &app,
        Method::GET,
        "/api/v1/cves?affects=all&releases=all&ubuntu=open",
        &hdr(&h),
        None,
    )
    .await;
    let list = r.json.as_array().unwrap();
    assert_eq!(list.len(), 1, "{}", r.json);
    assert_eq!(list[0]["hosts_vulnerable"], 1);
    assert_eq!(list[0]["hosts_fix_pending"], 0);
    let r = call(
        &app,
        Method::GET,
        "/api/v1/cves?affects=all&releases=all&ubuntu=fixed",
        &hdr(&h),
        None,
    )
    .await;
    assert!(
        r.json.as_array().unwrap().is_empty(),
        "angekündigt ist nicht behoben"
    );

    // Der Fix erscheint: dieselbe CVE wird für den Host nicht mehr verwundbar gemeldet, sobald er die Version hat.
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-50001",
        Utc::now(),
        &[("noble", "released", "6.8.0-20.20")],
    )];
    refresh::refresh_all(&st).await;
    assert_ne!(
        cve_status(&pool, hid, "CVE-2026-50001").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(host_status(&pool, hid).await, "ok");
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
    // CVE-2004-0230 ist in trixie "open" -> verwundbar; CVE-2024-1086 (fixed in 6.6.15-1) ist behoben und als gefixt gespeichert.
    assert_eq!(
        cve_status(&pool, hid, "CVE-2004-0230").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2024-1086").await.as_deref(),
        Some("fixed")
    );
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
    assert!(list.json["items"][0]["reviewed_at"].is_string());

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
         nvd_url = \"{base}/nvd\"\nkev_url = \"{base}/kev\"\nretries = 1\nretry_base_delay_ms = 10\nrequest_timeout_secs = 10\nubuntu_page_pause_ms = 0\nubuntu_mode = \"api\"\n{extra}\n"
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
        "/api/v1/cves?affects=all&releases=all",
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

// ---------- Ubuntu-Feed bei Drosselung/Ausfall: Backoff, Wiederaufnahme, Anzeige ----------

/// Konfiguration mit frei wählbaren Wiederholungen, Timeouts, Seitenpause und Watchdog (nur der Ubuntu-Feed).
async fn setup_cfg(
    pool: PgPool,
    base: &str,
    retries: u32,
    timeout_secs: u64,
    stall_secs: u64,
    pause_ms: u64,
) -> AppState {
    let toml = format!(
        "[cve]\nsources = [\"ubuntu\"]\nubuntu_url = \"{base}\"\nretries = {retries}\nretry_base_delay_ms = 10\n\
         request_timeout_secs = {timeout_secs}\nstall_timeout_secs = {stall_secs}\nubuntu_page_pause_ms = {pause_ms}\nubuntu_mode = \"api\"\n\
         [ntfy]\nurl = \"http://127.0.0.1:9\"\ntopic = \"t\"\n"
    );
    AppState::new(pool, Config::from_sources(Some(&toml), &|_| None).unwrap()).unwrap()
}

async fn retry_state(pool: &PgPool) -> (i32, Option<chrono::DateTime<Utc>>) {
    sqlx::query_as("SELECT retry_step, next_attempt_at FROM feed_state WHERE source = 'ubuntu'")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn minutes_until(t: Option<chrono::DateTime<Utc>>) -> Option<f64> {
    t.map(|t| (t - Utc::now()).num_milliseconds() as f64 / 60_000.0)
}

fn attempts(mock: &Shared, what: &str) -> usize {
    mock.lock()
        .unwrap()
        .log
        .iter()
        .filter(|l| l.as_str() == what)
        .count()
}

/// 503 ohne Retry-After: drei Versuche je Seite, dann endet der Lauf sauber. Die Wartezeit bis zum nächsten Lauf
/// wächst (2, 5, 10, 30 Minuten, danach normales Intervall); der Feed ist dabei nie grün; ein Erfolg setzt alles zurück.
#[sqlx::test(migrations = "./migrations")]
async fn retry_503_three_attempts_then_ladder_grows_and_success_resets(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 3, 10, 600, 0).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 15, Utc::now() - Duration::hours(1));
        m.ubuntu_status = Some(503);
    }
    let expect = [Some(2.0), Some(5.0), Some(10.0), Some(30.0), None, None];
    for (i, want) in expect.iter().enumerate() {
        mock.lock().unwrap().log.clear();
        let out = refresh::refresh_all(&st).await;
        assert!(
            matches!(&out[0].1, Outcome::Failed(m) if m == "HTTP 503"),
            "{:?}",
            out[0].1
        );
        assert_eq!(attempts(&mock, "ubuntu offset=0"), 3, "3 Versuche je Seite");
        let (step, next) = retry_state(&pool).await;
        assert_eq!(step, i as i32 + 1);
        match (want, minutes_until(next)) {
            (Some(w), Some(got)) => assert!(
                (got - w).abs() < 0.2,
                "Lauf {}: {got} Min. statt {w}",
                i + 1
            ),
            (None, None) => {}
            (w, g) => panic!("Lauf {}: erwartet {w:?}, war {g:?}", i + 1),
        }
        let f = ubuntu_feed(&app, &h).await;
        assert_ne!(f["state"], "ok");
        assert_eq!(f["failed_runs"], i as i32 + 1);
        let text = f["error_text"].as_str().unwrap();
        assert!(text.starts_with("Ubuntu meldet 503"), "{text}");
        if want.is_some() {
            assert!(text.contains("nächster Versuch in"), "{text}");
        }
    }
    // Quelle erholt sich: Erfolg setzt Leiter und Fehlertext zurück, der Feed wird erst jetzt grün.
    mock.lock().unwrap().ubuntu_status = None;
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(retry_state(&pool).await, (0, None));
    let f = ubuntu_feed(&app, &h).await;
    assert_eq!(f["state"], "ok");
    assert!(f["error_text"].is_null() && f["last_error"].is_null());
    assert_eq!(f["failed_runs"], 0);
}

/// 429 wird wie eine Drosselung behandelt (Wiederholung, Leiter, verständlicher Text).
#[sqlx::test(migrations = "./migrations")]
async fn retry_429_is_throttling_with_plain_text(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 2, 10, 600, 0).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 5, Utc::now());
        m.ubuntu_status = Some(429);
    }
    let out = refresh::refresh_all(&st).await;
    assert!(matches!(&out[0].1, Outcome::Failed(m) if m == "HTTP 429"));
    assert_eq!(attempts(&mock, "ubuntu offset=0"), 2);
    let text = ubuntu_feed(&app, &h).await["error_text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(text.starts_with("Ubuntu drosselt (429"), "{text}");
}

/// Retry-After in Sekunden bestimmt die Pause innerhalb des Laufs (statt des kurzen Backoffs).
#[sqlx::test(migrations = "./migrations")]
async fn retry_after_seconds_is_honoured_within_the_run(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 2, 10, 600, 0).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 5, Utc::now());
        m.ubuntu_status = Some(503);
        m.ubuntu_retry_after = Some("1".into());
    }
    let t = std::time::Instant::now();
    let out = refresh::refresh_all(&st).await;
    assert!(matches!(out[0].1, Outcome::Failed(_)));
    assert!(
        t.elapsed() >= std::time::Duration::from_millis(950),
        "Pause nur {:?}",
        t.elapsed()
    );
    assert_eq!(attempts(&mock, "ubuntu offset=0"), 2);
}

/// Retry-After als HTTP-Datum wird ebenso beachtet.
#[sqlx::test(migrations = "./migrations")]
async fn retry_after_http_date_is_honoured_within_the_run(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 2, 10, 600, 0).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 5, Utc::now());
        m.ubuntu_status = Some(503);
        m.ubuntu_retry_after = Some(
            (Utc::now() + Duration::seconds(3))
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
        );
    }
    let t = std::time::Instant::now();
    refresh::refresh_all(&st).await;
    // Das Datum hat Sekundenauflösung: zwischen 2 und 3 Sekunden Wartezeit.
    assert!(
        t.elapsed() >= std::time::Duration::from_millis(1800),
        "Pause nur {:?}",
        t.elapsed()
    );
    assert_eq!(attempts(&mock, "ubuntu offset=0"), 2);
}

/// Retry-After verlängert die Wartezeit bis zum nächsten Lauf über die Leiter hinaus, aber höchstens auf 15 Minuten.
#[sqlx::test(migrations = "./migrations")]
async fn retry_after_extends_the_next_attempt_and_is_capped_at_15_minutes(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    // Ein Versuch je Seite: keine Pause im Lauf, der Wunsch der Quelle wirkt nur auf den nächsten Lauf.
    let st = setup_cfg(pool.clone(), &base, 1, 10, 600, 0).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 5, Utc::now());
        m.ubuntu_status = Some(503);
        m.ubuntu_retry_after = Some("600".into());
    }
    refresh::refresh_all(&st).await;
    let got = minutes_until(retry_state(&pool).await.1).unwrap();
    assert!((got - 10.0).abs() < 0.2, "{got}");
    mock.lock().unwrap().ubuntu_retry_after = Some("86400".into());
    refresh::refresh_all(&st).await;
    let got = minutes_until(retry_state(&pool).await.1).unwrap();
    assert!((got - 15.0).abs() < 0.2, "{got}");
}

/// Timeout: eine Quelle, die nicht antwortet, ist ein Fehllauf mit verständlichem Text (kein Hängenbleiben).
#[sqlx::test(migrations = "./migrations")]
async fn retry_timeout_is_a_failed_run(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 1, 1, 600, 0).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 5, Utc::now());
        m.ubuntu_hang = true;
    }
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(&out[0].1, Outcome::Failed(m) if m.starts_with("Netzwerkfehler")),
        "{:?}",
        out[0].1
    );
    let f = ubuntu_feed(&app, &h).await;
    assert!(f["error_text"]
        .as_str()
        .unwrap()
        .starts_with("Verbindung zu Ubuntu fehlgeschlagen"));
    assert_eq!(f["failed_runs"], 1);
}

/// Verbindungsabbruch mitten im Lauf: geladene Seiten bleiben gespeichert, der Feed ist nie grün, die Leiter greift
/// (2 Minuten), und der nächste Lauf setzt bei der gespeicherten Seite fort, nicht bei Seite 1.
#[sqlx::test(migrations = "./migrations")]
async fn retry_connection_drop_midway_resumes_at_stored_page(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 1, 10, 600, 0).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 60, Utc::now() - Duration::hours(1));
        m.ubuntu_drop_offset = Some(20);
    }
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Incomplete { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cves").await,
        20,
        "Seite 1 bleibt gespeichert"
    );
    let f = ubuntu_feed(&app, &h).await;
    assert_eq!(f["state"], "incomplete");
    assert!(f["last_error"]
        .as_str()
        .unwrap()
        .starts_with("Lauf unterbrochen: Netzwerkfehler"));
    let text = f["error_text"].as_str().unwrap();
    assert!(
        text.contains("Lauf unterbrochen") && text.contains("nächster Versuch in"),
        "{text}"
    );
    assert!(f["backfill"]["progress"]
        .as_str()
        .unwrap()
        .contains("Seite 1"));
    let (step, next) = retry_state(&pool).await;
    assert_eq!(step, 1);
    assert!((minutes_until(next).unwrap() - 2.0).abs() < 0.2);

    // Quelle wieder gesund: Fortsetzung bei Offset 20, Abschluss, Leiter zurückgesetzt, jetzt erst grün.
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu_drop_offset = None;
        m.log.clear();
    }
    let out = refresh::refresh_all(&st).await;
    assert_eq!(
        offsets(&mock)[0],
        20,
        "setzt bei der gespeicherten Seite fort"
    );
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(count(&pool, "SELECT count(*) FROM cves").await, 60);
    assert_eq!(retry_state(&pool).await, (0, None));
    let f = ubuntu_feed(&app, &h).await;
    assert_eq!(f["state"], "ok");
    assert!(f["error_text"].is_null() && f["backfill"].is_null());
}

/// Fehllauf nach Fortschritt bei einem Erstabruf: Anzeige "Seite N von etwa M (Schätzung)", Läufe seit Beginn,
/// Zwischenstände sind nie grün.
#[sqlx::test(migrations = "./migrations")]
async fn initial_import_shows_page_estimate_and_never_goes_green_midway(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 1, 10, 600, 0).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 100, Utc::now() - Duration::hours(1));
    mock.lock().unwrap().ubuntu_fail_offset = Some(40);
    refresh::refresh_all(&st).await;
    let f = ubuntu_feed(&app, &h).await;
    assert_eq!(f["state"], "incomplete");
    let p = f["backfill"]["progress"].as_str().unwrap();
    assert!(
        p.starts_with("Erstabruf läuft: Seite 1 von etwa 5 (Schätzung)"),
        "{p}"
    );
    assert!(p.contains("1 Lauf seit Beginn"), "{p}");
    assert!(f["next_attempt_at"].is_string() && f["last_success_at"].is_null());
}

/// Hängender Lauf: meldet die Quelle über die Stall-Zeit hinaus keinen Fortschritt, wird der Lauf abgebrochen, die
/// Sperre ist frei und der nächste Lauf funktioniert.
#[sqlx::test(migrations = "./migrations")]
async fn hung_run_is_released_by_the_watchdog(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    // Anfrage-Timeout bewusst lang: nur der Watchdog kann diesen Lauf beenden.
    let st = setup_cfg(pool.clone(), &base, 1, 120, 1, 0).await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    {
        let mut m = mock.lock().unwrap();
        m.ubuntu = ubuntu_batch(1, 5, Utc::now());
        m.ubuntu_hang = true;
    }
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        refresh::refresh_all(&st),
    )
    .await
    .expect("Watchdog hat den Lauf nicht beendet");
    assert!(
        matches!(&out[0].1, Outcome::Failed(m) if m.contains("ohne Fortschritt")),
        "{:?}",
        out[0].1
    );
    let f = ubuntu_feed(&app, &h).await;
    assert!(f["error_text"]
        .as_str()
        .unwrap()
        .contains("hing und wurde abgebrochen"));
    assert_eq!(f["failed_runs"], 1);
    // Sperre freigegeben: der nächste Lauf läuft und schließt ab.
    mock.lock().unwrap().ubuntu_hang = false;
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    assert_eq!(ubuntu_feed(&app, &h).await["state"], "ok");
}

/// Höflichkeit: eine Anfrage nach der anderen mit Pause dazwischen, und ein User-Agent mit Projektname.
#[sqlx::test(migrations = "./migrations")]
async fn pages_are_paced_and_requests_identify_the_project(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup_cfg(pool.clone(), &base, 1, 10, 600, 300).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 60, Utc::now() - Duration::hours(1));
    let t = std::time::Instant::now();
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    // 3 Seiten: zwei Pausen zu je 300 ms.
    assert!(
        t.elapsed() >= std::time::Duration::from_millis(600),
        "{:?}",
        t.elapsed()
    );
    let uas = mock.lock().unwrap().user_agents.clone();
    assert!(!uas.is_empty());
    assert!(
        uas.iter()
            .all(|u| u.starts_with("patchwatch-server/")
                && u.contains("github.com/EinNiki/patchwatch")),
        "{uas:?}"
    );
}

// ---------- CVE-Liste: Filter "gefixt/offen" und Anzeige benutzen dieselben Chips ----------

struct FilterEnv {
    app: Router,
    h: Vec<(String, String)>,
    pool: PgPool,
}

async fn filter_env(pool: PgPool) -> FilterEnv {
    let st = setup(
        pool.clone(),
        &["debian", "ubuntu"],
        "",
        "http://127.0.0.1:9",
    )
    .await;
    let app = patchwatch_server::router(st);
    let h = login(&app, &pool).await;
    // Zwei Hosts: Debian trixie und Ubuntu noble.
    for (name, code) in [("deb1", "trixie"), ("ubu1", "noble")] {
        let id = add_host(&pool, name).await;
        sqlx::query("UPDATE hosts SET os_codename = $2 WHERE id = $1")
            .bind(id)
            .bind(code)
            .execute(&pool)
            .await
            .unwrap();
    }
    FilterEnv { app, h, pool }
}

impl FilterEnv {
    /// Zeile der Quellentabelle (`source_id` ist die stabile ID, `source` der Typ).
    async fn row(&self, cve: &str, source: &str, release: &str, package: &str, status: &str) {
        self.row_id(cve, source, source, release, package, status)
            .await;
    }

    async fn row_id(
        &self,
        cve: &str,
        source: &str,
        source_id: &str,
        release: &str,
        package: &str,
        status: &str,
    ) {
        sqlx::query("INSERT INTO cves (id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(cve)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO cve_source_status (cve_id, source, release, package, status, source_id) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(cve)
            .bind(source)
            .bind(release)
            .bind(package)
            .bind(status)
            .bind(source_id)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// Bewertung eines Hosts, die sich auf dieses Paket stützt.
    async fn host_uses(
        &self,
        host: &str,
        cve: &str,
        source: &str,
        release: &str,
        package: &str,
        status: &str,
    ) {
        sqlx::query("INSERT INTO host_cve_status (host_id, cve_id, status, reason, sources) SELECT id, $2, $3, 'test', $4 FROM hosts WHERE name = $1")
            .bind(host)
            .bind(cve)
            .bind(status)
            .bind(json!([{"source": source, "release": release, "package": package}]))
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn list(&self, query: &str) -> Vec<Value> {
        let r = call(
            &self.app,
            Method::GET,
            &format!("/api/v1/cves?affects=all&limit=500{query}"),
            &hdr(&self.h),
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{query}");
        r.json.as_array().unwrap().clone()
    }

    async fn ids(&self, query: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .list(query)
            .await
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_owned())
            .collect();
        v.sort();
        v
    }
}

fn chip(c: &Value, source: &str, release: &str) -> Option<String> {
    c["distros"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["source"] == source && d["release"] == release)
        .map(|d| d["status"].as_str().unwrap().to_owned())
}

/// Reale Beobachtung: eine CVE mit zwei gefixten Debian-Releases wird von `debian=fixed` gefunden, wenn eines davon
/// auf einem Host läuft; läuft keines davon auf einem Host, gehört die CVE nur zum Umfang "alle Releases".
#[sqlx::test(migrations = "./migrations")]
async fn filter_debian_fixed_finds_cve_with_two_fixed_releases_by_scope(pool: PgPool) {
    let e = filter_env(pool).await;
    // A: trixie (läuft) und bookworm (läuft nicht) gefixt.
    e.row("CVE-2026-30001", "debian", "trixie", "linux", "fixed")
        .await;
    e.row("CVE-2026-30001", "debian", "bookworm", "linux", "fixed")
        .await;
    // C: nur die Releases ohne eigenen Host sind gefixt, trixie ist verwundbar.
    e.row("CVE-2026-30003", "debian", "trixie", "linux", "vulnerable")
        .await;
    e.row("CVE-2026-30003", "debian", "forky", "linux", "fixed")
        .await;
    e.row("CVE-2026-30003", "debian", "sid", "linux", "fixed")
        .await;
    assert_eq!(e.ids("&debian=fixed").await, ["CVE-2026-30001"]);
    // Umfang "alle": beide Releases ohne eigenen Host zählen, die CVE C ist jetzt dabei.
    assert_eq!(
        e.ids("&debian=fixed&releases=all").await,
        ["CVE-2026-30001", "CVE-2026-30003"]
    );
    // Anzeige im selben Umfang: C zeigt im Standard nur trixie (verwundbar), mit "alle" auch forky und sid gefixt.
    let mine = e.list("&q=CVE-2026-30003").await;
    assert_eq!(
        chip(&mine[0], "debian", "trixie").as_deref(),
        Some("vulnerable")
    );
    assert_eq!(chip(&mine[0], "debian", "forky"), None);
    assert_eq!(mine[0]["hidden_releases"], 2);
    let all = e.list("&q=CVE-2026-30003&releases=all").await;
    assert_eq!(chip(&all[0], "debian", "forky").as_deref(), Some("fixed"));
}

/// Debian gefixt + Ubuntu egal / offen, und eine unpassende Kombination ohne Treffer. UND zwischen den Distros.
#[sqlx::test(migrations = "./migrations")]
async fn filter_combinations_use_and_between_distros(pool: PgPool) {
    let e = filter_env(pool).await;
    e.row("CVE-2026-30001", "debian", "trixie", "linux", "fixed")
        .await;
    e.row("CVE-2026-30001", "ubuntu", "noble", "linux", "fixed")
        .await;
    e.row("CVE-2026-30002", "debian", "trixie", "linux", "fixed")
        .await;
    e.row("CVE-2026-30002", "ubuntu", "noble", "linux", "vulnerable")
        .await;
    e.row("CVE-2026-30006", "debian", "trixie", "linux", "vulnerable")
        .await;
    e.row("CVE-2026-30006", "ubuntu", "noble", "linux", "fix_pending")
        .await;
    // "egal" ist keine Bedingung.
    assert_eq!(
        e.ids("&debian=fixed").await,
        ["CVE-2026-30001", "CVE-2026-30002"]
    );
    assert_eq!(
        e.ids("&debian=fixed&ubuntu=").await,
        ["CVE-2026-30001", "CVE-2026-30002"]
    );
    assert_eq!(e.ids("&debian=fixed&ubuntu=open").await, ["CVE-2026-30002"]);
    assert_eq!(e.ids("&debian=open&ubuntu=open").await, ["CVE-2026-30006"]);
    assert_eq!(
        e.ids("&debian=open&ubuntu=fixed").await,
        Vec::<String>::new()
    );
    // Alt-URL bleibt ein Alias.
    assert_eq!(
        e.ids("&split=debian_fixed_ubuntu_open").await,
        ["CVE-2026-30002"]
    );
}

/// Ein Chip, der "gefixt" zeigt, wird vom Filter "gefixt" gefunden, und ein roter Chip nicht: bei Releases mit eigenem
/// Host zählen nur die Pakete, auf die sich die Bewertung stützt (linux), nicht z. B. linux-nvidia.
#[sqlx::test(migrations = "./migrations")]
async fn filter_and_chip_agree_for_used_packages(pool: PgPool) {
    let e = filter_env(pool).await;
    // D: genutztes Paket gefixt, ein anderes Kernel-Paket verwundbar -> Chip "gefixt".
    e.row("CVE-2026-30004", "ubuntu", "noble", "linux", "fixed")
        .await;
    e.row(
        "CVE-2026-30004",
        "ubuntu",
        "noble",
        "linux-nvidia",
        "vulnerable",
    )
    .await;
    e.host_uses(
        "ubu1",
        "CVE-2026-30004",
        "ubuntu",
        "noble",
        "linux",
        "not_affected",
    )
    .await;
    // E: genutztes Paket verwundbar, ein anderes gefixt -> Chip "verwundbar".
    e.row("CVE-2026-30005", "ubuntu", "noble", "linux", "vulnerable")
        .await;
    e.row("CVE-2026-30005", "ubuntu", "noble", "linux-aws", "fixed")
        .await;
    e.host_uses(
        "ubu1",
        "CVE-2026-30005",
        "ubuntu",
        "noble",
        "linux",
        "vulnerable",
    )
    .await;
    let all = e.list("").await;
    let status = |id: &str| {
        chip(
            all.iter().find(|c| c["id"] == id).unwrap(),
            "ubuntu",
            "noble",
        )
        .unwrap()
    };
    assert_eq!(status("CVE-2026-30004"), "fixed");
    assert_eq!(status("CVE-2026-30005"), "vulnerable");
    assert_eq!(e.ids("&ubuntu=fixed").await, ["CVE-2026-30004"]);
    assert_eq!(e.ids("&ubuntu=open").await, ["CVE-2026-30005"]);
}

/// Anzeige und Filter liefern für jede Kombination dieselbe CVE-Liste (Filter = Chips der Anzeige).
#[sqlx::test(migrations = "./migrations")]
async fn filter_result_equals_list_of_cves_whose_chips_match(pool: PgPool) {
    let e = filter_env(pool).await;
    let cases = [
        ("CVE-2026-31001", "fixed", "fixed", "vulnerable"),
        ("CVE-2026-31002", "vulnerable", "fixed", "fixed"),
        ("CVE-2026-31003", "fix_pending", "vulnerable", "fixed"),
        ("CVE-2026-31004", "unknown", "not_affected", "fix_pending"),
        ("CVE-2026-31005", "fixed", "fixed", "fixed"),
    ];
    for (id, trixie, bookworm, noble) in cases {
        e.row(id, "debian", "trixie", "linux", trixie).await;
        e.row(id, "debian", "bookworm", "linux", bookworm).await;
        e.row(id, "ubuntu", "noble", "linux", noble).await;
    }
    // Mehrere Pakete je Release, wobei der Host nur eines nutzt: Chip und Filter müssen übereinstimmen.
    for (id, used, other) in [
        ("CVE-2026-31006", "fixed", "vulnerable"),
        ("CVE-2026-31007", "vulnerable", "fixed"),
    ] {
        e.row(id, "debian", "trixie", "linux", used).await;
        e.row(id, "debian", "trixie", "linux-6.12", other).await;
        e.host_uses("deb1", id, "debian", "trixie", "linux", "vulnerable")
            .await;
        e.row(id, "ubuntu", "noble", "linux", used).await;
        e.row(id, "ubuntu", "noble", "linux-aws", other).await;
        e.host_uses("ubu1", id, "ubuntu", "noble", "linux", "vulnerable")
            .await;
    }
    for scope in ["", "&releases=all"] {
        let all = e.list(scope).await;
        for d in ["", "fixed", "open"] {
            for u in ["", "fixed", "open"] {
                let want = |c: &Value, src: &str, f: &str| {
                    f.is_empty()
                        || c["distros"].as_array().unwrap().iter().any(|x| {
                            x["source"] == src
                                && match f {
                                    "fixed" => x["status"] == "fixed",
                                    _ => {
                                        x["status"] == "vulnerable" || x["status"] == "fix_pending"
                                    }
                                }
                        })
                };
                let mut expect: Vec<String> = all
                    .iter()
                    .filter(|c| want(c, "debian", d) && want(c, "ubuntu", u))
                    .map(|c| c["id"].as_str().unwrap().to_owned())
                    .collect();
                expect.sort();
                let got = e.ids(&format!("{scope}&debian={d}&ubuntu={u}")).await;
                assert_eq!(got, expect, "Umfang '{scope}' debian={d} ubuntu={u}");
            }
        }
    }
}

/// Stabile Quellen-IDs, abgeschaltete und gelöschte Quellen: der Filter hängt am Typ der Quelle, nicht an ihrer ID,
/// und alte Daten bleiben sichtbar und filterbar.
#[sqlx::test(migrations = "./migrations")]
async fn filter_works_with_stable_source_ids_and_disabled_sources(pool: PgPool) {
    let e = filter_env(pool).await;
    e.row_id(
        "CVE-2026-32001",
        "debian",
        "debian-a1b2c3d4",
        "trixie",
        "linux",
        "fixed",
    )
    .await;
    e.row_id(
        "CVE-2026-32001",
        "debian",
        "debian-a1b2c3d4",
        "bookworm",
        "linux",
        "fixed",
    )
    .await;
    assert_eq!(e.ids("&debian=fixed").await, ["CVE-2026-32001"]);
    // Quelle abgeschaltet bzw. gelöscht: vorhandene Daten bleiben erhalten und werden weiter gefunden.
    sqlx::query("UPDATE cve_sources SET enabled = false WHERE id = 'debian'")
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(e.ids("&debian=fixed").await, ["CVE-2026-32001"]);
    sqlx::query("UPDATE cve_sources SET deleted_at = now() WHERE id = 'debian'")
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(e.ids("&debian=fixed").await, ["CVE-2026-32001"]);
    let c = &e.list("&q=CVE-2026-32001").await[0];
    assert_eq!(chip(c, "debian", "trixie").as_deref(), Some("fixed"));
}

/// Ungültige Werte werden mit 400 abgelehnt, Sonderzeichen in der Suche stürzen nie ab.
#[sqlx::test(migrations = "./migrations")]
async fn filter_rejects_bad_values_and_survives_special_characters(pool: PgPool) {
    let e = filter_env(pool).await;
    e.row("CVE-2026-33001", "debian", "trixie", "linux", "fixed")
        .await;
    for bad in [
        "&debian=nix",
        "&ubuntu=1%27%20OR%201=1",
        "&releases=jeder",
        "&debian=FIXED",
    ] {
        let r = call(
            &e.app,
            Method::GET,
            &format!("/api/v1/cves?x=1{bad}"),
            &hdr(&e.h),
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    for q in [
        "%27",
        "%25",
        "_",
        "%5C",
        "%C3%A9%F0%9F%A6%80",
        "CVE-",
        "%22%3B%20DROP%20TABLE%20cves%3B--",
        "a%00b",
        "%0A",
    ] {
        let r = call(
            &e.app,
            Method::GET,
            &format!("/api/v1/cves?debian=fixed&q={q}"),
            &hdr(&e.h),
            None,
        )
        .await;
        assert!(
            r.status == StatusCode::OK || r.status == StatusCode::BAD_REQUEST,
            "q={q}: {}",
            r.status
        );
    }
    assert_eq!(count(&e.pool, "SELECT count(*) FROM cves").await, 1);
}

// ---------- Ubuntu hybrid: Massendaten (OVAL) plus stündlicher Abruf der API ----------

/// Eine OVAL-Datei wie bei Canonical (verkürzt): je Eintrag eine CVE mit den behobenen Kernel-Varianten
/// (`fixed`) und optional dem Kriterium "Kernel läuft" für offene Fälle (ohne Fixversion).
/// (CVE, behobene Kernel-Varianten (Paket, Version), zusätzlich "Kernel läuft")
type OvalDef<'a> = (&'a str, &'a [(&'a str, &'a str)], bool);

fn oval_xml(release: &str, defs: &[OvalDef<'_>]) -> String {
    let mut x = String::from(
        "<oval_definitions xmlns=\"http://oval.mitre.org/XMLSchema/oval-definitions-5\"><generator/><definitions>\
         <definition id=\"oval:inv\" class=\"inventory\" version=\"1\"><metadata><title>inv</title><description /></metadata></definition>",
    );
    for (cve, fixed, open) in defs {
        x.push_str(&format!(
            "<definition id=\"oval:{cve}\" class=\"vulnerability\" version=\"1\"><metadata><title>{cve}</title>\
             <reference source=\"CVE\" ref_id=\"{cve}\" ref_url=\"https://x\" /><description>Test &amp; Beschreibung {cve}</description>\
             <advisory><cve href=\"https://x\" priority=\"high\" public=\"20250709\">{cve}</cve></advisory></metadata><criteria>"
        ));
        for (pkg, ver) in *fixed {
            x.push_str(&format!(
                "<criterion test_ref=\"oval:t\" comment=\"'{pkg}' kernel in {release} was vulnerable but has been fixed (note: '{ver}').\" />"
            ));
        }
        if *open {
            x.push_str("<criterion test_ref=\"oval:o\" comment=\"Is kernel 'linux' running?\" />");
        }
        x.push_str("</criteria></definition>");
    }
    x.push_str("</definitions></oval_definitions>");
    x
}

fn bz2(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn set_oval(mock: &Shared, release: &str, xml: &str, etag: &str) {
    mock.lock().unwrap().oval.insert(
        format!("com.ubuntu.{release}.cve.oval.xml.bz2"),
        OvalFile {
            body: bz2(xml.as_bytes()),
            etag: etag.to_owned(),
            ..Default::default()
        },
    );
}

async fn setup_hybrid(pool: PgPool, base: &str, extra: &str) -> AppState {
    let timeout = if extra.contains("ubuntu_page_timeout_secs") {
        ""
    } else {
        "ubuntu_page_timeout_secs = 3\n"
    };
    let toml = format!(
        "[cve]\nsources = [\"ubuntu\"]\nubuntu_url = \"{base}\"\nubuntu_oval_url = \"{base}/oval\"\nubuntu_mode = \"hybrid\"\n\
         retries = 1\nretry_base_delay_ms = 10\nrequest_timeout_secs = 10\nubuntu_page_pause_ms = 0\n{timeout}{extra}\n\
         [ntfy]\nurl = \"http://127.0.0.1:9\"\ntopic = \"t\"\n"
    );
    let st = AppState::new(pool, Config::from_sources(Some(&toml), &|_| None).unwrap()).unwrap();
    patchwatch_server::cve::sources::ensure_seeded(&st)
        .await
        .unwrap();
    st
}

async fn bulk_json(pool: &PgPool) -> Value {
    sqlx::query_scalar::<_, Option<Value>>("SELECT bulk FROM feed_state WHERE source = 'ubuntu'")
        .fetch_one(pool)
        .await
        .unwrap()
        .unwrap_or(Value::Null)
}

/// Lässt den letzten Import aller Releases zwei Tage zurückliegen und hebt Wartezeiten nach Fehlern auf (fällig),
/// ohne die Frische zu berühren.
async fn make_bulk_due(pool: &PgPool) {
    sqlx::query(
        "UPDATE feed_state SET bulk = (SELECT jsonb_set(bulk, '{releases}', COALESCE((SELECT jsonb_object_agg(k, \
         (jsonb_set(v, '{checked_at}', to_jsonb(to_char(now() - interval '2 days', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))) || '{\"next_attempt_at\": null}'::jsonb)) \
         FROM jsonb_each(bulk->'releases') AS e(k, v)), '{}'::jsonb))) WHERE source = 'ubuntu'",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn status_rows(pool: &PgPool, cve: &str) -> Vec<(String, String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT release, package, status, fix_version FROM cve_source_status WHERE cve_id = $1 AND source_id = 'ubuntu' \
         ORDER BY release, package",
    )
    .bind(cve)
    .fetch_all(pool)
    .await
    .unwrap()
}

fn page_limits(mock: &Shared) -> Vec<usize> {
    mock.lock().unwrap().pages.iter().map(|p| p.0).collect()
}

#[sqlx::test(migrations = "./migrations")]
async fn hybrid_first_import_is_complete_green_and_maps_status(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[
                (
                    "CVE-2026-20001",
                    &[("linux", "6.8.0-20.20"), ("linux-aws", "6.8.0-1000.1")],
                    false,
                ),
                // Nur "Kernel läuft": offen oder unbekannt, wird nicht gespeichert.
                ("CVE-2026-20002", &[], true),
                // Kein Kernel-Paket: wird nie übernommen.
                ("CVE-2026-20009", &[("openssl", "3.0.13-1")], false),
            ],
        ),
        "\"v1\"",
    );
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-20003",
        Utc::now() - Duration::minutes(1),
        &[("noble", "released", "6.8.0-20.20")],
    )];
    let st = setup_hybrid(pool.clone(), &base, "ubuntu_bulk_releases = [\"noble\"]").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    gate(&st).await;
    assert_eq!(
        host_status(&pool, hid).await,
        "cve_unknown",
        "vor dem Import nie grün"
    );

    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );

    // Behoben-Daten stammen aus der Datei, mit Fixversion; offene und fremde Einträge nicht.
    assert_eq!(
        status_rows(&pool, "CVE-2026-20001").await,
        vec![
            (
                "noble".into(),
                "linux".into(),
                "fixed".into(),
                Some("6.8.0-20.20".into())
            ),
            (
                "noble".into(),
                "linux-aws".into(),
                "fixed".into(),
                Some("6.8.0-1000.1".into())
            ),
        ]
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cves WHERE id IN ('CVE-2026-20002', 'CVE-2026-20009')"
        )
        .await,
        0
    );
    // Die API liefert den Rest.
    assert_eq!(status_rows(&pool, "CVE-2026-20003").await.len(), 1);

    let row = ubuntu_feed_row(&app, &h).await;
    assert_eq!(row["state"], "ok");
    assert_eq!(row["bulk"]["complete"], true);
    let rel = &row["bulk"]["releases"][0];
    assert_eq!(
        (
            rel["release"].as_str(),
            rel["state"].as_str(),
            rel["result_text"].as_str()
        ),
        (Some("noble"), Some("ok"), Some("importiert"))
    );
    assert!(rel["bytes"].as_u64().unwrap() > 0 && rel["imported_at"].is_string());
    assert!(row["bulk"]["hourly"]["last_ok_at"].is_string());
    assert_eq!(row["bulk"]["hourly"]["page_size"], 20);
    assert_eq!(host_status(&pool, hid).await, "ok", "vollständig: grün");
    assert!(host_issue(&app, &h, hid).await.is_none());
    // Ehrlicher User-Agent auch bei den Massendaten, höchstens eine Datei je Release.
    assert_eq!(attempts(&mock, "oval com.ubuntu.noble.cve.oval.xml.bz2"), 1);
    assert!(mock
        .lock()
        .unwrap()
        .user_agents
        .iter()
        .all(|u| u.starts_with("patchwatch-server/")));
}

#[sqlx::test(migrations = "./migrations")]
async fn hybrid_second_run_is_a_conditional_304_and_shows_it(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
        ),
        "\"v1\"",
    );
    let st = setup_hybrid(pool.clone(), &base, "ubuntu_bulk_releases = [\"noble\"]").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    refresh::refresh_all(&st).await;
    let first = bulk_json(&pool).await["releases"]["noble"]["verified_at"].clone();

    // Noch nicht fällig (täglich): keine Anfrage an die Datei.
    refresh::refresh_all(&st).await;
    assert_eq!(attempts(&mock, "oval com.ubuntu.noble.cve.oval.xml.bz2"), 1);
    assert_eq!(
        attempts(&mock, "oval com.ubuntu.noble.cve.oval.xml.bz2 conditional"),
        0
    );

    make_bulk_due(&pool).await;
    refresh::refresh_all(&st).await;
    assert_eq!(
        attempts(&mock, "oval com.ubuntu.noble.cve.oval.xml.bz2 conditional"),
        1,
        "bedingte Anfrage mit If-None-Match"
    );
    let row = ubuntu_feed_row(&app, &h).await;
    assert_eq!(
        row["bulk"]["releases"][0]["result_text"],
        "unverändert (304)"
    );
    assert_eq!(row["state"], "ok");
    assert_ne!(
        bulk_json(&pool).await["releases"]["noble"]["verified_at"],
        first,
        "304 bestätigt den Stand"
    );
    assert_eq!(status_rows(&pool, "CVE-2026-20001").await.len(), 1);
}

/// Abgeschnittene, zu große und unlesbare Dateien: die vorhandenen Daten bleiben, die Quelle ist nie grün,
/// und eine Datei ohne vorherigen Import macht aus "unbekannt" nie "behoben".
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_broken_files_keep_old_data_and_are_never_green(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let good = oval_xml(
        "noble",
        &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
    );
    set_oval(&mock, "noble", &good, "\"v1\"");
    let st = setup_hybrid(
        pool.clone(),
        &base,
        "ubuntu_bulk_releases = [\"noble\"]\nubuntu_oval_max_bytes = 5000",
    )
    .await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    refresh::refresh_all(&st).await;
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "ok");

    let file = "com.ubuntu.noble.cve.oval.xml.bz2";
    type Breaker = Box<dyn Fn(&mut OvalFile)>;
    let broken: Vec<(&str, Breaker)> = vec![
        (
            "abgeschnittene bz2-Datei",
            Box::new(|f: &mut OvalFile| {
                f.cut_at = Some(f.body.len() / 2);
                f.etag = "\"v2\"".into();
            }),
        ),
        (
            "gültiges bz2, aber XML ohne Ende",
            Box::new(|f: &mut OvalFile| {
                f.body =
                    bz2(b"<oval_definitions><definitions><definition class=\"vulnerability\">");
                f.etag = "\"v3\"".into();
            }),
        ),
        (
            "größer als das Limit",
            Box::new(|f: &mut OvalFile| {
                f.body = vec![b'x'; 6000];
                f.etag = "\"v4\"".into();
            }),
        ),
        (
            "kein bz2",
            Box::new(|f: &mut OvalFile| {
                f.body = b"das ist kein bzip2".to_vec();
                f.etag = "\"v5\"".into();
            }),
        ),
    ];
    for (what, change) in broken {
        let mut f = mock.lock().unwrap().oval[file].clone();
        f.cut_at = None;
        change(&mut f);
        mock.lock().unwrap().oval.insert(file.into(), f);
        make_bulk_due(&pool).await;
        refresh::refresh_all(&st).await;
        let row = ubuntu_feed_row(&app, &h).await;
        assert_eq!(row["state"], "incomplete", "{what}: nie grün");
        assert_eq!(row["bulk"]["releases"][0]["state"], "error", "{what}");
        assert!(
            row["bulk"]["releases"][0]["result_text"]
                .as_str()
                .unwrap()
                .len()
                > 5,
            "{what}"
        );
        // Alte Daten bleiben; der Host bleibt innerhalb der Frische bewertet (Rot bliebe rot).
        assert_eq!(
            status_rows(&pool, "CVE-2026-20001").await.len(),
            1,
            "{what}"
        );
        assert_eq!(host_status(&pool, hid).await, "ok", "{what}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn hybrid_failed_first_import_stores_nothing_and_hosts_stay_unknown(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let mut f = OvalFile {
        body: bz2(oval_xml(
            "noble",
            &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
        )
        .as_bytes()),
        etag: "\"v1\"".into(),
        ..Default::default()
    };
    f.cut_at = Some(30);
    mock.lock()
        .unwrap()
        .oval
        .insert("com.ubuntu.noble.cve.oval.xml.bz2".into(), f);
    let st = setup_hybrid(pool.clone(), &base, "ubuntu_bulk_releases = [\"noble\"]").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    refresh::refresh_all(&st).await;
    assert_eq!(count(&pool, "SELECT count(*) FROM cve_source_status WHERE source_id = 'ubuntu' AND status = 'fixed'").await, 0);
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "incomplete");
    assert_eq!(
        host_status(&pool, hid).await,
        "cve_unknown",
        "fehlende Information ist nie grün"
    );
    let issue = host_issue(&app, &h, hid).await.unwrap();
    assert!(
        issue.contains("noble") && issue.contains("Massendaten"),
        "{issue}"
    );
}

/// Statusabbildung im Adapter: fixed aus der Datei, needed/pending/ignored aus der API, nichts für fehlende
/// Information; ein roter Host bleibt rot, auch wenn die Datei das Release nicht (mehr) kennt.
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_status_mapping_open_cases_and_missing_information(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[
                ("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false),
                ("CVE-2026-20002", &[], true),
            ],
        ),
        "\"v1\"",
    );
    let now = Utc::now();
    mock.lock().unwrap().ubuntu = vec![
        ubuntu_cve(
            "CVE-2026-20010",
            now - Duration::minutes(1),
            &[("noble", "needed", "")],
        ),
        ubuntu_cve(
            "CVE-2026-20011",
            now - Duration::minutes(2),
            &[("noble", "pending", "6.8.0-99.99")],
        ),
        ubuntu_cve(
            "CVE-2026-20012",
            now - Duration::minutes(3),
            &[("noble", "ignored", "end of life")],
        ),
        ubuntu_cve(
            "CVE-2026-20013",
            now - Duration::minutes(4),
            &[("noble", "needs-triage", "")],
        ),
    ];
    let st = setup_hybrid(pool.clone(), &base, "ubuntu_bulk_releases = [\"noble\"]").await;
    let app = patchwatch_server::router(st.clone());
    let _ = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    refresh::refresh_all(&st).await;
    let s = |c: &'static str| {
        let pool = pool.clone();
        async move {
            status_rows(&pool, c)
                .await
                .first()
                .map(|r| (r.2.clone(), r.3.clone()))
        }
    };
    assert_eq!(
        s("CVE-2026-20001").await,
        Some(("fixed".into(), Some("6.8.0-20.20".into())))
    );
    assert_eq!(s("CVE-2026-20010").await.unwrap().0, "vulnerable");
    assert_eq!(
        s("CVE-2026-20011").await,
        Some(("fix_pending".into(), Some("6.8.0-99.99".into())))
    );
    assert_eq!(s("CVE-2026-20012").await.unwrap().0, "vulnerable");
    assert_eq!(s("CVE-2026-20013").await.unwrap().0, "unknown");
    // "Kernel läuft" ohne Fixkriterium und unbekannte CVEs: keine Zeile, also nie fixed/not_affected.
    assert_eq!(s("CVE-2026-20002").await, None);
    assert_eq!(s("CVE-2026-29999").await, None);
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");
}

/// Massendaten frisch, API fällt aus: kein Totalausfall. Seiten werden kleiner (20, 10, 5, 5), der Fehler mit
/// Statuscode steht in der Anzeige, bei dauerhaftem 503 kommt ein Hinweis, und nach Ablauf der Frische ist die
/// CVE-Lage "unbekannt".
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_api_outage_is_no_total_outage_until_freshness_ends(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
        ),
        "\"v1\"",
    );
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 3, Utc::now() - Duration::hours(1));
    let st = setup_hybrid(pool.clone(), &base, "ubuntu_bulk_releases = [\"noble\"]").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    sqlx::query("DELETE FROM cve_watchlist")
        .execute(&pool)
        .await
        .unwrap();
    // Erster Lauf: alles gut, die Quelle ist vollständig.
    refresh::refresh_all(&st).await;
    // Der Host hat ein offenes CVE aus der API: rot, und Rot bleibt Rot.
    assert_eq!(host_status(&pool, hid).await, "cve_vulnerable");

    mock.lock().unwrap().ubuntu_status = Some(503);
    mock.lock().unwrap().ubuntu_retry_after = Some("7".into());
    mock.lock().unwrap().pages.clear();
    for _ in 0..3 {
        let out = refresh::refresh_all(&st).await;
        assert!(
            matches!(out[0].1, Outcome::Updated { .. }),
            "API-Ausfall ist kein Fehlschlag der Quelle: {:?}",
            out[0].1
        );
    }
    let limits = page_limits(&mock);
    // Erster Lauf: 20, 10, 5 und ein Wiederholversuch auf der kleinsten Stufe; danach bleibt es bei 5.
    assert_eq!(
        limits,
        vec![20, 10, 5, 5, 5, 5, 5, 5],
        "die Größe bleibt klein, nie unter 5"
    );
    let row = ubuntu_feed_row(&app, &h).await;
    assert_eq!(row["bulk"]["hourly"]["status"], 503);
    assert_eq!(row["bulk"]["hourly"]["retry_after_secs"], 7);
    assert_eq!(row["bulk"]["hourly"]["page_size"], 5, "nie unter 5");
    assert!(row["bulk"]["hourly"]["error_text"]
        .as_str()
        .unwrap()
        .contains("503"));
    assert!(row["bulk"]["hourly"]["hint"]
        .as_str()
        .unwrap()
        .contains("503/504"));
    assert_eq!(
        row["state"], "incomplete",
        "dauerhafter Ausfall der offenen Fälle: nie grün"
    );
    assert_eq!(
        row["bulk"]["complete"], true,
        "die Massendaten sind weiter vollständig"
    );

    // Frische vorbei: unbekannt.
    sqlx::query(
        "UPDATE feed_state SET usable_until = now() - interval '1 minute', \
         bulk = jsonb_set(bulk, '{ok,noble}', to_jsonb(to_char(now() - interval '1 minute', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))) \
         WHERE source = 'ubuntu'",
    )
    .execute(&pool)
    .await
    .unwrap();
    gate(&st).await;
    assert_eq!(
        host_status(&pool, hid).await,
        "cve_vulnerable",
        "Rot bleibt Rot, auch wenn die Frische abläuft"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn hybrid_fresh_bulk_keeps_hosts_usable_when_the_api_is_down(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
        ),
        "\"v1\"",
    );
    let st = setup_hybrid(pool.clone(), &base, "ubuntu_bulk_releases = [\"noble\"]").await;
    let app = patchwatch_server::router(st.clone());
    let _ = login(&app, &pool).await;
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    mock.lock().unwrap().ubuntu_status = Some(504);
    refresh::refresh_all(&st).await;
    gate(&st).await;
    assert_eq!(
        host_status(&pool, hid).await,
        "ok",
        "Massendaten frisch, API ausgefallen: noch nutzbar"
    );
    // Frische vorbei: unbekannt, nie grün.
    sqlx::query(
        "UPDATE feed_state SET usable_until = now() - interval '1 minute', \
         bulk = jsonb_set(bulk, '{ok,noble}', to_jsonb(to_char(now() - interval '1 minute', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))) \
         WHERE source = 'ubuntu'",
    )
    .execute(&pool)
    .await
    .unwrap();
    gate(&st).await;
    assert_eq!(host_status(&pool, hid).await, "cve_unknown");
}

#[sqlx::test(migrations = "./migrations")]
async fn hybrid_timeout_in_the_hourly_fetch_shrinks_pages_and_keeps_bulk(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
        ),
        "\"v1\"",
    );
    mock.lock().unwrap().ubuntu_hang = true;
    let st = setup_hybrid(
        pool.clone(),
        &base,
        "ubuntu_bulk_releases = [\"noble\"]\nubuntu_page_timeout_secs = 1",
    )
    .await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    // Antwort kommt nie: 20, 10, 5 und ein Wiederholversuch auf der kleinsten Stufe, jeweils nach 1 s Zeitlimit.
    assert_eq!(attempts(&mock, "ubuntu hang"), 4);
    let row = ubuntu_feed_row(&app, &h).await;
    assert_eq!(row["bulk"]["hourly"]["page_size"], 5);
    assert!(row["bulk"]["hourly"]["error_text"].is_string());
    assert_eq!(row["bulk"]["complete"], true);
    assert_eq!(status_rows(&pool, "CVE-2026-20001").await.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn hybrid_422_teaches_the_maximum_page_size(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 3, Utc::now() - Duration::hours(1));
    mock.lock().unwrap().ubuntu_422_above = Some(10);
    let st = setup_hybrid(pool.clone(), &base, "").await;
    let _ = patchwatch_server::router(st.clone());
    refresh::refresh_all(&st).await;
    assert_eq!(page_limits(&mock), vec![20, 10]);
    let b = bulk_json(&pool).await;
    assert_eq!(b["incr"]["max_page"], 10);
    assert_eq!(b["incr"]["page_size"], 10);
    // Der nächste Lauf fängt direkt mit dem gelernten Maximum an.
    mock.lock().unwrap().pages.clear();
    refresh::refresh_all(&st).await;
    assert_eq!(page_limits(&mock)[0], 10);
}

#[sqlx::test(migrations = "./migrations")]
async fn hybrid_page_size_shrinks_on_503_and_grows_back_after_success(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 3, Utc::now() - Duration::hours(1));
    mock.lock().unwrap().ubuntu_503_above = Some(7);
    let st = setup_hybrid(pool.clone(), &base, "").await;
    let _ = patchwatch_server::router(st.clone());
    refresh::refresh_all(&st).await;
    assert_eq!(page_limits(&mock), vec![20, 10, 5]);
    let size = || async {
        bulk_json(&pool).await["incr"]["page_size"]
            .as_u64()
            .unwrap()
    };
    assert_eq!(size().await, 5);
    mock.lock().unwrap().ubuntu_503_above = None;
    mock.lock().unwrap().pages.clear();
    refresh::refresh_all(&st).await;
    assert_eq!(size().await, 10, "fehlerfreier Lauf: eine Stufe größer");
    refresh::refresh_all(&st).await;
    assert_eq!(size().await, 20);
    assert_eq!(page_limits(&mock), vec![5, 10]);
}

/// Umstellung ohne Lücke: der bisherige bestätigte Cursor bleibt, der Abstand wird über mehrere Läufe (Seitenlimit
/// je Lauf) geschlossen; der Cursor rückt erst vor, wenn alles gelesen ist.
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_switch_closes_the_gap_without_losing_entries(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let newest = Utc::now() - Duration::minutes(10);
    let mut items = ubuntu_batch(1, 25, newest);
    let cursor = newest - Duration::hours(1);
    items.extend((0..5).map(|i| {
        ubuntu_cve(
            &format!("CVE-2026-9{i:04}"),
            cursor - Duration::minutes(i),
            &[("noble", "needed", "")],
        )
    }));
    mock.lock().unwrap().ubuntu = items;
    let st = setup_hybrid(
        pool.clone(),
        &base,
        "ubuntu_page_size = 5\nubuntu_incremental_pages = 2",
    )
    .await;
    let _ = patchwatch_server::router(st.clone());
    sqlx::query("INSERT INTO feed_state (source, cursor, last_success_at) VALUES ('ubuntu', $1, now()) ON CONFLICT (source) DO UPDATE SET cursor = $1")
        .bind(cursor.to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
    refresh::refresh_all(&st).await;
    let c = || async { ubuntu_cursor(&pool).await };
    assert_eq!(
        c().await,
        cursor.to_rfc3339(),
        "Abstand offen: Cursor bleibt"
    );
    for _ in 0..12 {
        if c().await != cursor.to_rfc3339() {
            break;
        }
        refresh::refresh_all(&st).await;
    }
    assert_ne!(c().await, cursor.to_rfc3339(), "Abstand geschlossen");
    assert_eq!(count(&pool, "SELECT count(DISTINCT cve_id) FROM cve_source_status WHERE source_id = 'ubuntu' AND cve_id LIKE 'CVE-2026-1%'").await, 25, "keine Lücke");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE cve_id LIKE 'CVE-2026-9%'"
        )
        .await,
        0,
        "nichts jenseits des Cursors"
    );
}

/// Der Erstimport beginnt mit der ersten Seite, ohne relevante Releases ist die Quelle sofort vollständig.
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_initial_import_ends_complete(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 50, Utc::now() - Duration::hours(1));
    let st = setup_hybrid(pool.clone(), &base, "").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let out = refresh::refresh_all(&st).await;
    assert!(
        matches!(out[0].1, Outcome::Updated { .. }),
        "{:?}",
        out[0].1
    );
    let row = ubuntu_feed_row(&app, &h).await;
    assert_eq!(row["state"], "ok");
    assert!(row["backfill"].is_null());
    assert!(ubuntu_cursor_opt(&pool).await.is_some());
}

/// Ein vorhandener Rückstandsabbau wird weder gelöscht noch zurückgesetzt: er ruht im Hybridmodus
/// (`backfill_parked`) und läuft im Rückfallmodus `api` mit demselben Fortschritt weiter.
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_parks_the_legacy_backfill_and_api_mode_resumes_it(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    mock.lock().unwrap().ubuntu = ubuntu_batch(1, 3, Utc::now() - Duration::hours(1));
    let cursor = (Utc::now() - Duration::days(3)).to_rfc3339();
    let backfill = json!({
        "target": (Utc::now() - Duration::days(365)).to_rfc3339(), "pending": cursor.clone(), "next_offset": 400,
        "pages_done": 20, "runs": 4, "started_at": Utc::now().to_rfc3339(), "initial": true, "est_pages": 1100
    });
    let st = setup_hybrid(pool.clone(), &base, "").await;
    let _ = patchwatch_server::router(st.clone());
    sqlx::query("INSERT INTO feed_state (source, cursor, backfill) VALUES ('ubuntu', $1, $2) ON CONFLICT (source) DO UPDATE SET cursor = $1, backfill = $2")
        .bind(&cursor)
        .bind(&backfill)
        .execute(&pool)
        .await
        .unwrap();
    refresh::refresh_all(&st).await;
    let (bf, parked): (Option<Value>, Option<Value>) =
        sqlx::query_as("SELECT backfill, backfill_parked FROM feed_state WHERE source = 'ubuntu'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(bf.is_none());
    assert_eq!(
        parked.unwrap()["next_offset"],
        400,
        "Fortschritt bleibt erhalten"
    );

    // Rückfall: derselbe Fortschritt läuft weiter (Seite bei Offset 400), die Hybriddaten sind weg.
    let api = setup_cfg(pool.clone(), &base, 1, 10, 600, 0).await;
    mock.lock().unwrap().pages.clear();
    refresh::refresh_all(&api).await;
    let (bf, parked, bulk): (Option<Value>, Option<Value>, Option<Value>) = sqlx::query_as(
        "SELECT backfill, backfill_parked, bulk FROM feed_state WHERE source = 'ubuntu'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(parked.is_none() && bulk.is_none());
    assert!(
        mock.lock().unwrap().pages.iter().any(|p| p.1 >= 400),
        "setzt bei Offset 400 fort: {:?}",
        mock.lock().unwrap().pages
    );
    assert!(bf.is_some() || ubuntu_cursor_opt(&pool).await.is_some());
}

/// Ein Release ohne Massendaten (Datei fehlt): nur Hosts dieses Releases sind "unbekannt", der Rest bleibt grün.
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_missing_release_only_affects_hosts_of_that_release(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
        ),
        "\"v1\"",
    );
    let st = setup_hybrid(pool.clone(), &base, "").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    let n = add_host(&pool, "web-noble").await;
    let j = add_host(&pool, "web-jammy").await;
    assert_eq!(
        report(&app, &noble("web-noble", "6.8.0-31.31", "6.8.0-31.31")).await,
        StatusCode::NO_CONTENT
    );
    let jammy = K {
        codename: "jammy",
        os_version: "22.04",
        release: "5.15.0-100-generic",
        package: "linux-image-5.15.0-100-generic",
        ..noble("web-jammy", "5.15.0-100.110", "5.15.0-100.110")
    };
    assert_eq!(report(&app, &jammy).await, StatusCode::NO_CONTENT);
    refresh::refresh_all(&st).await;
    gate(&st).await;
    assert_eq!(host_status(&pool, n).await, "ok");
    assert_eq!(host_status(&pool, j).await, "cve_unknown");
    let issue = host_issue(&app, &h, j).await.unwrap();
    assert!(issue.contains("jammy"), "{issue}");
    assert!(host_issue(&app, &h, n).await.is_none());
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "incomplete");
    // Datei erscheint: beide grün, Quelle vollständig.
    set_oval(
        &mock,
        "jammy",
        &oval_xml(
            "jammy",
            &[("CVE-2026-20001", &[("linux", "5.15.0-1.1")], false)],
        ),
        "\"j1\"",
    );
    make_bulk_due(&pool).await;
    refresh::refresh_all(&st).await;
    gate(&st).await;
    assert_eq!(host_status(&pool, j).await, "ok");
    assert_eq!(ubuntu_feed_row(&app, &h).await["state"], "ok");
}

/// Quelle löschen und neu anlegen: der Zustand der alten Quelle (Massendaten, ETags) gehört zur alten ID; die neue
/// Quelle beginnt mit einem vollständigen Import und kommt wieder auf "vollständig".
#[sqlx::test(migrations = "./migrations")]
async fn hybrid_delete_and_recreate_source_imports_again(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    set_oval(
        &mock,
        "noble",
        &oval_xml(
            "noble",
            &[("CVE-2026-20001", &[("linux", "6.8.0-20.20")], false)],
        ),
        "\"v1\"",
    );
    let st = setup_hybrid(pool.clone(), &base, "ubuntu_bulk_releases = [\"noble\"]").await;
    let app = patchwatch_server::router(st.clone());
    let h = login(&app, &pool).await;
    refresh::refresh_all(&st).await;
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
    assert_ne!(new_id, "ubuntu");
    mock.lock().unwrap().log.clear();
    refresh::refresh_all(&st).await;
    assert_eq!(
        attempts(&mock, "oval com.ubuntu.noble.cve.oval.xml.bz2"),
        1,
        "unbedingter Neuimport (kein If-None-Match)"
    );
    let row = feed(&feeds(&app, &h).await, &new_id).clone();
    assert_eq!(row["state"], "ok");
    assert_eq!(row["bulk"]["complete"], true);
}

// ---------- Filter und Chips: Umfang sichtbar, Trefferzahl bei "Alle Releases" ----------

impl FilterEnv {
    async fn scope_count(&self, query: &str) -> (i64, i64) {
        let r = call(
            &self.app,
            Method::GET,
            &format!("/api/v1/cves/scope-count?affects=all&x=1{query}"),
            &hdr(&self.h),
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{query}: {}", r.json);
        (
            r.json["mine"].as_i64().unwrap(),
            r.json["all"].as_i64().unwrap(),
        )
    }
}

/// Wie CVE-2026-98930: bookworm offen (läuft auf keinem Host), forky/sid/trixie gefixt (trixie läuft auf einem Host).
/// "Debian offen" findet die CVE nur im Umfang "alle", die Chips tragen das Merkmal `mine`, und die Zählung für den
/// Leer-Zustand nennt die Treffer bei "Alle Releases" mit derselben Filterlogik wie die Liste.
#[sqlx::test(migrations = "./migrations")]
async fn filter_open_release_outside_scope_is_found_only_with_scope_all(pool: PgPool) {
    let e = filter_env(pool).await;
    for (rel, st) in [
        ("bookworm", "vulnerable"),
        ("forky", "fixed"),
        ("sid", "fixed"),
        ("trixie", "fixed"),
    ] {
        e.row("CVE-2026-98930", "debian", rel, "linux", st).await;
    }
    e.host_uses(
        "deb1",
        "CVE-2026-98930",
        "debian",
        "trixie",
        "linux",
        "fixed",
    )
    .await;
    // Zweite CVE: wirklich offen im eigenen Release, muss in beiden Umfängen erscheinen.
    e.row("CVE-2026-98931", "debian", "trixie", "linux", "vulnerable")
        .await;

    // Umfang "meine Releases": kein Treffer für die CVE (trixie ist gefixt), die andere CVE ja.
    assert_eq!(e.ids("&debian=open").await, vec!["CVE-2026-98931"]);
    // Umfang "alle": beide.
    assert_eq!(
        e.ids("&debian=open&releases=all").await,
        vec!["CVE-2026-98930", "CVE-2026-98931"]
    );
    // Die Zählung für den Leer-Zustand benutzt dieselbe Logik: mine = Liste, all = Liste bei Umfang alle.
    assert_eq!(e.scope_count("&debian=open").await, (1, 2));
    // Anzeige: nur der Chip trixie zählt (mine), die anderen sind gekennzeichnet und gehören nicht zur Liste.
    let list = e.list("&releases=all&q=CVE-2026-98930").await;
    let chips = list[0]["distros"].as_array().unwrap();
    let mine: Vec<(&str, bool)> = chips
        .iter()
        .map(|c| (c["release"].as_str().unwrap(), c["mine"].as_bool().unwrap()))
        .collect();
    assert_eq!(
        mine,
        vec![
            ("bookworm", false),
            ("forky", false),
            ("sid", false),
            ("trixie", true)
        ]
    );
}

/// Leer-Zustand: Filter ohne Treffer im Umfang "meine Releases" meldet, wie viele bei "alle" passen; ohne Treffer
/// auch dort steht 0 da (kein Angebot ohne Wirkung).
#[sqlx::test(migrations = "./migrations")]
async fn filter_scope_count_tells_how_many_match_with_all_releases(pool: PgPool) {
    let e = filter_env(pool).await;
    for i in 0..3 {
        let id = format!("CVE-2026-9700{i}");
        e.row(&id, "debian", "bookworm", "linux", "vulnerable")
            .await;
        e.row(&id, "debian", "trixie", "linux", "fixed").await;
        e.host_uses("deb1", &id, "debian", "trixie", "linux", "fixed")
            .await;
    }
    assert_eq!(e.scope_count("&debian=open").await, (0, 3));
    assert!(e.ids("&debian=open").await.is_empty());
    assert_eq!(e.ids("&debian=open&releases=all").await.len(), 3);
    // Ein Filter, der auch im weiten Umfang nichts findet.
    assert_eq!(e.scope_count("&ubuntu=open").await, (0, 0));
    // Ungültige Werte werden wie in der Liste abgelehnt.
    let r = call(
        &e.app,
        Method::GET,
        "/api/v1/cves/scope-count?debian=kaputt",
        &hdr(&e.h),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

// ---------- Host-Ansicht: Fix-Lage je CVE ----------

/// Alle Zustände werden gespeichert (auch "gefixt" und "nicht betroffen"), mit den richtigen Versionen; die Zähler
/// stimmen mit der Liste überein; Filter, Sortierung, Seiten und Sonderzeichen funktionieren.
/// Ohne das Speichern von "gefixt"/"nicht betroffen" bliebe die Liste leer bzw. die Zähler 0.
#[sqlx::test(migrations = "./migrations")]
async fn host_cves_lists_all_states_with_versions_and_counters(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "web1").await;
    // Läuft 6.8.0-31.31, installiert (neuester) 6.8.0-35.35.
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-35.35")).await,
        StatusCode::NO_CONTENT
    );
    let now = Utc::now() - Duration::minutes(10);
    mock.lock().unwrap().ubuntu = vec![
        ubuntu_cve("CVE-2026-20001", now, &[("noble", "needed", "")]),
        ubuntu_cve(
            "CVE-2026-20002",
            now,
            &[("noble", "released", "6.8.0-30.30")],
        ),
        ubuntu_cve(
            "CVE-2026-20003",
            now,
            &[("noble", "released", "6.8.0-33.33")],
        ),
        ubuntu_cve("CVE-2026-20004", now, &[("noble", "not-affected", "")]),
        ubuntu_cve(
            "CVE-2026-20005",
            now,
            &[("noble", "pending", "6.8.0-99.99")],
        ),
    ];
    refresh::refresh_all(&st).await;

    let cookies = login(&app, &pool).await;
    let h = hdr(&cookies);
    let url = format!("/api/v1/hosts/{hid}/cves");
    let r = call(&app, Method::GET, &url, &h, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let by_id = |id: &str| -> Value {
        r.json["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["cve_id"] == id)
            .unwrap_or_else(|| panic!("{id} fehlt: {}", r.json))
            .clone()
    };
    assert_eq!(by_id("CVE-2026-20001")["status"], "vulnerable");
    let fixed = by_id("CVE-2026-20002");
    assert_eq!(fixed["status"], "fixed");
    assert_eq!(fixed["fix_version"], "6.8.0-30.30");
    assert_eq!(fixed["source"], "ubuntu");
    assert_eq!(
        by_id("CVE-2026-20003")["status"],
        "fixed_installed_reboot_required"
    );
    assert_eq!(by_id("CVE-2026-20003")["fix_version"], "6.8.0-33.33");
    assert_eq!(by_id("CVE-2026-20004")["status"], "not_affected");
    // Ein nur angekündigter Fix lässt den Host verwundbar (siehe Regel in eval.rs).
    assert_eq!(by_id("CVE-2026-20005")["status"], "vulnerable");
    assert_eq!(r.json["host"]["running_kernel_version"], "6.8.0-31.31");
    assert_eq!(r.json["host"]["newest_kernel_version"], "6.8.0-35.35");
    assert_eq!(r.json["host"]["reboot_needed"], true);
    assert!(r.json["issue"].is_null());

    // Zähler = Listeneinträge je Zustand.
    let items = r.json["items"].as_array().unwrap();
    assert_eq!(r.json["total"], items.len());
    for (state, n) in r.json["counts"].as_object().unwrap() {
        let listed = items.iter().filter(|i| i["status"] == *state).count();
        assert_eq!(n.as_u64().unwrap() as usize, listed, "{state}");
    }
    assert_eq!(r.json["counts"]["fixed"], 1);
    assert_eq!(r.json["counts"]["not_affected"], 1);
    assert_eq!(r.json["counts"]["unknown"], 0);

    // Wichtigstes zuerst: Neustart nötig, dann offen, Fix angekündigt, gefixt, nicht betroffen.
    let order: Vec<&str> = items
        .iter()
        .map(|i| i["status"].as_str().unwrap())
        .collect();
    assert_eq!(
        order,
        [
            "fixed_installed_reboot_required",
            "vulnerable",
            "vulnerable",
            "fixed",
            "not_affected"
        ]
    );

    // Gruppen, Status, Suche, Sortierung und Seiten (serverseitig).
    let open = call(&app, Method::GET, &format!("{url}?group=open"), &h, None).await;
    assert_eq!(open.json["total"], 3);
    assert_eq!(open.json["counts"]["vulnerable"], 2);
    let one = call(&app, Method::GET, &format!("{url}?status=fixed"), &h, None).await;
    assert_eq!(one.json["total"], 1);
    let q = call(&app, Method::GET, &format!("{url}?q=20004"), &h, None).await;
    assert_eq!(q.json["total"], 1);
    assert_eq!(
        q.json["counts"]["vulnerable"], 2,
        "Zähler gelten für den ganzen Host"
    );
    let asc = call(
        &app,
        Method::GET,
        &format!("{url}?sort=cve&dir=asc&limit=2&offset=1"),
        &h,
        None,
    )
    .await;
    let ids: Vec<&str> = asc.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["cve_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["CVE-2026-20002", "CVE-2026-20003"]);
    assert_eq!(asc.json["total"], 5);
    // Whitelist: unbekannte Werte werden abgelehnt, nie in SQL übernommen.
    for bad in ["sort=x;drop", "dir=up", "status=gone", "group=all2"] {
        let r = call(&app, Method::GET, &format!("{url}?{bad}"), &h, None).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    // Sonderzeichen in der Suche: LIKE-Zeichen und Unicode brechen nichts und treffen nicht alles.
    for term in ["caf%C3%A9", "%F0%9F%94%A5", "100%25", "a_b", "'%3B--"] {
        let r = call(&app, Method::GET, &format!("{url}?q={term}"), &h, None).await;
        assert_eq!(r.status, StatusCode::OK, "{term}");
        assert_eq!(r.json["total"], 0, "{term}");
    }
    // Host-Liste: kompakte CVE-Lage.
    let hosts = call(&app, Method::GET, "/api/v1/hosts", &h, None).await;
    assert_eq!(hosts.json[0]["cve_vulnerable"], 2);
    assert_eq!(hosts.json[0]["cve_reboot"], 1);
    assert_eq!(hosts.json[0]["cve_fixed"], 1);
}

/// Host-Ansicht: Gruppen nach Fix-Version stimmen mit den Einzelzeilen überein, Fix-Version-/Level-Filter,
/// `open_with_fix`, Sortierung nach Level dann Alter, Sonderzeichen.
#[sqlx::test(migrations = "./migrations")]
async fn host_cve_groups_match_rows_and_filters(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-35.35")).await,
        StatusCode::NO_CONTENT
    );
    let now = Utc::now() - Duration::minutes(10);
    mock.lock().unwrap().ubuntu = vec![
        ubuntu_cve("CVE-2026-30001", now, &[("noble", "needed", "")]),
        ubuntu_cve(
            "CVE-2026-30002",
            now,
            &[("noble", "released", "6.8.0-33.33")],
        ),
        ubuntu_cve(
            "CVE-2026-30003",
            now,
            &[("noble", "released", "6.8.0-33.33")],
        ),
        ubuntu_cve(
            "CVE-2026-30004",
            now,
            &[("noble", "released", "6.8.0-35.35")],
        ),
        ubuntu_cve(
            "CVE-2026-30005",
            now,
            &[("noble", "released", "6.8.0-30.30")],
        ),
        ubuntu_cve("CVE-2026-30006", now, &[("noble", "released", "6.8.0-9.9")]),
    ];
    refresh::refresh_all(&st).await;
    let cookies = login(&app, &pool).await;
    let h = hdr(&cookies);
    let url = format!("/api/v1/hosts/{hid}/cves");

    // Gruppen "Neustart nötig": neueste Version zuerst, Summe = Zähler = Einzelzeilen.
    let g = call(
        &app,
        Method::GET,
        &format!("{url}/groups?kind=reboot"),
        &h,
        None,
    )
    .await;
    assert_eq!(g.status, StatusCode::OK);
    let groups = g.json["groups"].as_array().unwrap();
    let got: Vec<(String, u64)> = groups
        .iter()
        .map(|x| {
            (
                x["fix_version"].as_str().unwrap().to_string(),
                x["count"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("6.8.0-35.35".to_string(), 1),
            ("6.8.0-33.33".to_string(), 2)
        ]
    );
    let all = call(
        &app,
        Method::GET,
        &format!("{url}?status=fixed_installed_reboot_required"),
        &h,
        None,
    )
    .await;
    assert_eq!(g.json["total"], all.json["total"]);
    assert_eq!(all.json["counts"]["fixed_installed_reboot_required"], 3);
    for (v, n) in &got {
        let one = call(
            &app,
            Method::GET,
            &format!("{url}?status=fixed_installed_reboot_required&fix_version={v}"),
            &h,
            None,
        )
        .await;
        assert_eq!(one.json["total"].as_u64().unwrap(), *n, "{v}");
        assert!(one.json["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["fix_version"] == v.as_str()));
    }
    // dpkg-Reihenfolge: 9.9 < 30.30 bei "fixed".
    let gf = call(
        &app,
        Method::GET,
        &format!("{url}/groups?kind=fixed"),
        &h,
        None,
    )
    .await;
    let fv: Vec<&str> = gf.json["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["fix_version"].as_str().unwrap())
        .collect();
    assert_eq!(fv, ["6.8.0-30.30", "6.8.0-9.9"]);
    // Offen ohne Fix: nie als Fix installiert gezählt, open_with_fix = 0.
    assert_eq!(all.json["open_with_fix"], 0);
    assert!(all.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["published_at"].is_string()));

    // Ungültige Gruppenart, Level-Filter, Sonderzeichen.
    let bad = call(
        &app,
        Method::GET,
        &format!("{url}/groups?kind=x;drop"),
        &h,
        None,
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let hi = call(&app, Method::GET, &format!("{url}?level_min=10"), &h, None).await;
    assert_eq!(hi.status, StatusCode::OK);
    assert!(hi.json["total"].as_u64().unwrap() <= 6);
    for term in ["caf%C3%A9", "%F0%9F%94%A5", "100%25", "a_b", "'%3B--"] {
        let r = call(
            &app,
            Method::GET,
            &format!("{url}/groups?kind=fixed&q={term}"),
            &h,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{term}");
        assert_eq!(r.json["total"], 0, "{term}");
        let r = call(
            &app,
            Method::GET,
            &format!("{url}?fix_version={term}"),
            &h,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{term}");
        assert_eq!(r.json["total"], 0, "{term}");
    }
}

/// Eine unvollständige Quelle erzeugt nie neue "gefixt"/"nicht betroffen"-Einträge; bereits Bekanntes bleibt stehen,
/// der Host zeigt den Hinweis "Bewertung eingeschränkt".
#[sqlx::test(migrations = "./migrations")]
async fn host_cves_incomplete_source_creates_no_new_fixed_entries(pool: PgPool) {
    let mock: Shared = Arc::default();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["ubuntu"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "web1").await;
    assert_eq!(
        report(&app, &noble("web1", "6.8.0-31.31", "6.8.0-35.35")).await,
        StatusCode::NO_CONTENT
    );
    let now = Utc::now() - Duration::minutes(10);
    mock.lock().unwrap().ubuntu = vec![ubuntu_cve(
        "CVE-2026-20002",
        now,
        &[("noble", "released", "6.8.0-30.30")],
    )];
    refresh::refresh_all(&st).await;
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-20002").await.as_deref(),
        Some("fixed")
    );

    // Quelle wird unvollständig (Abruf wird neu aufgebaut): neue CVEs werden nicht als gefixt erfasst.
    sqlx::query("UPDATE feed_state SET backfill = '{}'::jsonb")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cves (id) VALUES ('CVE-2026-20009')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO cve_source_status (cve_id, source, source_id, release, package, status, fix_version) \
         SELECT 'CVE-2026-20009', source, source_id, release, package, status, fix_version \
         FROM cve_source_status WHERE cve_id = 'CVE-2026-20002' LIMIT 1",
    )
    .execute(&pool)
    .await
    .unwrap();
    patchwatch_server::cve::reeval::reevaluate_all(&st)
        .await
        .unwrap();
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-20009").await,
        None,
        "kein neues gefixt aus unvollständiger Quelle"
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-20002").await.as_deref(),
        Some("fixed"),
        "Bekanntes bleibt"
    );
    let cookies = login(&app, &pool).await;
    let h = hdr(&cookies);
    let r = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{hid}/cves"),
        &h,
        None,
    )
    .await;
    assert!(
        r.json["issue"].as_str().unwrap().contains("unvollständig"),
        "{}",
        r.json
    );
}

// ---------- Debian: Archiv und Security getrennt ----------

fn tracker_with_suites() -> String {
    json!({"linux": {
        // A: Archiv unter der Fix-Version, Security darüber -> für Hosts mit Security gefixt
        "CVE-2026-98432": {"description": "A", "releases": {
            "trixie": {"status": "resolved", "fixed_version": "6.12.113-1", "urgency": "high",
                       "repositories": {"trixie": "6.12.107-1", "trixie-security": "6.12.115-2"}},
            "bookworm": {"status": "resolved", "fixed_version": "6.1.190-1", "urgency": "high",
                       "repositories": {"bookworm": "6.1.176-1", "bookworm-security": "6.1.190-1"}}}},
        // B: die Fix-Version steckt weder im Archiv noch in Security (z. B. nur in proposed-updates)
        "CVE-2026-98433": {"description": "B", "releases": {
            "trixie": {"status": "resolved", "fixed_version": "6.12.200-1", "urgency": "low",
                       "repositories": {"trixie": "6.12.107-1", "trixie-security": "6.12.115-2"}}}},
        // C: nicht betroffen
        "CVE-2026-98434": {"description": "C", "releases": {
            "trixie": {"status": "resolved", "fixed_version": "0", "urgency": "low",
                       "repositories": {"trixie": "6.12.107-1", "trixie-security": "6.12.115-2"}}}},
    }})
    .to_string()
}

fn trixie_host(version: &str) -> K<'_> {
    K {
        host: "deb1",
        os_id: "debian",
        os_version: "13",
        codename: "trixie",
        release: "6.12.107+deb13-amd64",
        package: "linux-image-6.12.107+deb13-amd64",
        source: "linux-signed-amd64",
        version,
        newest_release: "6.12.107+deb13-amd64",
        newest_version: version,
        proxmox: false,
    }
}

/// Suiten werden je Zeile gespeichert, der Chip-Status und die Filter "gefixt"/"offen" richten sich nach der neuen
/// Definition (gefixt = Security oder Archiv enthält den Fix), die Hostbewertung bleibt unverändert, und der Host mit
/// Archiv-Version unter dem Fix bekommt den Hinweis "Fix verfügbar über Security-Updates".
#[sqlx::test(migrations = "./migrations")]
async fn debian_suites_are_stored_and_drive_chip_filter_and_host_hint(pool: PgPool) {
    let mock: Shared = Arc::default();
    mock.lock().unwrap().debian_body = tracker_with_suites();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["debian"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    let hid = add_host(&pool, "deb1").await;
    assert_eq!(
        report(&app, &trixie_host("6.12.107-1")).await,
        StatusCode::NO_CONTENT
    );
    refresh::refresh_all(&st).await;

    // Rohdaten und gespeicherte Zeile: beide Suiten, je mit Version und Status.
    let suites: Value = sqlx::query_scalar(
        "SELECT suites FROM cve_source_status WHERE cve_id = 'CVE-2026-98432' AND source = 'debian' AND release = 'trixie'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        suites["trixie"],
        json!({"version": "6.12.107-1", "status": "vulnerable"})
    );
    assert_eq!(
        suites["trixie-security"],
        json!({"version": "6.12.115-2", "status": "fixed"})
    );

    let cookies = login(&app, &pool).await;
    let h = hdr(&cookies);
    let one = call(&app, Method::GET, "/api/v1/cves/CVE-2026-98432", &h, None).await;
    let chip_a = one.json["distros"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["release"] == "trixie")
        .unwrap()
        .clone();
    assert_eq!(chip_a["status"], "fixed");
    assert_eq!(chip_a["suites"]["trixie-security"]["status"], "fixed");
    assert_eq!(chip_a["suites"]["trixie"]["status"], "vulnerable");

    // Filter: A gefixt (Security hat den Fix), B offen (kein Archiv enthält die Fix-Version).
    let ids = |q: &'static str| {
        let app = app.clone();
        let hh: Vec<(String, String)> = cookies.clone();
        async move {
            let r = call(
                &app,
                Method::GET,
                &format!("/api/v1/cves?affects=all&limit=100{q}"),
                &hdr(&hh),
                None,
            )
            .await;
            let mut v: Vec<String> = r
                .json
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c["id"].as_str().unwrap().to_owned())
                .collect();
            v.sort();
            v
        }
    };
    assert_eq!(ids("&debian=fixed").await, ["CVE-2026-98432"]);
    assert_eq!(ids("&debian=open").await, ["CVE-2026-98433"]);
    let b = call(&app, Method::GET, "/api/v1/cves/CVE-2026-98433", &h, None).await;
    let chip_b = b.json["distros"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["release"] == "trixie")
        .unwrap();
    assert_eq!(
        chip_b["status"], "vulnerable",
        "Fix weder im Archiv noch in Security"
    );

    // Hostbewertung unverändert (eval.rs): Archiv-Kernel unter der Fix-Version bleibt verwundbar, mit Hinweis.
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-98432").await.as_deref(),
        Some("vulnerable")
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-98434").await.as_deref(),
        Some("not_affected")
    );
    let list = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{hid}/cves"),
        &h,
        None,
    )
    .await;
    let a = list.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["cve_id"] == "CVE-2026-98432")
        .unwrap();
    assert_eq!(a["fix_hint"], "security", "{a}");
    let b = list.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["cve_id"] == "CVE-2026-98433")
        .unwrap();
    assert!(
        b["fix_hint"].is_null(),
        "kein Fix in Security: kein Hinweis"
    );

    // Nach dem Installieren der Security-Version ist der Eintrag gefixt (nicht mehr "verfügbar").
    assert_eq!(
        report(&app, &trixie_host("6.12.115-2")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        cve_status(&pool, hid, "CVE-2026-98432").await.as_deref(),
        Some("fixed")
    );
}

/// Bestehende Zeilen ohne Suiten bleiben unverändert (suites = NULL); der nächste Import füllt sie nach,
/// ohne Änderungs-Ereignisse zu erzeugen und ohne Status oder Fix-Version anzufassen.
#[sqlx::test(migrations = "./migrations")]
async fn debian_suites_migration_keeps_rows_and_import_backfills_quietly(pool: PgPool) {
    let mock: Shared = Arc::default();
    mock.lock().unwrap().debian_body = tracker_with_suites();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["debian"], "", &base).await;
    refresh::refresh_all(&st).await;
    let before: (String, Option<String>) = sqlx::query_as(
        "SELECT status, fix_version FROM cve_source_status WHERE cve_id = 'CVE-2026-98432' AND release = 'trixie'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // Zustand vor der Migration nachstellen: Zeilen ohne Suiten, Abruf-Validatoren leer.
    sqlx::query("UPDATE cve_source_status SET raw = raw - 'suites' WHERE source = 'debian'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE feed_state SET etag = NULL, last_modified = NULL")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE suites IS NOT NULL"
        )
        .await,
        0
    );
    let events_before = count(&pool, "SELECT count(*) FROM events").await;

    refresh::refresh_all(&st).await;
    let after: (String, Option<String>) = sqlx::query_as(
        "SELECT status, fix_version FROM cve_source_status WHERE cve_id = 'CVE-2026-98432' AND release = 'trixie'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after, "Status und Fix-Version bleiben");
    assert!(
        count(
            &pool,
            "SELECT count(*) FROM cve_source_status WHERE suites IS NOT NULL"
        )
        .await
            > 0,
        "nachgefüllt"
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM events").await,
        events_before,
        "stille Nachfüllung, keine Ereignisse"
    );
}

/// Sonderzeichen in Release-/Paketnamen und Versionen stürzen weder Adapter noch API ab.
#[sqlx::test(migrations = "./migrations")]
async fn debian_suites_special_characters_do_not_crash(pool: PgPool) {
    let mock: Shared = Arc::default();
    mock.lock().unwrap().debian_body = json!({"linux": {"CVE-2026-98440": {"description": "café 🔥 <script>", "releases": {
        "trixie": {"status": "resolved", "fixed_version": "6.12.113-1", "urgency": "low",
                   "repositories": {"trixie": "kaputt version ünï", "trixie-security": "6.12.115-2", "trixie 🔥": "x"}}}}}})
    .to_string();
    let base = start_mock(mock.clone()).await;
    let st = setup(pool.clone(), &["debian"], "", &base).await;
    let app = patchwatch_server::router(st.clone());
    refresh::refresh_all(&st).await;
    let cookies = login(&app, &pool).await;
    let r = call(
        &app,
        Method::GET,
        "/api/v1/cves/CVE-2026-98440",
        &hdr(&cookies),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let s = &r.json["distros"][0]["suites"];
    assert_eq!(
        s["trixie"]["status"], "unknown",
        "ungültige Version bleibt unbekannt, nie grün"
    );
}

// ---------- CVE-Liste: „Betrifft meine Hosts“ ----------

async fn list_ids(app: &Router, h: &[(String, String)], query: &str) -> Vec<String> {
    let r = call(
        app,
        Method::GET,
        &format!("/api/v1/cves?{query}"),
        &hdr(h),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{query}: {}", r.json);
    r.json
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect()
}

/// A betrifft zwei Hosts, B einen, C ist überall gefixt (neueste Veröffentlichung, höchstes Level), D nur „unbekannt“
/// (Proxmox), E betrifft einen Host mit Sonderzeichen im Text.
async fn seed_affects(pool: &PgPool) {
    let h1 = add_host(pool, "web1").await;
    let h2 = add_host(pool, "web2").await;
    let h3 = add_host(pool, "pve1").await;
    for (id, prio, days, desc) in [
        ("CVE-2026-10001", "medium", 30, "A zwei Hosts"),
        ("CVE-2026-10002", "high", 20, "B ein Host"),
        ("CVE-2026-10003", "critical", 1, "C überall gefixt"),
        ("CVE-2026-10004", "critical", 2, "D nur unbekannt"),
        ("CVE-2026-10005", "low", 40, "E café 😀 ünïcode 100% _x_"),
        ("CVE-2026-10006", "low", 50, "F Neustart nötig"),
    ] {
        sqlx::query("INSERT INTO cves (id, description, priority, published_at) VALUES ($1, $2, $3, now() - make_interval(days => $4))")
            .bind(id)
            .bind(desc)
            .bind(prio)
            .bind(days)
            .execute(pool)
            .await
            .unwrap();
    }
    for (host, cve, st) in [
        (h1, "CVE-2026-10001", "vulnerable"),
        (h2, "CVE-2026-10001", "fix_pending"),
        (h1, "CVE-2026-10002", "vulnerable"),
        (h2, "CVE-2026-10002", "fixed"),
        (h1, "CVE-2026-10003", "fixed"),
        (h2, "CVE-2026-10003", "not_affected"),
        (h3, "CVE-2026-10004", "unknown"),
        (h1, "CVE-2026-10005", "vulnerable"),
        (h1, "CVE-2026-10006", "fixed_installed_reboot_required"),
    ] {
        sqlx::query("INSERT INTO host_cve_status (host_id, cve_id, status, reason) VALUES ($1, $2, $3, 'test')")
            .bind(host)
            .bind(cve)
            .bind(st)
            .execute(pool)
            .await
            .unwrap();
    }
    // Quelleneinträge: Debian für A und C, Ubuntu für B (ein Release ohne Host, deshalb mit releases=all).
    for (cve, src, rel, st) in [
        ("CVE-2026-10001", "debian", "trixie", "vulnerable"),
        ("CVE-2026-10003", "debian", "trixie", "fixed"),
        ("CVE-2026-10002", "ubuntu", "noble", "vulnerable"),
        ("CVE-2026-10003", "ubuntu", "noble", "vulnerable"),
    ] {
        sqlx::query("INSERT INTO cve_source_status (cve_id, source, release, package, status) VALUES ($1, $2, $3, 'linux', $4)")
            .bind(cve)
            .bind(src)
            .bind(rel)
            .bind(st)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn cve_list_puts_cves_affecting_my_hosts_first(pool: PgPool) {
    let st = setup(pool.clone(), &[], "", "http://127.0.0.1:9").await;
    let app = patchwatch_server::router(st);
    let h = login(&app, &pool).await;
    seed_affects(&pool).await;

    // Standard = „Meine Hosts“: nur CVEs mit mindestens einem verwundbaren, angekündigten oder Neustart-Host,
    // zuerst die mit den meisten Hosts. C (gefixt/nicht betroffen) und D (nur unbekannt) fehlen.
    assert_eq!(
        list_ids(&app, &h, "").await,
        [
            "CVE-2026-10001",
            "CVE-2026-10002",
            "CVE-2026-10005",
            "CVE-2026-10006"
        ],
        "A (2 Hosts) vor B (high) vor E, F (je 1 Host, nach Level)"
    );
    assert_eq!(
        list_ids(&app, &h, "affects=mine").await,
        list_ids(&app, &h, "").await
    );

    // „Alle“: dieselben zuerst, danach der Rest nach Level und Alter (C vor D: jüngere Veröffentlichung).
    let all = list_ids(&app, &h, "affects=all").await;
    assert_eq!(
        &all[..4],
        [
            "CVE-2026-10001",
            "CVE-2026-10002",
            "CVE-2026-10005",
            "CVE-2026-10006"
        ]
    );
    assert_eq!(
        &all[4..],
        ["CVE-2026-10003", "CVE-2026-10004"].map(String::from)
    );

    // Spalte „Hosts“: absteigend (Standard) und aufsteigend nach Anzahl betroffener Hosts.
    let asc = list_ids(&app, &h, "affects=all&sort=hosts&dir=asc").await;
    assert_eq!(
        asc.last().unwrap(),
        "CVE-2026-10001",
        "meiste Hosts zuletzt bei aufsteigend"
    );
    let r = call(&app, Method::GET, "/api/v1/cves?sort=hosts", &hdr(&h), None).await;
    assert_eq!(r.json[0]["hosts_vulnerable"], 1);
    assert_eq!(r.json[0]["hosts_fix_pending"], 1);
    let f = call(&app, Method::GET, "/api/v1/cves?q=10006", &hdr(&h), None).await;
    assert_eq!(
        f.json[0]["hosts_reboot"], 1,
        "Neustart nötig wird mitgezählt"
    );

    // Ungültige Werte: 400, nie SQL.
    for bad in ["affects=x", "sort=hosts;drop", "affects=all'"] {
        assert_eq!(
            call(
                &app,
                Method::GET,
                &format!("/api/v1/cves?{bad}"),
                &hdr(&h),
                None
            )
            .await
            .status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    // Alte Sortierungen funktionieren weiter.
    assert_eq!(
        list_ids(&app, &h, "affects=all&sort=latest").await[0],
        "CVE-2026-10003"
    );
    assert_eq!(
        list_ids(&app, &h, "affects=all&sort=level").await[0],
        "CVE-2026-10003"
    );

    // Zähler für die Zeile über der Liste.
    let r = call(
        &app,
        Method::GET,
        "/api/v1/cves/scope-count",
        &hdr(&h),
        None,
    )
    .await;
    assert_eq!(r.json["affecting"], 4, "{}", r.json);
}

#[sqlx::test(migrations = "./migrations")]
async fn cve_list_affects_combines_with_debian_ubuntu_filter_search_and_paging(pool: PgPool) {
    let st = setup(pool.clone(), &[], "", "http://127.0.0.1:9").await;
    let app = patchwatch_server::router(st);
    let h = login(&app, &pool).await;
    seed_affects(&pool).await;

    // Debian offen: nur A (C ist gefixt); mit „Alle“ ändert sich daran nichts, mit Ubuntu offen kommt B (C ist nicht betroffen).
    assert_eq!(
        list_ids(&app, &h, "releases=all&debian=open").await,
        ["CVE-2026-10001"]
    );
    assert_eq!(
        list_ids(&app, &h, "releases=all&ubuntu=open").await,
        ["CVE-2026-10002"]
    );
    assert_eq!(
        list_ids(&app, &h, "releases=all&ubuntu=open&affects=all").await,
        ["CVE-2026-10002", "CVE-2026-10003"]
    );
    assert_eq!(
        list_ids(&app, &h, "releases=all&debian=fixed").await,
        Vec::<String>::new()
    );
    assert_eq!(
        list_ids(&app, &h, "releases=all&debian=fixed&affects=all").await,
        ["CVE-2026-10003"]
    );
    assert_eq!(
        list_ids(&app, &h, "releases=all&distro=debian").await,
        ["CVE-2026-10001"]
    );

    // Gezielte Suche findet jede CVE (auch ohne betroffene Hosts); Sonderzeichen stürzen nicht ab.
    assert_eq!(
        list_ids(&app, &h, "q=CVE-2026-10003").await,
        ["CVE-2026-10003"]
    );
    assert_eq!(list_ids(&app, &h, "q=caf%C3%A9").await, ["CVE-2026-10005"]);
    assert_eq!(
        list_ids(&app, &h, "q=%F0%9F%98%80").await,
        ["CVE-2026-10005"]
    );
    assert_eq!(list_ids(&app, &h, "q=100%25").await, ["CVE-2026-10005"]);
    for q in ["%27%3B--", "%00", "%25%25", "%5C"] {
        let s = call(
            &app,
            Method::GET,
            &format!("/api/v1/cves?q={q}"),
            &hdr(&h),
            None,
        )
        .await
        .status;
        assert!(
            s == StatusCode::OK || s == StatusCode::BAD_REQUEST,
            "{q}: {s}"
        );
    }

    // Paginierung über mehrere Seiten: dieselbe Reihenfolge wie die ganze Liste, keine Lücke, keine Doppelten.
    let full = list_ids(&app, &h, "affects=all").await;
    let mut paged = Vec::new();
    for off in (0..full.len()).step_by(2) {
        paged.extend(list_ids(&app, &h, &format!("affects=all&limit=2&offset={off}")).await);
    }
    assert_eq!(paged, full);
    assert_eq!(full.len(), 6);
}

// ---------- CVE-Liste: „Aktualisiert“ = Änderung laut Quelle, nie der Importzeitpunkt ----------

fn rec(id: &str, updated: Option<chrono::DateTime<Utc>>) -> patchwatch_server::cve::Record {
    use patchwatch_server::cve::{Entry, Record, SourceStatus};
    Record {
        cve_id: id.into(),
        description: Some("test".into()),
        updated_at: updated,
        entries: vec![Entry {
            release: "noble".into(),
            package: "linux".into(),
            status: SourceStatus::Vulnerable,
            fix_version: None,
            raw: json!({}),
        }],
        ..Record::default()
    }
}

async fn import(pool: &PgPool, source: &str, recs: &[patchwatch_server::cve::Record]) {
    let mut c = pool.acquire().await.unwrap();
    patchwatch_server::cve::ingest::ingest(&mut c, source, recs)
        .await
        .unwrap();
}

async fn updated_of(app: &Router, h: &[(String, String)], id: &str) -> Value {
    let r = call(
        app,
        Method::GET,
        &format!("/api/v1/cves?affects=all&releases=all&q={id}"),
        &hdr(h),
        None,
    )
    .await;
    r.json[0]["updated_at"].clone()
}

#[sqlx::test(migrations = "./migrations")]
async fn cve_updated_shows_source_date_never_import_time(pool: PgPool) {
    let st = setup(pool.clone(), &[], "", "http://127.0.0.1:9").await;
    let app = patchwatch_server::router(st);
    let h = login(&app, &pool).await;
    let t1 = Utc::now() - Duration::days(30);
    let t2 = Utc::now() - Duration::days(3);
    let t0 = Utc::now() - Duration::days(90);

    // Quelle mit Datum liefert genau dieses Datum; Quelle ohne Datum (OVAL, Debian): „unbekannt“ = null.
    import(
        &pool,
        "ubuntu",
        &[rec("CVE-2026-20001", Some(t1)), rec("CVE-2026-20002", None)],
    )
    .await;
    let dated = updated_of(&app, &h, "CVE-2026-20001").await;
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(dated.as_str().unwrap())
            .unwrap()
            .timestamp(),
        t1.timestamp()
    );
    assert_eq!(
        updated_of(&app, &h, "CVE-2026-20002").await,
        Value::Null,
        "ohne Quelldatum nie der Importzeitpunkt"
    );
    let synced: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_synced_at FROM cves WHERE id = 'CVE-2026-20002'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        synced.is_some_and(|s| (Utc::now() - s).num_seconds() < 60),
        "Importzeitpunkt steht getrennt in last_synced_at"
    );

    // Erneuter Import (unverändert, mit und ohne Datum) ändert „Aktualisiert“ nicht; der Abgleich rückt vor.
    sqlx::query("UPDATE cves SET last_synced_at = now() - interval '1 day'")
        .execute(&pool)
        .await
        .unwrap();
    import(
        &pool,
        "ubuntu",
        &[rec("CVE-2026-20001", Some(t1)), rec("CVE-2026-20002", None)],
    )
    .await;
    import(
        &pool,
        "debian",
        &[rec("CVE-2026-20001", None), rec("CVE-2026-20002", None)],
    )
    .await;
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(
            updated_of(&app, &h, "CVE-2026-20001")
                .await
                .as_str()
                .unwrap()
        )
        .unwrap()
        .timestamp(),
        t1.timestamp()
    );
    assert_eq!(updated_of(&app, &h, "CVE-2026-20002").await, Value::Null);
    let fresh: i64 = count(
        &pool,
        "SELECT count(*) FROM cves WHERE last_synced_at > now() - interval '1 hour'",
    )
    .await;
    assert_eq!(fresh, 2, "auch unveränderte CVEs gelten als abgeglichen");

    // Zweite Quelle mit neuerem Datum gewinnt, mit älterem nicht; ein Datum füllt eine bisher unbekannte CVE nach.
    import(
        &pool,
        "osv",
        &[
            rec("CVE-2026-20001", Some(t2)),
            rec("CVE-2026-20002", Some(t0)),
        ],
    )
    .await;
    import(&pool, "ubuntu", &[rec("CVE-2026-20001", Some(t0))]).await;
    let ts = |v: Value| {
        chrono::DateTime::parse_from_rfc3339(v.as_str().unwrap())
            .unwrap()
            .timestamp()
    };
    assert_eq!(
        ts(updated_of(&app, &h, "CVE-2026-20001").await),
        t2.timestamp()
    );
    assert_eq!(
        ts(updated_of(&app, &h, "CVE-2026-20002").await),
        t0.timestamp()
    );

    // Sortierung nach „Aktualisiert“ nutzt das Quelldatum; CVEs ohne Datum stehen in beiden Richtungen zuletzt.
    import(&pool, "ubuntu", &[rec("CVE-2026-20003", None)]).await;
    assert_eq!(
        list_ids(&app, &h, "affects=all&releases=all&sort=updated").await,
        ["CVE-2026-20001", "CVE-2026-20002", "CVE-2026-20003"]
    );
    assert_eq!(
        list_ids(&app, &h, "affects=all&releases=all&sort=updated&dir=asc").await,
        ["CVE-2026-20002", "CVE-2026-20001", "CVE-2026-20003"]
    );

    // Detail: Quelldatum und Abgleich getrennt, „unbekannt“ bleibt null.
    let d = call(
        &app,
        Method::GET,
        "/api/v1/cves/CVE-2026-20003",
        &hdr(&h),
        None,
    )
    .await;
    assert_eq!(d.json["last_change_at"], Value::Null);
    assert!(d.json["last_synced_at"].is_string());
}
