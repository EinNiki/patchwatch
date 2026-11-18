use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use http_body_util::BodyExt;
use patchwatch_server::{admin, config::Config, router, security, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tower::ServiceExt;

type Session = (String, String);
async fn call(
    app: &Router,
    method: Method,
    path: &str,
    session: Option<&Session>,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some((cookie, csrf)) = session {
        request = request
            .header("cookie", cookie)
            .header("x-csrf-token", csrf);
    }
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(
            request
                .header("content-type", "application/json")
                .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookie,
    )
}
async fn setup(pool: &PgPool, base: Option<&str>) -> (Router, Session, i64) {
    let cfg = Config::from_sources(None, &|key| {
        (key == "PATCHWATCH_CVE_OSV_URL").then(|| base.unwrap_or("https://api.osv.dev").to_owned())
    })
    .unwrap();
    let app = router(AppState::new(pool.clone(), cfg).unwrap());
    admin::upsert_admin(pool, "admin", "a-long-test-password")
        .await
        .unwrap();
    let (status, json, cookie) = call(
        &app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"username":"admin","password":"a-long-test-password"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id =
        sqlx::query_scalar("INSERT INTO hosts(name,token_hash) VALUES ('host',$1) RETURNING id")
            .bind(security::sha256("pw_sbom-token-0123456789abcdef"))
            .fetch_one(pool)
            .await
            .unwrap();
    (
        app,
        (
            cookie.unwrap(),
            json["csrf_token"].as_str().unwrap().to_owned(),
        ),
        id,
    )
}
fn input(components: Value) -> Value {
    json!({"label":"Webshop","kind":"container","identity":"example/webshop@sha256:abc",
        "sbom":{"bomFormat":"CycloneDX","specVersion":"1.6","components":components}})
}
async fn put(app: &Router, s: &Session, host: i64, key: &str, components: Value) -> Value {
    let (status, body, _) = call(
        app,
        Method::PUT,
        &format!("/api/v1/hosts/{host}/inventories/{key}"),
        Some(s),
        None,
        Some(input(components)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}
async fn items(app: &Router, s: &Session, filter: &str) -> Value {
    let (status, body, _) = call(
        app,
        Method::GET,
        &format!("/api/v1/software?{filter}"),
        Some(s),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[sqlx::test(migrations = "./migrations")]
async fn import_preserves_instances_and_replaces_only_its_context(pool: PgPool) {
    let (app, s, h) = setup(&pool, None).await;
    let original = put(
        &app,
        &s,
        h,
        "web",
        json!([
            {"bom-ref":"one","name":"same","version":"1","purl":"pkg:npm/same@1"},
            {"bom-ref":"two","name":"same","version":"2","purl":"pkg:npm/same@2"},
            {"bom-ref":"private","name":"custom-app"}
        ]),
    )
    .await;
    put(&app, &s, h, "other", json!([{"name":"same","version":"3"}])).await;
    let listed = items(&app, &s, "kind=container").await;
    assert_eq!(listed["total"], 4);
    let ids: std::collections::HashSet<_> = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 4, "each installation has its own identity");
    assert!(listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["status"] == "unknown"));
    let updated = put(
        &app,
        &s,
        h,
        "web",
        json!([{"name":"replacement","version":"4"}]),
    )
    .await;
    assert_eq!(updated["id"], original["id"]);
    assert_eq!(updated["generation"], 2);
    assert_eq!(items(&app, &s, "").await["total"], 2);
    assert_eq!(items(&app, &s, "kind=system").await["total"], 0);
    assert_eq!(items(&app, &s, "q=sha256%3Aabc").await["total"], 2);
    let (status, _, _) = call(
        &app,
        Method::PUT,
        &format!("/api/v1/hosts/{h}/inventories/web"),
        Some(&s),
        None,
        Some(input(
            json!([{"name":"x","version":"1","purl":"pkg:npm/x@2"}]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        items(&app, &s, "").await["total"],
        2,
        "a rejected import is atomic"
    );
    put(&app, &s, h, "web", json!([])).await;
    assert_eq!(items(&app, &s, "").await["total"], 1);
    let (status, _, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/hosts/{h}/inventories/other"),
        Some(&s),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(items(&app, &s, "").await["total"], 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn uploads_require_csrf_or_the_owning_host_token(pool: PgPool) {
    let (app, s, h) = setup(&pool, None).await;
    let without_csrf = (s.0.clone(), String::new());
    let path = format!("/api/v1/hosts/{h}/inventories/app");
    assert_eq!(
        call(
            &app,
            Method::PUT,
            &path,
            Some(&without_csrf),
            None,
            Some(input(json!([])))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, Method::PUT, &path, None, None, Some(input(json!([]))))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let second: i64 = sqlx::query_scalar(
        "INSERT INTO hosts(name,token_hash) VALUES('other','other') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut upload = input(json!([{"name":"private-tool"}]));
    upload["host_id"] = json!(second);
    assert_eq!(
        call(
            &app,
            Method::PUT,
            "/api/v1/agent/inventories/ci",
            None,
            Some("pw_sbom-token-0123456789abcdef"),
            Some(upload)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(items(&app, &s, &format!("host_id={h}")).await["total"], 1);
    assert_eq!(
        items(&app, &s, &format!("host_id={second}")).await["total"],
        0
    );
    sqlx::query("UPDATE admin_users SET permissions=ARRAY['hosts.read'] WHERE username='admin'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            Method::PUT,
            &path,
            Some(&s),
            None,
            Some(input(json!([])))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[derive(Default)]
struct Mock {
    calls: AtomicUsize,
    fail: AtomicBool,
    slow: AtomicBool,
    entered: tokio::sync::Notify,
}
async fn mock(State(st): State<Arc<Mock>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    st.calls.fetch_add(1, Ordering::SeqCst);
    st.entered.notify_one();
    if st.slow.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    if st.fail.load(Ordering::SeqCst) {
        return (StatusCode::OK, Json(json!({"unexpected":true})));
    }
    let results: Vec<_> = body["queries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| {
            assert!(q.get("version").is_none(), "a versioned PURL is sufficient");
            if q["package"]["purl"]
                .as_str()
                .unwrap()
                .contains("demo-vulnerable")
            {
                if q.get("page_token").is_none() {
                    json!({"vulns":[{"id":"GHSA-test-first"}],"next_page_token":"next"})
                } else {
                    json!({"vulns":[{"id":"RUSTSEC-2099-0001"}]})
                }
            } else {
                json!({})
            }
        })
        .collect();
    (StatusCode::OK, Json(json!({"results":results})))
}
async fn start(st: Arc<Mock>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/querybatch", post(mock))
                .with_state(st),
        )
        .await
        .unwrap();
    });
    base
}
async fn enable(pool: &PgPool) {
    sqlx::query("INSERT INTO cve_sources(id,kind,label) VALUES('osv','osv','OSV')")
        .execute(pool)
        .await
        .unwrap();
}
async fn scan(app: &Router, s: &Session, id: i64) -> (StatusCode, Value) {
    let (status, body, _) = call(
        app,
        Method::POST,
        &format!("/api/v1/software/inventories/{id}/scan"),
        Some(s),
        None,
        Some(json!({})),
    )
    .await;
    (status, body)
}

#[sqlx::test(migrations = "./migrations")]
async fn osv_pagination_cache_and_disabled_sources_are_conservative(pool: PgPool) {
    let state = Arc::new(Mock::default());
    let base = start(state.clone()).await;
    let (app, s, h) = setup(&pool, Some(&base)).await;
    enable(&pool).await;
    let bom = json!([
        {"name":"demo-vulnerable","version":"1.0.0","purl":"pkg:npm/demo-vulnerable@1.0.0"},
        {"name":"serde","version":"1.0.0","purl":"pkg:cargo/serde@1.0.0"},
        {"name":"private"}, {"name":"openssl","version":"1","purl":"pkg:deb/debian/openssl@1"},
        {"name":"private-registry","purl":"pkg:npm/private-registry@1.0.0?repository_url=https%3A%2F%2Fprivate.example"}
    ]);
    let id = put(&app, &s, h, "app", bom.clone()).await["id"]
        .as_i64()
        .unwrap();
    let (status, r) = scan(&app, &s, id).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["checked"], 2);
    assert_eq!(r["unmatched"], 3);
    assert_eq!(
        state.calls.load(Ordering::SeqCst),
        2,
        "pagination must complete"
    );
    let listed = items(&app, &s, "").await;
    let rows = listed["items"].as_array().unwrap();
    let vuln = rows
        .iter()
        .find(|v| v["name"] == "demo-vulnerable")
        .unwrap();
    assert_eq!(vuln["status"], "vulnerable");
    assert_eq!(vuln["findings"].as_array().unwrap().len(), 2);
    assert!(vuln["findings"][0]["url"]
        .as_str()
        .unwrap()
        .starts_with("https://osv.dev/vulnerability/"));
    assert_eq!(
        rows.iter().find(|v| v["name"] == "serde").unwrap()["status"],
        "no_known_findings"
    );
    let second = put(&app, &s, h, "other", bom).await["id"].as_i64().unwrap();
    assert_eq!(scan(&app, &s, second).await.1["checked"], 2);
    assert_eq!(
        state.calls.load(Ordering::SeqCst),
        2,
        "identical versions reuse the cache"
    );
    sqlx::query("UPDATE cve_sources SET enabled=false WHERE id='osv'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(items(&app, &s, "").await["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["status"] == "unknown" && v["findings"].as_array().unwrap().is_empty()));
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_scans_never_clear_known_vulnerabilities_or_confirm_empty_results(pool: PgPool) {
    let state = Arc::new(Mock::default());
    let base = start(state.clone()).await;
    let (app, s, h) = setup(&pool, Some(&base)).await;
    enable(&pool).await;
    let id = put(
        &app,
        &s,
        h,
        "app",
        json!([
            {"name":"demo-vulnerable","purl":"pkg:npm/demo-vulnerable@1.0.0"},
            {"name":"serde","purl":"pkg:cargo/serde@1.0.0"}
        ]),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    assert_eq!(scan(&app, &s, id).await.1["ok"], true);
    sqlx::query("DELETE FROM software_osv_cache")
        .execute(&pool)
        .await
        .unwrap();
    state.fail.store(true, Ordering::SeqCst);
    assert_eq!(scan(&app, &s, id).await.1["ok"], false);
    let listed = items(&app, &s, "").await;
    assert_eq!(listed["items"][0]["status"], "vulnerable");
    assert_eq!(listed["items"][1]["status"], "unknown");
    sqlx::query("UPDATE admin_users SET permissions=ARRAY['hosts.read'] WHERE username='admin'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(items(&app, &s, "").await["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["findings"].as_array().unwrap().is_empty()));
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_reimports_discard_scan_results_for_old_components(pool: PgPool) {
    let state = Arc::new(Mock::default());
    state.slow.store(true, Ordering::SeqCst);
    let base = start(state.clone()).await;
    let (app, s, h) = setup(&pool, Some(&base)).await;
    enable(&pool).await;
    let id = put(
        &app,
        &s,
        h,
        "app",
        json!([{"name":"serde","purl":"pkg:cargo/serde@1.0.0"}]),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    let app2 = app.clone();
    let s2 = s.clone();
    let scanning = tokio::spawn(async move { scan(&app2, &s2, id).await });
    tokio::time::timeout(Duration::from_secs(2), state.entered.notified())
        .await
        .unwrap();
    put(
        &app,
        &s,
        h,
        "app",
        json!([{"name":"serde","purl":"pkg:cargo/serde@2.0.0"}]),
    )
    .await;
    assert_eq!(scanning.await.unwrap().0, StatusCode::CONFLICT);
    let listed = items(&app, &s, "").await;
    assert_eq!(listed["items"][0]["version"], "2.0.0");
    assert_eq!(listed["items"][0]["status"], "unknown");
}
