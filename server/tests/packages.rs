//! Pakete und ausstehende Updates je Host: Schema 2, Hash, Wiederanforderung, Migration (Wegwerf-Datenbank).
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use patchwatch_server::config::Config;
use patchwatch_server::{admin, router, security, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

const TOKEN: &str = "pw_test-token-nur-fuer-tests-0123456789abcdef";
const PASSWORD: &str = "ein-langes-test-passwort";
const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn state(pool: PgPool) -> AppState {
    let cfg = Config::from_sources(None, &|_| None).unwrap();
    AppState::new(pool, cfg).unwrap()
}

async fn add_host(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO hosts (name, token_hash) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(security::sha256(TOKEN))
        .fetch_one(pool)
        .await
        .unwrap()
}

struct Resp {
    status: StatusCode,
    json: Value,
    cookie: Option<String>,
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
        cookie: parts
            .headers
            .get(header::SET_COOKIE)
            .and_then(|c| c.to_str().ok())
            .map(|c| c.split(';').next().unwrap().to_owned()),
        json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

async fn login(app: &Router, pool: &PgPool) -> String {
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
    r.cookie.unwrap()
}

fn pkg(name: &str, version: &str, arch: &str) -> Value {
    json!({"name": name, "version": version, "arch": arch, "source": name, "source_version": version})
}

/// Report im Schema 2; `packages` None = nur der Hash.
fn report(packages: Option<Vec<Value>>, hash: Option<&str>, items: Option<Value>) -> Value {
    let mut updates = json!({"pending": 2, "security": 1, "remove": 1});
    if let Some(i) = items {
        updates["items"] = i;
    }
    json!({
        "schema_version": 2, "agent_version": "0.2.0", "hostname": "web1", "collected_at_unix": 1,
        "os": {"id": "debian", "version_id": "13", "codename": "trixie", "pretty_name": "Debian 13"},
        "kernel": {"running_release": "6.12.0-1-amd64", "running_package": null,
                   "newest_installed_release": null, "newest_installed_package": null, "reboot_needed_kernel": null},
        "reboot_required_file": false, "updates": updates, "uptime_seconds": 10, "proxmox": null,
        "packages": packages, "packages_hash": hash, "packages_count": 3, "packages_truncated": false,
        "apt_lists_updated_unix": 1_700_000_000
    })
}

fn items() -> Value {
    json!([
        {"name": "openssl", "kind": "upgrade", "from": "3.0.1", "to": "3.0.2", "origin": "Debian-Security:13/trixie-security", "security": true},
        {"name": "newpkg", "kind": "new", "from": null, "to": "1.0", "origin": "Debian:13/stable", "security": false},
        {"name": "oldpkg", "kind": "remove", "from": "0.9", "to": null, "origin": "", "security": false}
    ])
}

async fn send(app: &Router, body: Value) -> Resp {
    let auth = format!("Bearer {TOKEN}");
    call(
        app,
        Method::POST,
        "/api/v1/report",
        &[("authorization", &auth)],
        Some(body),
    )
    .await
}

#[sqlx::test(migrations = "./migrations")]
async fn schema_2_stores_packages_hash_update_kinds_and_list_age(pool: PgPool) {
    let app = router(state(pool.clone()));
    let id = add_host(&pool, "web1").await;
    let pk = vec![
        pkg("bash", "5.2", "amd64"),
        pkg("libc6", "2.41", "amd64"),
        pkg("libc6", "2.40", "i386"),
    ];
    assert_eq!(
        send(&app, report(Some(pk), Some(HASH_A), Some(items())))
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    let (hash, count, truncated, lists, listed, remove): (Option<String>, Option<i32>, bool, Option<i64>, bool, Option<i32>) =
        sqlx::query_as(
            "SELECT packages_hash, packages_count, packages_truncated, extract(epoch from apt_lists_updated_at)::bigint, \
             updates_listed, updates_remove FROM hosts WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        (hash.as_deref(), count, truncated),
        (Some(HASH_A), Some(3), false)
    );
    assert_eq!(
        (lists, listed, remove),
        (Some(1_700_000_000), true, Some(1))
    );
    // Multiarch: ein Eintrag je Name, die niedrigere Version gewinnt (Regel F1), samt Architektur.
    let libc: (String, Option<String>) = sqlx::query_as(
        "SELECT version, arch FROM host_packages WHERE host_id = $1 AND name = 'libc6'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(libc, ("2.40".into(), Some("i386".into())));
    let kinds: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT name, kind, security FROM host_updates WHERE host_id = $1 ORDER BY name",
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        kinds,
        [
            ("newpkg".into(), "new".into(), false),
            ("oldpkg".into(), "remove".into(), false),
            ("openssl".into(), "upgrade".into(), true)
        ]
    );
    // Die Liste gehört nicht in die Historie.
    let raw_has_list: i64 =
        sqlx::query_scalar("SELECT count(*) FROM reports WHERE raw ? 'packages'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(raw_has_list, 0);

    // Route: Sicherheit zuerst, dann Art; Entfernen ohne Zielversion.
    let session = login(&app, &pool).await;
    let got = call(
        &app,
        Method::GET,
        &format!("/api/v1/hosts/{id}/updates"),
        &[("cookie", &session)],
        None,
    )
    .await;
    let names: Vec<&str> = got.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["openssl", "newpkg", "oldpkg"]);
    assert_eq!(got.json["items"][2]["kind"], "remove");
    assert_eq!(got.json["items"][2]["to"], Value::Null);
}

#[sqlx::test(migrations = "./migrations")]
async fn unchanged_hash_keeps_the_stored_list_and_a_changed_one_asks_for_it(pool: PgPool) {
    let app = router(state(pool.clone()));
    let id = add_host(&pool, "web1").await;
    let pk = vec![pkg("bash", "5.2", "amd64")];
    assert_eq!(
        send(&app, report(Some(pk.clone()), Some(HASH_A), None))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let count = |pool: &PgPool| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM host_packages WHERE host_id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    // Gleicher Hash, keine Liste: nichts ändert sich, keine Wiederanforderung.
    let same = send(&app, report(None, Some(HASH_A), None)).await;
    assert_eq!(same.status, StatusCode::NO_CONTENT);
    assert_eq!(count(&pool).await, 1);
    let requested: bool =
        sqlx::query_scalar("SELECT report_requested_at IS NOT NULL FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!requested);

    // Anderer Hash ohne Liste (z. B. Datenbank wiederhergestellt): der Agent soll die Liste nachliefern.
    let ask = send(&app, report(None, Some(HASH_B), None)).await;
    assert_eq!(ask.status, StatusCode::OK);
    assert_eq!(ask.json["need_packages"], true);
    assert_eq!(
        count(&pool).await,
        1,
        "bestehende Liste bleibt, bis die neue kommt"
    );
    let requested: bool =
        sqlx::query_scalar("SELECT report_requested_at IS NOT NULL FROM hosts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(requested, "Bericht wird beim nächsten Check-in angefordert");
    // Mit Liste ist es erledigt.
    let ok = send(
        &app,
        report(
            Some(vec![pkg("bash", "5.3", "amd64"), pkg("curl", "8", "amd64")]),
            Some(HASH_B),
            None,
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::NO_CONTENT);
    assert_eq!(count(&pool).await, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn first_seen_survives_and_vanished_updates_are_removed(pool: PgPool) {
    let app = router(state(pool.clone()));
    let id = add_host(&pool, "web1").await;
    send(&app, report(None, None, Some(items()))).await;
    let first: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT first_seen FROM host_updates WHERE host_id = $1 AND name = 'openssl'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    // Nur noch openssl: die anderen verschwinden, die erste Sichtung von openssl bleibt.
    send(&app, report(None, None, Some(json!([items()[0].clone()])))).await;
    let rows: Vec<(
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as("SELECT name, first_seen, last_seen FROM host_updates WHERE host_id = $1")
        .bind(id)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, first);
    assert!(rows[0].2 > first);
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_schema_2_fields_are_rejected_and_schema_1_still_works(pool: PgPool) {
    let app = router(state(pool.clone()));
    add_host(&pool, "web1").await;
    let mut bad_hash = report(None, Some("ZZ"), None);
    assert_eq!(
        send(&app, bad_hash.clone()).await.status,
        StatusCode::BAD_REQUEST
    );
    bad_hash["packages_hash"] = json!(HASH_A.to_uppercase());
    assert_eq!(
        send(&app, bad_hash).await.status,
        StatusCode::BAD_REQUEST,
        "nur Kleinbuchstaben-Hex"
    );
    let bad_kind = report(
        None,
        None,
        Some(
            json!([{"name": "x", "kind": "purge", "from": null, "to": "1", "origin": "o", "security": false}]),
        ),
    );
    assert_eq!(send(&app, bad_kind).await.status, StatusCode::BAD_REQUEST);
    let no_to = report(
        None,
        None,
        Some(
            json!([{"name": "x", "kind": "upgrade", "from": "1", "to": null, "origin": "o", "security": false}]),
        ),
    );
    assert_eq!(send(&app, no_to).await.status, StatusCode::BAD_REQUEST);
    let bad_arch = report(
        Some(vec![json!({"name": "x", "version": "1", "arch": "a b"})]),
        Some(HASH_A),
        None,
    );
    assert_eq!(send(&app, bad_arch).await.status, StatusCode::BAD_REQUEST);
    let mut v3 = report(None, None, None);
    v3["schema_version"] = json!(3);
    assert_eq!(send(&app, v3).await.status, StatusCode::BAD_REQUEST);
    // Schema 1 ohne die neuen Felder (älterer Agent): angenommen, Update-Art aus `from` abgeleitet.
    let mut old = report(
        None,
        None,
        Some(json!([
        {"name": "libc6", "from": "2.35-1", "to": "2.35-2", "origin": "Ubuntu:22.04/jammy-security", "security": true},
        {"name": "vim", "from": null, "to": "9", "origin": "Ubuntu", "security": false}])),
    );
    old["schema_version"] = json!(1);
    for k in [
        "packages_hash",
        "packages_count",
        "packages_truncated",
        "apt_lists_updated_unix",
    ] {
        old.as_object_mut().unwrap().remove(k);
    }
    assert_eq!(send(&app, old).await.status, StatusCode::NO_CONTENT);
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM host_updates ORDER BY name")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(kinds, ["upgrade", "new"]);
}

/// Die Migration ändert und löscht nichts: Zeilen aus dem Stand vor 0027 bleiben, alte Update-Listen werden übernommen.
#[sqlx::test(migrations = false)]
async fn migration_0027_keeps_existing_rows_and_adopts_old_update_lists(pool: PgPool) {
    let all = sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .unwrap();
    // Teilstand bis einschließlich 0026: gleiche Migrationen, nur gefiltert (sqlx 0.8 hat kein `run_to`).
    let mut before = sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await
        .unwrap();
    before.migrations = std::borrow::Cow::Owned(
        all.migrations
            .iter()
            .filter(|m| m.version <= 26)
            .cloned()
            .collect(),
    );
    before.run(&pool).await.unwrap();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO hosts (name, token_hash, updates_pending, updates_list) VALUES ('alt', 'h', 2, $1) RETURNING id",
    )
    .bind(json!([
        {"name": "libc6", "from": "1", "to": "2", "origin": "x-security", "security": true},
        {"name": "vim", "from": null, "to": "9", "origin": "x", "security": false}
    ]))
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO host_packages (host_id, name, version, last_seen) VALUES ($1, 'bash', '5', now())")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    all.run(&pool).await.unwrap();

    let pkgs: Vec<(
        String,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as("SELECT version, arch, first_seen FROM host_packages WHERE host_id = $1")
        .bind(id)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(
        pkgs,
        [("5".into(), None, None)],
        "bestehende Pakete unverändert, neue Spalten leer"
    );
    let old: Option<Value> = sqlx::query_scalar("SELECT updates_list FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(old.is_some(), "die alte Spalte bleibt unberührt");
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT name, kind, security FROM host_updates WHERE host_id = $1 ORDER BY name",
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            ("libc6".into(), "upgrade".into(), true),
            ("vim".into(), "new".into(), false)
        ]
    );
    let listed: bool = sqlx::query_scalar("SELECT updates_listed FROM hosts WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(listed);
}

async fn get(app: &Router, session: &str, uri: &str) -> Resp {
    call(app, Method::GET, uri, &[("cookie", session)], None).await
}

fn names(r: &Resp) -> Vec<String> {
    r.json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_owned())
        .collect()
}

#[sqlx::test(migrations = "./migrations")]
async fn host_packages_merge_filter_sort_and_page(pool: PgPool) {
    let app = router(state(pool.clone()));
    let id = add_host(&pool, "web1").await;
    let pk = vec![
        pkg("bash", "5.2", "amd64"),
        pkg("openssl", "3.0.1", "amd64"),
        pkg("curl", "8", "amd64"),
        pkg("a_b", "1", "amd64"),
    ];
    send(&app, report(Some(pk), Some(HASH_A), Some(items()))).await;
    let s = login(&app, &pool).await;
    let base = format!("/api/v1/hosts/{id}/packages");

    // Alle: installierte und das noch nicht installierte neue Paket, das zu entfernende steht auch drin.
    let all = get(&app, &s, &base).await;
    assert_eq!(all.json["total"], 6);
    assert_eq!(
        names(&all),
        ["a_b", "bash", "curl", "newpkg", "oldpkg", "openssl"]
    );
    let h = &all.json["host"];
    assert_eq!(
        (
            h["installed"].as_i64(),
            h["updates"].as_i64(),
            h["security"].as_i64(),
            h["new"].as_i64()
        ),
        (Some(4), Some(3), Some(1), Some(1))
    );
    assert!(h["apt_lists_updated_at"].is_string());

    // Nur mit Update / nur Sicherheit.
    assert_eq!(
        names(&get(&app, &s, &format!("{base}?update=1&sort=security&dir=desc")).await),
        ["openssl", "newpkg", "oldpkg"]
    );
    let sec = get(&app, &s, &format!("{base}?security=1")).await;
    assert_eq!(names(&sec), ["openssl"]);
    assert_eq!(sec.json["items"][0]["installed"], "3.0.1");
    assert_eq!(sec.json["items"][0]["candidate"], "3.0.2");
    assert_eq!(sec.json["total"], 1);

    // Suche: Platzhalterzeichen sind wörtlich (`_` trifft nur `a_b`, `%` nichts).
    assert_eq!(
        names(&get(&app, &s, &format!("{base}?q=a_b")).await),
        ["a_b"]
    );
    assert_eq!(
        get(&app, &s, &format!("{base}?q=%25")).await.json["total"],
        0
    );
    assert_eq!(
        names(&get(&app, &s, &format!("{base}?q=SSL")).await),
        ["openssl"]
    );

    // Seiten und Richtung.
    let page = get(&app, &s, &format!("{base}?limit=2&offset=2&dir=desc")).await;
    assert_eq!(names(&page), ["newpkg", "curl"]);
    assert_eq!(page.json["total"], 6);

    // Sortierung nur aus der Liste, Einschleusen schlägt fehl; unbekannter Host = 404.
    for bad in [
        "sort=name;DROP%20TABLE%20hosts",
        "sort=password",
        "dir=sideways",
    ] {
        assert_eq!(
            get(&app, &s, &format!("{base}?{bad}")).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    assert_eq!(
        get(
            &app,
            &s,
            &format!("{base}?q=%27%3B%20DROP%20TABLE%20hosts%3B--")
        )
        .await
        .json["total"],
        0
    );
    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM hosts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still, 1);
    assert_eq!(
        get(&app, &s, "/api/v1/hosts/999999/packages").await.status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn overview_counts_hosts_versions_and_updates_across_hosts(pool: PgPool) {
    let app = router(state(pool.clone()));
    let a = add_host(&pool, "web1").await;
    let b: i64 = sqlx::query_scalar(
        "INSERT INTO hosts (name, token_hash) VALUES ('web2', 'x') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    send(
        &app,
        report(
            Some(vec![
                pkg("openssl", "3.0.1", "amd64"),
                pkg("bash", "5.2", "amd64"),
            ]),
            Some(HASH_A),
            Some(items()),
        ),
    )
    .await;
    // Zweiter Host direkt in der Datenbank: andere Version, kein Update.
    sqlx::query("INSERT INTO host_packages (host_id, name, version, last_seen) VALUES ($1, 'openssl', '3.0.0', now())")
        .bind(b)
        .execute(&pool)
        .await
        .unwrap();
    let _ = a;
    let s = login(&app, &pool).await;
    let all = get(&app, &s, "/api/v1/packages?q=openssl").await;
    assert_eq!(
        all.json["items"][0],
        json!({"name": "openssl", "hosts": 2, "versions": 2, "updates": 1, "security": 1})
    );
    assert_eq!(
        names(&get(&app, &s, "/api/v1/packages?security=1").await),
        ["openssl"]
    );
    assert_eq!(
        names(&get(&app, &s, "/api/v1/packages?update=1&sort=name").await),
        ["newpkg", "oldpkg", "openssl"]
    );
    assert_eq!(
        get(&app, &s, "/api/v1/packages?sort=1%3B--").await.status,
        StatusCode::BAD_REQUEST
    );
}

async fn security_events(pool: &PgPool) -> Vec<Value> {
    sqlx::query_scalar("SELECT payload FROM events WHERE kind = 'security_updates_new' ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

fn sec_item(name: &str) -> Value {
    json!({"name": name, "kind": "upgrade", "from": "1", "to": "2", "origin": "Debian-Security:13/trixie-security", "security": true})
}

#[sqlx::test(migrations = "./migrations")]
async fn only_newly_appearing_security_updates_raise_the_event(pool: PgPool) {
    let app = router(state(pool.clone()));
    add_host(&pool, "web1").await;
    // Erster Report: Bestand, keine Neuigkeit.
    send(&app, report(None, None, Some(json!([sec_item("a")])))).await;
    assert!(security_events(&pool).await.is_empty());
    // Gleicher Stand: nichts. Dazu kommen b und ein normales Update: nur b zählt.
    send(&app, report(None, None, Some(json!([sec_item("a")])))).await;
    let plain = json!({"name": "p", "kind": "upgrade", "from": "1", "to": "2", "origin": "Debian:13/stable", "security": false});
    send(
        &app,
        report(
            None,
            None,
            Some(json!([sec_item("a"), sec_item("b"), plain])),
        ),
    )
    .await;
    let ev = security_events(&pool).await;
    assert_eq!(ev.len(), 1);
    assert_eq!(
        (
            ev[0]["count"].as_i64(),
            &ev[0]["packages"],
            ev[0]["name"].as_str()
        ),
        (Some(1), &json!(["b"]), Some("web1"))
    );
    // Später mehr als fünf auf einmal: gebündelt, fünf Namen, volle Zahl.
    let many: Vec<Value> = ["a", "b"]
        .iter()
        .chain(["c", "d", "e", "f", "g", "h"].iter())
        .map(|n| sec_item(n))
        .collect();
    send(&app, report(None, None, Some(json!(many)))).await;
    let ev = security_events(&pool).await;
    assert_eq!(ev.len(), 2);
    assert_eq!(
        (
            ev[1]["count"].as_i64(),
            ev[1]["packages"].as_array().unwrap().len()
        ),
        (Some(6), 5)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_new_channel_does_not_subscribe_to_the_security_update_event(pool: PgPool) {
    let st = state(pool.clone());
    let all = patchwatch_server::notify::store::load_all(&pool, &st.cfg)
        .await
        .unwrap();
    assert!(!all.is_empty());
    for ch in all {
        assert!(!ch.subscribes("security_update_new"), "{}", ch.kind);
        assert!(
            ch.subscribes("host_status"),
            "andere Ereignisse bleiben vorausgewählt"
        );
    }
}
