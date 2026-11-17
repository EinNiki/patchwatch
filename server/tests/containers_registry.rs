//! Registry-Prüfung gegen einen lokalen Mock (keine echten Registries): Digest-Vergleich, Plattformen, feste Versionen,
//! Fehler, Zwischenspeicher, Abruflimit. Wegwerf-Datenbank je Test.
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use axum::Router;
use chrono::{Duration, Utc};
use patchwatch_server::containers::eval::{evaluate, Local, Verdict};
use patchwatch_server::containers::registry::Registries;
use patchwatch_server::containers::worker::{load_facts, run_due, DOCKER_HUB_GET_BUDGET};
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

const IDX: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OLD_IDX: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const M_ARM: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const M_AMD: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const CFG_ARM: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const CFG_AMD: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const CFG_OLD: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

type Handler = dyn Fn(&Method, &str) -> Response + Send + Sync;

#[derive(Clone)]
struct Mock {
    log: Arc<Mutex<Vec<String>>>,
    handler: Arc<Handler>,
}

impl Mock {
    fn count(&self, needle: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(needle))
            .count()
    }
    fn gets(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("GET "))
            .count()
    }
}

async fn serve(m: Mock) -> String {
    async fn any(State(m): State<Mock>, method: Method, uri: Uri, _h: HeaderMap) -> Response {
        let pq = uri
            .path_and_query()
            .map(|p| p.to_string())
            .unwrap_or_default();
        m.log.lock().unwrap().push(format!("{method} {pq}"));
        (m.handler)(&method, &pq)
    }
    let app: Router = Router::new().fallback(any).with_state(m);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    base
}

fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    let mut b = Response::builder().status(StatusCode::from_u16(status).unwrap());
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

fn json(body: &str) -> Response {
    resp(200, &[("content-type", "application/json")], body)
}

/// Standard-Mock: `app:latest` ist ein Index mit zwei Plattformen; Tag-Listen für `tool`.
fn standard(index_digest: &'static str, arm_cfg: &'static str) -> Mock {
    let handler = move |m: &Method, pq: &str| -> Response {
        if pq.starts_with("/token") {
            return json(r#"{"token":"t0k"}"#);
        }
        if pq == "/v2/library/app/manifests/latest" && m == Method::HEAD {
            return resp(
                200,
                &[
                    ("docker-content-digest", index_digest),
                    ("content-type", "application/vnd.oci.image.index.v1+json"),
                ],
                "",
            );
        }
        if pq == format!("/v2/library/app/manifests/{index_digest}") {
            return json(&format!(
                r#"{{"manifests":[
                  {{"digest":"{M_ARM}","platform":{{"os":"linux","architecture":"arm64","variant":"v8"}}}},
                  {{"digest":"{M_AMD}","platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#
            ));
        }
        if pq == format!("/v2/library/app/manifests/{M_ARM}") {
            return json(&format!(r#"{{"config":{{"digest":"{arm_cfg}"}}}}"#));
        }
        if pq == format!("/v2/library/app/manifests/{M_AMD}") {
            return json(&format!(r#"{{"config":{{"digest":"{CFG_AMD}"}}}}"#));
        }
        if pq.starts_with("/v2/library/tool/tags/list") {
            return json(
                r#"{"tags":["1.2.3","1.2.9","1.3.0","2.0.1","2.1.0-rc1","1.2.3-alpine","latest","1.4"]}"#,
            );
        }
        resp(404, &[], "")
    };
    Mock {
        log: Arc::default(),
        handler: Arc::new(handler),
    }
}

async fn host(pool: &PgPool) -> i64 {
    sqlx::query_scalar("INSERT INTO hosts (name, token_hash) VALUES ('h', 'x') RETURNING id")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
async fn container(
    pool: &PgPool,
    host_id: i64,
    cid: &str,
    image: &str,
    image_id: &str,
    repo_digest: Option<&str>,
    arch: &str,
    variant: Option<&str>,
) {
    let digests: Vec<String> = repo_digest.map(str::to_owned).into_iter().collect();
    sqlx::query(
        "INSERT INTO host_containers (host_id, container_id, name, state, image_ref, image_id, repo_digests, os, arch, \
         variant, first_seen, last_seen) VALUES ($1, $2, $2, 'running', $3, $4, $5, 'linux', $6, $7, now(), now())",
    )
    .bind(host_id)
    .bind(cid)
    .bind(image)
    .bind(image_id)
    .bind(&digests)
    .bind(arch)
    .bind(variant)
    .execute(pool)
    .await
    .unwrap();
}

fn key(tag: &str, repo: &str) -> (String, String, String) {
    ("docker.io".into(), repo.into(), tag.into())
}

async fn verdict(
    pool: &PgPool,
    image: &str,
    image_id: &str,
    digests: &[String],
    tag: &str,
    repo: &str,
    platform: &str,
) -> Verdict {
    let (base, plat) = load_facts(pool, &key(tag, repo), Some(platform))
        .await
        .unwrap();
    evaluate(
        &Local {
            image_ref: image,
            image_id,
            repo_digests: digests,
        },
        base.as_ref(),
        plat.as_ref(),
    )
}

fn hours(h: i64) -> Duration {
    Duration::hours(h)
}

/// Gleicher Digest wie lokal: „aktuell“, ohne Plattformabfrage (nur Token-`GET`, kein Manifest-`GET`).
#[sqlx::test]
async fn floating_same_digest_is_current(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    container(
        &pool,
        h,
        "c1",
        "app:latest",
        CFG_ARM,
        Some(&format!("app@{IDX}")),
        "arm64",
        Some("v8"),
    )
    .await;
    let s = run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    assert_eq!((s.checked, s.failed), (1, 0));
    assert_eq!(
        mock.count("manifests/sha256"),
        0,
        "kein Manifest-GET bei gleichem Digest"
    );
    let v = verdict(
        &pool,
        "app:latest",
        CFG_ARM,
        &[format!("app@{IDX}")],
        "latest",
        "library/app",
        "linux/arm64/v8",
    )
    .await;
    assert_eq!(v, Verdict::Current);
}

/// Anderer Index-Digest, aber das Manifest der Host-Plattform ist unverändert (andere Plattform neu gebaut): „aktuell“.
#[sqlx::test]
async fn other_platform_rebuilt_is_current(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    let local = format!("app@{OLD_IDX}");
    container(
        &pool,
        h,
        "c1",
        "app:latest",
        CFG_ARM,
        Some(&local),
        "arm64",
        Some("v8"),
    )
    .await;
    run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    let v = verdict(
        &pool,
        "app:latest",
        CFG_ARM,
        &[local],
        "latest",
        "library/app",
        "linux/arm64/v8",
    )
    .await;
    assert_eq!(v, Verdict::Current);
}

/// Anderer Index-Digest und anderes Manifest für die Host-Plattform: neueres Image, mit Plattformbestätigung.
#[sqlx::test]
async fn platform_changed_is_update(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    let local = format!("app@{OLD_IDX}");
    container(
        &pool,
        h,
        "c1",
        "app:latest",
        CFG_OLD,
        Some(&local),
        "arm64",
        Some("v8"),
    )
    .await;
    run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    let v = verdict(
        &pool,
        "app:latest",
        CFG_OLD,
        &[local],
        "latest",
        "library/app",
        "linux/arm64/v8",
    )
    .await;
    assert!(
        matches!(
            v,
            Verdict::UpdateAvailable {
                platform_confirmed: true
            }
        ),
        "{v:?}"
    );
}

/// Ein Abruf für mehrere Hosts mit demselben Tag; innerhalb des Intervalls kein zweiter Abruf.
#[sqlx::test]
async fn one_fetch_for_many_hosts_and_cached(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h1 = host(&pool).await;
    let h2: i64 =
        sqlx::query_scalar("INSERT INTO hosts (name, token_hash) VALUES ('h2', 'y') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let d = format!("app@{IDX}");
    container(
        &pool,
        h1,
        "c1",
        "app:latest",
        CFG_ARM,
        Some(&d),
        "arm64",
        Some("v8"),
    )
    .await;
    container(
        &pool,
        h2,
        "c2",
        "app:latest",
        CFG_ARM,
        Some(&d),
        "arm64",
        Some("v8"),
    )
    .await;
    let now = Utc::now();
    run_due(&pool, &regs, now, hours(6), None).await.unwrap();
    assert_eq!(mock.count("HEAD /v2/library/app/manifests/latest"), 1);
    let s = run_due(&pool, &regs, now + Duration::minutes(5), hours(6), None)
        .await
        .unwrap();
    assert_eq!((s.checked, s.skipped_fresh), (0, 1));
    assert_eq!(mock.count("HEAD /v2/library/app/manifests/latest"), 1);
    // Mit `force` wird der Zwischenspeicher übergangen.
    let f = BTreeSet::from([key("latest", "library/app")]);
    let s = run_due(&pool, &regs, now + Duration::minutes(6), hours(6), Some(&f))
        .await
        .unwrap();
    assert_eq!(s.checked, 1);
    assert_eq!(mock.count("HEAD /v2/library/app/manifests/latest"), 2);
}

/// Feste Version: neueste Patch-, Minor- und Major-Version getrennt; Vorabversion, Variante und Fremdtags zählen nicht.
#[sqlx::test]
async fn fixed_tag_reports_patch_minor_major(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    container(&pool, h, "c1", "tool:1.2.3", CFG_ARM, None, "arm64", None).await;
    run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    let (base, _) = load_facts(&pool, &key("1.2.3", "library/tool"), None)
        .await
        .unwrap();
    let n = base.unwrap().newest;
    assert_eq!(n.patch.as_deref(), Some("1.2.9"));
    assert_eq!(n.minor.as_deref(), Some("1.3.0"));
    assert_eq!(
        n.major.as_deref(),
        Some("2.0.1"),
        "2.1.0-rc1 ist eine Vorabversion"
    );
}

/// Pin per Digest, unbekannte Registry und nicht vergleichbarer Tag: keine Anfrage an die Registry.
#[sqlx::test]
async fn pinned_unsupported_incomparable_make_no_request(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    container(
        &pool,
        h,
        "c1",
        &format!("app@{IDX}"),
        CFG_ARM,
        None,
        "arm64",
        None,
    )
    .await;
    container(
        &pool,
        h,
        "c2",
        "registry.example.org/x/y:latest",
        CFG_ARM,
        None,
        "arm64",
        None,
    )
    .await;
    container(
        &pool,
        h,
        "c3",
        "tool:20240101abcdef",
        CFG_ARM,
        None,
        "arm64",
        None,
    )
    .await;
    let s = run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    assert_eq!((s.checked, s.failed, s.deferred), (0, 0, 0));
    assert!(mock.log.lock().unwrap().is_empty(), "keine einzige Anfrage");
    let v = verdict(&pool, &format!("app@{IDX}"), CFG_ARM, &[], "", "", "").await;
    assert_eq!(v, Verdict::Pinned);
    let v = verdict(
        &pool,
        "registry.example.org/x/y:latest",
        CFG_ARM,
        &[],
        "latest",
        "x/y",
        "",
    )
    .await;
    assert_eq!(v, Verdict::Unsupported);
}

/// 429 mit `Retry-After`: Fehlerzustand mit Klartext, der Rest der Registry wartet bis zum nächsten Lauf.
#[sqlx::test]
async fn throttling_is_recorded_and_stops_registry(pool: PgPool) {
    let handler = |_: &Method, pq: &str| -> Response {
        if pq.starts_with("/token") {
            return json(r#"{"token":"t"}"#);
        }
        resp(429, &[("retry-after", "0")], "")
    };
    let mock = Mock {
        log: Arc::default(),
        handler: Arc::new(handler),
    };
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    container(&pool, h, "c1", "app:latest", CFG_ARM, None, "arm64", None).await;
    container(&pool, h, "c2", "other:latest", CFG_ARM, None, "arm64", None).await;
    let s = run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    assert_eq!(
        s.failed, 1,
        "nach der Drosselung wird dieselbe Registry nicht weiter gefragt"
    );
    let (base, _) = load_facts(&pool, &key("latest", "library/app"), None)
        .await
        .unwrap();
    let b = base.unwrap();
    assert_eq!(b.status, "error");
    assert!(b.error.unwrap().contains("drosselt"));
}

/// Zu große Antwort, Weiterleitung und Zeitüberschreitung enden als Fehler mit Klartext, nie als „aktuell“.
#[sqlx::test]
async fn oversize_redirect_and_timeout_are_errors(pool: PgPool) {
    let handler = |m: &Method, pq: &str| -> Response {
        if pq.starts_with("/token") {
            return json(r#"{"token":"t"}"#);
        }
        if pq.contains("/big/") {
            return resp(
                200,
                &[("docker-content-digest", IDX)],
                &"x".repeat(2 * 1024 * 1024),
            );
        }
        if pq.contains("/redir/") {
            return resp(302, &[("location", "http://169.254.169.254/latest")], "");
        }
        let _ = m;
        resp(404, &[], "")
    };
    let mock = Mock {
        log: Arc::default(),
        handler: Arc::new(handler),
    };
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    container(&pool, h, "c1", "big/x:1.0.0", CFG_ARM, None, "arm64", None).await;
    container(
        &pool,
        h,
        "c2",
        "redir/x:latest",
        CFG_ARM,
        None,
        "arm64",
        None,
    )
    .await;
    run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    for (repo, tag) in [("big/x", "1.0.0"), ("redir/x", "latest")] {
        let (base, _) = load_facts(&pool, &key(tag, repo), None).await.unwrap();
        let b = base.unwrap_or_else(|| panic!("{repo}: kein Eintrag"));
        assert_eq!(b.status, "error", "{repo}");
        assert!(b.error.is_some(), "{repo}");
    }
    assert_eq!(
        mock.count("169.254"),
        0,
        "der Weiterleitung wird nicht gefolgt"
    );
}

/// Docker Hub: ist das `GET`-Budget des Fensters aufgebraucht, wird nicht gefragt, sondern „später geprüft“ vermerkt.
#[sqlx::test]
async fn docker_hub_budget_defers(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    container(&pool, h, "c1", "app:latest", CFG_ARM, None, "arm64", None).await;
    sqlx::query(
        "INSERT INTO container_image_checks (registry, repository, tag, platform, checked_at, status, get_count) \
         VALUES ('docker.io', 'library/other', 'latest', '', now(), 'ok', $1)",
    )
    .bind(DOCKER_HUB_GET_BUDGET as i32)
    .execute(&pool)
    .await
    .unwrap();
    let s = run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    assert_eq!((s.checked, s.deferred), (0, 1));
    assert_eq!(mock.gets(), 0);
    let v = verdict(
        &pool,
        "app:latest",
        CFG_ARM,
        &[],
        "latest",
        "library/app",
        "",
    )
    .await;
    assert_eq!(v, Verdict::Deferred);
}

/// Nie mehr als eine Anfrage gleichzeitig je Registry (zwei Sitzungen laufen nacheinander).
#[sqlx::test]
async fn one_request_at_a_time_per_registry(_pool: PgPool) {
    let regs = Registries::for_tests("http://127.0.0.1:9");
    let first = regs.session("docker.io", "library/app").await.unwrap();
    let second = tokio::time::timeout(
        std::time::Duration::from_millis(150),
        regs.session("docker.io", "library/tool"),
    )
    .await;
    assert!(second.is_err(), "zweite Sitzung muss warten");
    // Eine andere Registry ist nicht betroffen.
    assert!(regs.session("ghcr.io", "x/y").await.is_ok());
    drop(first);
    assert!(regs.session("docker.io", "library/tool").await.is_ok());
    // Unbekannte Registry: nicht erlaubt.
    assert!(regs.session("evil.example", "x/y").await.is_err());
}

/// Ohne Plattformangabe des Hosts bleibt es bei „Digest weicht ab“ (nichts wird geraten).
#[sqlx::test]
async fn unknown_platform_is_unconfirmed(pool: PgPool) {
    let mock = standard(IDX, CFG_ARM);
    let regs = Registries::for_tests(&serve(mock.clone()).await);
    let h = host(&pool).await;
    let local = format!("app@{OLD_IDX}");
    sqlx::query(
        "INSERT INTO host_containers (host_id, container_id, name, state, image_ref, image_id, repo_digests, first_seen, last_seen) \
         VALUES ($1, 'c1', 'c1', 'running', 'app:latest', $2, $3, now(), now())",
    )
    .bind(h)
    .bind(CFG_OLD)
    .bind(vec![local.clone()])
    .execute(&pool)
    .await
    .unwrap();
    run_due(&pool, &regs, Utc::now(), hours(6), None)
        .await
        .unwrap();
    assert_eq!(mock.count("manifests/sha256"), 0);
    let v = verdict(
        &pool,
        "app:latest",
        CFG_OLD,
        &[local],
        "latest",
        "library/app",
        "",
    )
    .await;
    assert!(
        matches!(
            v,
            Verdict::UpdateAvailable {
                platform_confirmed: false
            }
        ),
        "{v:?}"
    );
}
