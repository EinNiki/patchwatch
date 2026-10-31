//! Live-WebSocket: nur mit Session und passender Origin, Ereignisse kommen per NOTIFY an.

use futures_util::StreamExt;
use patchwatch_server::config::Config;
use patchwatch_server::{admin, live, router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error, Message};

const PASSWORD: &str = "ein-langes-test-passwort";

/// Startet den Server auf einem freien Port samt Live-Listener; liefert Adresse und Session-Cookie.
async fn start(pool: &PgPool) -> (SocketAddr, String) {
    let cfg = Config::from_sources(None, &|_| None).unwrap();
    let st = AppState::new(pool.clone(), cfg).unwrap();
    admin::upsert_admin(pool, "admin", PASSWORD).await.unwrap();
    tokio::spawn(live::run(st.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router(st).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/auth/login"))
        .json(&json!({"username": "admin", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    let cookie = resp.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (addr, cookie)
}

fn request(addr: SocketAddr, cookie: Option<&str>, origin: Option<&str>) -> impl IntoClientRequest {
    let mut r = format!("ws://{addr}/api/v1/live")
        .into_client_request()
        .unwrap();
    if let Some(c) = cookie {
        r.headers_mut().insert("cookie", c.parse().unwrap());
    }
    if let Some(o) = origin {
        r.headers_mut().insert("origin", o.parse().unwrap());
    }
    r
}

fn status_of(e: Error) -> u16 {
    match e {
        Error::Http(resp) => resp.status().as_u16(),
        other => panic!("kein HTTP-Fehler: {other}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn websocket_requires_session_and_matching_origin(pool: PgPool) {
    let (addr, cookie) = start(&pool).await;
    let origin = format!("http://{addr}");
    let own = Some(origin.as_str());

    let e = tokio_tungstenite::connect_async(request(addr, None, own))
        .await
        .unwrap_err();
    assert_eq!(status_of(e), 401, "ohne Session");
    let e = tokio_tungstenite::connect_async(request(addr, Some("pw_session=falsch"), own))
        .await
        .unwrap_err();
    assert_eq!(status_of(e), 401, "ungültige Session");
    let e = tokio_tungstenite::connect_async(request(
        addr,
        Some(&cookie),
        Some("https://evil.example"),
    ))
    .await
    .unwrap_err();
    assert_eq!(status_of(e), 403, "fremde Origin");
    let e = tokio_tungstenite::connect_async(request(addr, Some(&cookie), None))
        .await
        .unwrap_err();
    assert_eq!(status_of(e), 403, "ohne Origin");
}

#[sqlx::test(migrations = "./migrations")]
async fn websocket_receives_events_and_ignores_client_messages(pool: PgPool) {
    let (addr, cookie) = start(&pool).await;
    let origin = format!("http://{addr}");
    let (mut ws, _) = tokio_tungstenite::connect_async(request(addr, Some(&cookie), Some(&origin)))
        .await
        .unwrap();
    // Nach dem Verbinden meldet der Listener ggf. ein `resync`; darauf warten wir nicht.
    tokio::time::sleep(Duration::from_millis(300)).await;
    futures_util::SinkExt::send(&mut ws, Message::text("{\"type\":\"evil\"}"))
        .await
        .unwrap();

    sqlx::query("SELECT pg_notify('patchwatch_live', $1)")
        .bind(json!({"type": "report_received", "host_id": 7}).to_string())
        .execute(&pool)
        .await
        .unwrap();
    // Kein JSON-Objekt: wird nicht weitergereicht.
    sqlx::query("SELECT pg_notify('patchwatch_live', 'kein json')")
        .execute(&pool)
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let Message::Text(t) = ws.next().await.unwrap().unwrap() else {
                continue;
            };
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if v["type"] != "resync" {
                return v;
            }
        }
    })
    .await
    .expect("Ereignis kam nicht an");
    assert_eq!(got, json!({"type": "report_received", "host_id": 7}));
}
