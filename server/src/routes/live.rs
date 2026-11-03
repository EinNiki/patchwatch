//! `GET /api/v1/live`: WebSocket, nur Server -> Client. Voraussetzungen: gültige Session und passende Origin.

use crate::error::ApiError;
use crate::extract::Admin;
use crate::state::AppState;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::Response;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

const PING_EVERY: Duration = Duration::from_secs(25);
/// Ohne Lebenszeichen (Pong oder anderer Frame) innerhalb dieser Zeit wird die Verbindung beendet.
const IDLE_LIMIT: Duration = Duration::from_secs(75);
/// Die Session wird regelmäßig erneut geprüft (Logout, Ablauf, Passwortwechsel).
const SESSION_RECHECK: Duration = Duration::from_secs(60);

/// Origin muss zum `Host` passen oder in `PATCHWATCH_ALLOWED_ORIGINS` stehen (Schutz vor Cross-Site-WebSocket-Hijacking).
fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let origin = origin.trim_end_matches('/').to_ascii_lowercase();
    if allowed.contains(&origin) {
        return true;
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase);
    match (origin.split_once("://"), host) {
        (Some((_, o_host)), Some(h)) => o_host == h,
        _ => false,
    }
}

pub async fn live(
    admin: Admin,
    State(st): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    if !origin_allowed(&headers, &st.cfg.allowed_origins) {
        return Err(ApiError::Forbidden("Origin nicht erlaubt"));
    }
    let permit =
        st.live_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests {
                retry_after_secs: 10,
            })?;
    let rx = st.live.subscribe();
    let session_hash = admin.session_hash;
    Ok(ws
        .max_message_size(1024)
        .max_frame_size(1024)
        .on_upgrade(move |socket| async move {
            serve(socket, st, rx, session_hash).await;
            drop(permit);
        }))
}

async fn session_valid(st: &AppState, hash: &[u8]) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM sessions s JOIN admin_users a ON a.id = s.admin_id \
         WHERE s.id_hash = $1 AND s.expires_at > now() AND NOT a.must_change_password)",
    )
    .bind(hash)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(false)
}

async fn serve(
    mut socket: WebSocket,
    st: AppState,
    mut rx: tokio::sync::broadcast::Receiver<std::sync::Arc<str>>,
    session_hash: Vec<u8>,
) {
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut recheck = tokio::time::interval(SESSION_RECHECK);
    let mut last_seen = tokio::time::Instant::now();
    // Die ersten Ticks feuern sofort; überspringen.
    ping.tick().await;
    recheck.tick().await;
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(text) => {
                    if socket.send(Message::text(text.to_string())).await.is_err() { break; }
                }
                // Zu langsamer Client: Verpasstes per REST nachladen lassen.
                Err(RecvError::Lagged(_)) => {
                    if socket.send(Message::text(r#"{"type":"resync"}"#)).await.is_err() { break; }
                }
                Err(RecvError::Closed) => break,
            },
            incoming = socket.recv() => match incoming {
                // Push-only: eingehende Daten werden ignoriert, zählen aber als Lebenszeichen.
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => last_seen = tokio::time::Instant::now(),
            },
            _ = ping.tick() => {
                if last_seen.elapsed() > IDLE_LIMIT || socket.send(Message::Ping(Vec::new().into())).await.is_err() { break; }
            }
            _ = recheck.tick() => {
                if !session_valid(&st, &session_hash).await {
                    let _ = socket.send(Message::Close(Some(CloseFrame { code: 4401, reason: "Sitzung abgelaufen".into() }))).await;
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(origin: Option<&str>, host: Option<&str>) -> HeaderMap {
        let mut m = HeaderMap::new();
        if let Some(o) = origin {
            m.insert(header::ORIGIN, o.parse().unwrap());
        }
        if let Some(x) = host {
            m.insert(header::HOST, x.parse().unwrap());
        }
        m
    }

    #[test]
    fn origin_must_match_host_or_allowlist() {
        let none: Vec<String> = vec![];
        assert!(origin_allowed(
            &h(Some("https://pw.example.org"), Some("pw.example.org")),
            &none
        ));
        assert!(origin_allowed(
            &h(Some("http://localhost:3100"), Some("localhost:3100")),
            &none
        ));
        assert!(!origin_allowed(
            &h(Some("https://evil.example"), Some("pw.example.org")),
            &none
        ));
        assert!(!origin_allowed(
            &h(
                Some("https://pw.example.org.evil.example"),
                Some("pw.example.org")
            ),
            &none
        ));
        assert!(!origin_allowed(&h(None, Some("pw.example.org")), &none));
        assert!(!origin_allowed(
            &h(Some("null"), Some("pw.example.org")),
            &none
        ));
        let allow = vec!["http://10.0.4.90:3100".to_owned()];
        assert!(origin_allowed(
            &h(Some("http://10.0.4.90:3100"), Some("10.0.4.90:8080")),
            &allow
        ));
        assert!(!origin_allowed(
            &h(Some("http://10.0.4.91:3100"), Some("10.0.4.90:8080")),
            &allow
        ));
    }
}
