//! Live-Ereignisse: Sender schreiben ein kleines JSON per `pg_notify`, der WebSocket-Endpunkt
//! (siehe `routes/live.rs`) leitet sie an angemeldete Clients weiter. Payload bewusst klein;
//! Clients laden Daten über die REST-API nach.

use serde_json::{json, Value};
use sqlx::PgConnection;

pub const CHANNEL: &str = "patchwatch_live";

/// Sendet ein beliebiges kleines JSON (höchstens ~7 KB, Grenze von `pg_notify`).
pub async fn publish(conn: &mut PgConnection, payload: &Value) {
    if let Err(e) = sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CHANNEL)
        .bind(payload.to_string())
        .execute(conn)
        .await
    {
        tracing::warn!(error = %e, "Live-Ereignis konnte nicht gesendet werden");
    }
}

/// Sendet ein Live-Ereignis (`type` plus optional Host/CVE). Fehler sind nie fatal für den Aufrufer.
pub async fn notify(
    conn: &mut PgConnection,
    kind: &str,
    host_id: Option<i64>,
    cve_id: Option<&str>,
) {
    let mut payload = json!({ "type": kind });
    if let Some(h) = host_id {
        payload["host_id"] = Value::from(h);
    }
    if let Some(c) = cve_id {
        payload["cve_id"] = Value::from(c);
    }
    publish(conn, &payload).await;
}

/// Hört auf `patchwatch_live` und verteilt jede gültige JSON-Nachricht an die WebSocket-Verbindungen.
/// Bei Verbindungsverlust wird neu verbunden; Clients laden nach einem `resync` ohnehin per REST nach.
pub async fn run(state: crate::state::AppState) {
    loop {
        match listen(&state).await {
            Ok(()) => return,
            Err(e) => tracing::warn!(error = %e, "Live-Listener getrennt, neuer Versuch in 3 s"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

async fn listen(state: &crate::state::AppState) -> sqlx::Result<()> {
    let mut l = sqlx::postgres::PgListener::connect_with(&state.pool).await?;
    l.listen(CHANNEL).await?;
    // Nach (Wieder-)Verbindung können Ereignisse fehlen: Clients synchronisieren neu.
    let _ = state.live.send(r#"{"type":"resync"}"#.into());
    loop {
        let n = l.recv().await?;
        // Nur JSON-Objekte weiterreichen; `send` schlägt ohne Empfänger fehl, was hier normal ist.
        if serde_json::from_str::<Value>(n.payload()).is_ok_and(|v| v.is_object()) {
            let _ = state.live.send(n.payload().into());
        }
    }
}
