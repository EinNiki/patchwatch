//! Konfiguration der Benachrichtigungskanäle. Geheimnisse sind nur schreibend: Sie werden nie
//! zurückgegeben, in der Datenbank verschlüsselt abgelegt und in keiner Antwort oder Fehlermeldung gezeigt.

use crate::authz;
use crate::error::{ApiError, ApiResult};
use crate::extract::{Authed, CsrfAuthed};
use crate::notify::channels::{self, KINDS};
use crate::notify::secret_target;
use crate::notify::store::{self, Effective, Update};
use crate::notify::{events, messages};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use chrono::NaiveTime;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::time::Duration;

#[derive(Serialize)]
struct ChannelView {
    kind: String,
    enabled: bool,
    /// Nur Unkritisches (URL, Topic, Raum, Server); Geheimnisse stehen nie hier.
    config: Value,
    secret_set: bool,
    events: Vec<String>,
    summary_time: Option<String>,
    timezone: Option<String>,
    last_error: Option<String>,
    last_ok_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Aus den Umgebungsvariablen vorbelegt (noch nicht in der UI gespeichert).
    from_env: bool,
}

impl From<&Effective> for ChannelView {
    fn from(e: &Effective) -> Self {
        Self {
            kind: e.kind.clone(),
            enabled: e.enabled,
            config: e.config.clone(),
            secret_set: e.secret_set(),
            events: e.events.clone(),
            summary_time: e.summary_time.map(|t| t.format("%H:%M").to_string()),
            timezone: e.timezone.clone(),
            last_error: e.last_error.clone(),
            last_ok_at: e.last_ok_at,
            updated_at: e.updated_at,
            from_env: e.from_env,
        }
    }
}

fn known_kind(kind: &str) -> ApiResult<()> {
    if KINDS.contains(&kind) {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

pub async fn list(
    _: Authed<authz::p::ChannelsRead>,
    State(st): State<AppState>,
) -> ApiResult<Json<Value>> {
    let all = store::load_all(&st.pool, &st.cfg).await?;
    Ok(Json(json!({
        // Ohne Schlüssel lassen sich keine Geheimnisse speichern; die UI weist darauf hin.
        "secret_storage": st.cfg.secret_key.is_some(),
        "events": events::ALL,
        "channels": all.iter().map(ChannelView::from).collect::<Vec<_>>(),
    })))
}

pub async fn get_one(
    _: Authed<authz::p::ChannelsRead>,
    State(st): State<AppState>,
    Path(kind): Path<String>,
) -> ApiResult<Json<Value>> {
    known_kind(&kind)?;
    let ch = store::load(&st.pool, &st.cfg, &kind)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!(ChannelView::from(&ch))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutBody {
    enabled: bool,
    #[serde(default)]
    config: Value,
    /// Setzt oder ersetzt das Geheimnis; fehlt das Feld, bleibt das gespeicherte erhalten.
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    clear_secret: bool,
    events: Option<Vec<String>>,
    summary_time: Option<String>,
    timezone: Option<String>,
}

/// Erlaubte (unkritische) Konfigurationsfelder je Kanal; alles andere wird verworfen, damit keine
/// Geheimnisse im Klartext-Feld `config` landen.
fn config_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        "ntfy" => &["url", "topic"],
        "gotify" => &["url"],
        "matrix" => &["homeserver", "room_id"],
        "smtp" => &["host", "port", "security", "username", "from", "to"],
        "telegram" => &["chat_id"],
        "webhook" => &["url"],
        _ => &[],
    }
}

fn clean_config(kind: &str, raw: &Value) -> ApiResult<Value> {
    let mut out = Map::new();
    let empty = Map::new();
    let obj = match raw {
        Value::Object(o) => o,
        Value::Null => &empty,
        _ => return Err(ApiError::BadRequest("config muss ein Objekt sein".into())),
    };
    for key in config_keys(kind) {
        match obj.get(*key) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => {
                let s = s.trim();
                if s.len() > 512 || s.chars().any(char::is_control) {
                    return Err(ApiError::BadRequest(format!("ungültiger Wert für {key}")));
                }
                if !s.is_empty() {
                    out.insert((*key).to_owned(), Value::String(s.to_owned()));
                }
            }
            Some(_) => return Err(ApiError::BadRequest(format!("{key} muss Text sein"))),
        }
    }
    Ok(Value::Object(out))
}

pub async fn put(
    CsrfAuthed(_, _): CsrfAuthed<authz::p::ChannelsWrite>,
    State(st): State<AppState>,
    Path(kind): Path<String>,
    Json(body): Json<PutBody>,
) -> ApiResult<Json<Value>> {
    known_kind(&kind)?;
    let existing = store::load(&st.pool, &st.cfg, &kind)
        .await?
        .ok_or(ApiError::NotFound)?;
    let bad = |m: String| ApiError::BadRequest(m);

    let config = clean_config(&kind, &body.config)?;
    let secret = match body.secret.as_deref() {
        None => None,
        Some(s) => {
            if s.is_empty() || s.len() > 2048 || s.chars().any(char::is_control) {
                return Err(bad("Geheimnis: 1–2048 Zeichen ohne Steuerzeichen".into()));
            }
            if st.cfg.secret_key.is_none() {
                return Err(bad(
                    "PATCHWATCH_SECRET_KEY ist nicht gesetzt: Geheimnisse können nicht gespeichert werden".into(),
                ));
            }
            channels::validate_secret(&kind, s).map_err(bad)?;
            Some(s.to_owned())
        }
    };
    if secret.is_some() && body.clear_secret {
        return Err(bad("secret und clear_secret schließen sich aus".into()));
    }
    // Gemeinsame Regel (notify::secret_target): ändern sich Adresse, Host oder Port, wird das gespeicherte Geheimnis
    // verworfen und muss neu eingegeben werden (ein altes Geheimnis geht nie an ein anderes Ziel).
    let drop_stored = secret.is_none()
        && existing.secret.is_some()
        && secret_target::channel_drops_secret(&kind, &existing.config, &config);
    let clear_secret = body.clear_secret || drop_stored;
    // Ein nur in der Umgebung vorhandenes Geheimnis (ntfy-Token) wird nicht in die DB übernommen.
    let has_secret = secret.is_some() || (!clear_secret && existing.secret.is_some());
    if has_secret {
        let target = secret_target::channel_target(&kind, &config);
        if let Some(m) =
            secret_target::cleartext_problem(target.as_ref(), &st.cfg.notify_allowed_hosts)
        {
            return Err(bad(m.into()));
        }
    }
    let any_config = config.as_object().is_some_and(|o| !o.is_empty());
    if body.enabled || any_config {
        channels::validate_config(&kind, &config, has_secret || !body.enabled).map_err(bad)?;
    }

    let events = match &body.events {
        None => existing.events.clone(),
        Some(list) => {
            let mut out: Vec<String> = Vec::new();
            for e in list {
                if !events::ALL.contains(&e.as_str()) {
                    return Err(bad(format!("unbekannte Ereignisart {e:?}")));
                }
                if !out.contains(e) {
                    out.push(e.clone());
                }
            }
            out
        }
    };
    let summary_time = match body
        .summary_time
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(t) => Some(
            NaiveTime::parse_from_str(t, "%H:%M")
                .map_err(|_| bad("Uhrzeit muss HH:MM sein".into()))?,
        ),
    };
    let timezone = match body
        .timezone
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(tz) => {
            tz.parse::<chrono_tz::Tz>()
                .map_err(|_| bad("unbekannte Zeitzone".into()))?;
            Some(tz.to_owned())
        }
    };

    store::save(
        &st.pool,
        &st.cfg,
        &kind,
        Update {
            enabled: body.enabled,
            config,
            secret,
            clear_secret,
            events,
            summary_time,
            timezone,
        },
    )
    .await
    .map_err(|e| {
        // Fehlertexte aus `save` enthalten keine Geheimnisse.
        tracing::error!(error = %e, "Kanal speichern fehlgeschlagen");
        ApiError::Internal(e)
    })?;
    let saved = store::load(&st.pool, &st.cfg, &kind)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!(ChannelView::from(&saved))))
}

/// "Testnachricht senden" über die gespeicherte Konfiguration. Das Ergebnis ist generisch
/// (`ok` / `nicht erreichbar` / `HTTP <Code>`); der Antwort-Body der Gegenseite wird nie gezeigt.
pub async fn test(
    CsrfAuthed(_, _): CsrfAuthed<authz::p::ChannelsTest>,
    State(st): State<AppState>,
    Path(kind): Path<String>,
) -> ApiResult<Json<Value>> {
    known_kind(&kind)?;
    st.limiter
        .check(&format!("notify-test:{kind}"), 5, Duration::from_secs(60))
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let ch = store::load(&st.pool, &st.cfg, &kind)
        .await?
        .ok_or(ApiError::NotFound)?;
    let result = match ch.build(&st.cfg, &st.pool) {
        Ok(c) => c.send(&messages::test_message()).await,
        Err(e) => Err(e),
    };
    let summary = match &result {
        Ok(()) => "ok".to_owned(),
        Err(e) => e.summary(),
    };
    let recorded = if result.is_ok() {
        Ok(())
    } else {
        Err(summary.as_str())
    };
    store::record_result(&st.pool, &kind, recorded).await;
    Ok(Json(json!({ "ok": result.is_ok(), "result": summary })))
}
