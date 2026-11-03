//! Benachrichtigungskanäle. Jeder Kanal implementiert [`Channel`]; weitere kommen
//! durch einen neuen Eintrag in [`KINDS`] und [`build`] hinzu.
//!
//! Fehlermeldungen sind absichtlich generisch (`nicht erreichbar`, `HTTP <Code>`): Weder URLs noch
//! Antwort-Bodies der Gegenseite gelangen in Logs, die Datenbank oder an den Browser.

use super::messages::Message;
use super::ssrf;
use crate::live;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use async_trait::async_trait;
use reqwest::{Method, Url};
use serde_json::{json, Value};
use sqlx::PgPool;

pub const KINDS: [&str; 9] = [
    "ntfy", "matrix", "gotify", "discord", "browser", "smtp", "telegram", "slack", "webhook",
];

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// Konfiguration unvollständig oder ungültig (Text ohne Geheimnisse).
    Config(String),
    /// DNS, Verbindung, Zeitüberschreitung oder gesperrte Zieladresse.
    Unreachable,
    /// Die Gegenseite hat mit diesem HTTP-Status geantwortet.
    Http(u16),
    /// Der SMTP-Server hat mit diesem Statuscode geantwortet (nie mit seinem Text).
    Smtp(u16),
}

impl SendError {
    /// Generische Kurzbeschreibung für UI, Datenbank und Logs.
    pub fn summary(&self) -> String {
        match self {
            Self::Config(m) => format!("Konfiguration ungültig: {m}"),
            Self::Unreachable => "nicht erreichbar".to_owned(),
            Self::Http(c) => format!("HTTP {c}"),
            Self::Smtp(c) => format!("SMTP {c}"),
        }
    }
}

#[async_trait]
pub trait Channel: Send + Sync {
    fn kind(&self) -> &'static str;
    async fn send(&self, msg: &Message) -> Result<(), SendError>;
}

/// Ausgehende HTTP-Aufrufe mit SSRF-Schutz. `trusted` gilt nur für Werte aus der Server-Konfiguration
/// (z. B. die ntfy-Umgebungsvariablen des Admins): Dort entfällt die Adressprüfung wie bisher.
#[derive(Clone)]
pub struct Http {
    pub allowed_hosts: Vec<String>,
    pub trusted: bool,
}

impl Http {
    async fn send(
        &self,
        method: Method,
        url: &Url,
        bearer: Option<&str>,
        headers: &[(&str, &str)],
        body: &Value,
    ) -> Result<(), SendError> {
        let client = if self.trusted {
            ssrf::trusted_client()
        } else {
            let target = ssrf::resolve(url.clone(), &self.allowed_hosts)
                .await
                .map_err(|e| {
                    // Nur die Kategorie ins Log, nie die URL.
                    tracing::warn!(reason = ?e, "Kanal-Ziel abgelehnt");
                    SendError::Unreachable
                })?;
            ssrf::pinned_client(&target)
        }
        .map_err(|_| SendError::Unreachable)?;
        let mut req = client.request(method, url.clone()).json(body);
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        // Der Antwort-Body wird nie gelesen.
        // Geheimnisse stecken teils in der URL (Telegram, Slack, Discord): Fehler vor dem Logging von der URL befreien.
        let resp = req.send().await.map_err(|e| {
            tracing::warn!(error = %e.without_url(), "Kanal-Versand fehlgeschlagen");
            SendError::Unreachable
        })?;
        let code = resp.status().as_u16();
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(SendError::Http(code))
        }
    }
}

fn cfg_str<'a>(config: &'a Value, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn cfg_url(config: &Value, key: &str, what: &str) -> Result<Url, SendError> {
    let raw = cfg_str(config, key).ok_or_else(|| SendError::Config(format!("{what} fehlt")))?;
    ssrf::parse_url(raw, false).map_err(|e| SendError::Config(format!("{what}: {}", e.message())))
}

fn need_secret(secret: Option<String>, what: &str) -> Result<String, SendError> {
    secret
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SendError::Config(format!("{what} fehlt")))
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

pub struct Ntfy {
    url: Url,
    topic: String,
    token: Option<String>,
    http: Http,
}

#[async_trait]
impl Channel for Ntfy {
    fn kind(&self) -> &'static str {
        "ntfy"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        // JSON-Publish an die Basis-URL, damit UTF-8 im Titel funktioniert.
        let mut url = self.url.clone();
        let trimmed = url.path().trim_end_matches('/').to_owned();
        url.set_path(if trimmed.is_empty() { "/" } else { &trimmed });
        let body = json!({
            "topic": self.topic, "title": clip(&m.title, 250), "message": clip(&m.body, 4000),
            "priority": m.priority, "tags": m.tags,
        });
        self.http
            .send(Method::POST, &url, self.token.as_deref(), &[], &body)
            .await
    }
}

pub struct Gotify {
    url: Url,
    token: String,
    http: Http,
}

#[async_trait]
impl Channel for Gotify {
    fn kind(&self) -> &'static str {
        "gotify"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        let mut url = self.url.clone();
        {
            let Ok(mut seg) = url.path_segments_mut() else {
                return Err(SendError::Config("URL ungültig".into()));
            };
            seg.pop_if_empty().push("message");
        }
        // ntfy-Priorität 1–5 auf Gotify 0–10 abbilden.
        let priority = match m.priority {
            0..=1 => 1,
            2 => 3,
            3 => 5,
            4 => 7,
            _ => 10,
        };
        let body = json!({ "title": clip(&m.title, 250), "message": clip(&m.body, 4000), "priority": priority });
        self.http
            .send(
                Method::POST,
                &url,
                None,
                &[("X-Gotify-Key", &self.token)],
                &body,
            )
            .await
    }
}

pub struct Matrix {
    homeserver: Url,
    room_id: String,
    token: String,
    http: Http,
}

#[async_trait]
impl Channel for Matrix {
    fn kind(&self) -> &'static str {
        "matrix"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        let mut txn = [0u8; 16];
        OsRng.fill_bytes(&mut txn);
        let txn: String = txn.iter().map(|b| format!("{b:02x}")).collect();
        let mut url = self.homeserver.clone();
        {
            let Ok(mut seg) = url.path_segments_mut() else {
                return Err(SendError::Config("URL ungültig".into()));
            };
            // Segmente werden prozentkodiert (Raum-IDs enthalten `!` und `:`).
            seg.pop_if_empty()
                .extend(["_matrix", "client", "v3", "rooms", self.room_id.as_str()])
                .extend(["send", "m.room.message", txn.as_str()]);
        }
        let body =
            json!({ "msgtype": "m.text", "body": clip(&format!("{}\n{}", m.title, m.body), 4000) });
        self.http
            .send(Method::PUT, &url, Some(&self.token), &[], &body)
            .await
    }
}

pub struct Discord {
    webhook: Url,
    http: Http,
}

#[async_trait]
impl Channel for Discord {
    fn kind(&self) -> &'static str {
        "discord"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        let body = json!({
            "username": "patchwatch",
            "content": clip(&format!("**{}**\n{}", m.title, m.body), 1900),
            // Keine Erwähnungen/Pings über Inhalte aus Feeds.
            "allowed_mentions": { "parse": [] },
        });
        self.http
            .send(Method::POST, &self.webhook, None, &[], &body)
            .await
    }
}

/// Telegram: Der Bot-Token steckt im Pfad der API-URL und wird deshalb nie geloggt oder gespeichert.
pub struct Telegram {
    base: Url,
    token: String,
    chat_id: String,
    http: Http,
}

pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// Bot-Token im Format `<Bot-ID>:<Geheimnis>`.
pub fn valid_telegram_token(t: &str) -> bool {
    let Some((id, rest)) = t.split_once(':') else {
        return false;
    };
    (5..=16).contains(&id.len())
        && id.chars().all(|c| c.is_ascii_digit())
        && (30..=60).contains(&rest.len())
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Chat-ID: Zahl (negativ bei Gruppen) oder `@kanalname`.
pub fn valid_chat_id(s: &str) -> bool {
    let num = s.strip_prefix('-').unwrap_or(s);
    if !num.is_empty() && num.len() <= 20 && num.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    s.strip_prefix('@').is_some_and(|n| {
        (5..=32).contains(&n.len()) && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Telegram mit anderer Basis-URL (Tests und lokale Bot-API-Server); Token und Chat-ID werden wie sonst geprüft.
pub fn telegram_with_base(
    base: Url,
    token: String,
    chat_id: &str,
    http: Http,
) -> Result<Box<dyn Channel>, SendError> {
    if !valid_telegram_token(&token) {
        return Err(SendError::Config("Bot-Token: ungültiges Format".into()));
    }
    if !valid_chat_id(chat_id) {
        return Err(SendError::Config("Chat-ID: Zahl oder @name".into()));
    }
    Ok(Box::new(Telegram {
        base,
        token,
        chat_id: chat_id.to_owned(),
        http,
    }))
}

#[async_trait]
impl Channel for Telegram {
    fn kind(&self) -> &'static str {
        "telegram"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        let mut url = self.base.clone();
        {
            let Ok(mut seg) = url.path_segments_mut() else {
                return Err(SendError::Config("URL ungültig".into()));
            };
            seg.pop_if_empty()
                .push(&format!("bot{}", self.token))
                .push("sendMessage");
        }
        let body = json!({
            "chat_id": self.chat_id,
            "text": clip(&format!("{}\n{}", m.title, m.body), 4000),
            "disable_web_page_preview": true,
        });
        self.http.send(Method::POST, &url, None, &[], &body).await
    }
}

/// Slack: Die Webhook-URL ist das Geheimnis; erlaubt ist nur `https://hooks.slack.com/services/…`.
pub struct Slack {
    webhook: Url,
    http: Http,
}

pub fn parse_slack_webhook(raw: &str) -> Result<Url, String> {
    let url = ssrf::parse_url(raw, true).map_err(|e| e.message().to_string())?;
    if url.scheme() != "https"
        || url.host_str() != Some("hooks.slack.com")
        || !url.path().starts_with("/services/")
    {
        return Err("nur https://hooks.slack.com/services/… ist erlaubt".into());
    }
    Ok(url)
}

/// Slack verlangt `&`, `<` und `>` als Entities (sonst wirken Inhalte aus Feeds als Link oder Erwähnung).
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[async_trait]
impl Channel for Slack {
    fn kind(&self) -> &'static str {
        "slack"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        let text = slack_escape(&format!("*{}*\n{}", m.title, m.body));
        let body = json!({ "text": clip(&text, 3500) });
        self.http
            .send(Method::POST, &self.webhook, None, &[], &body)
            .await
    }
}

/// Generischer Webhook mit festem JSON-Schema (keine Vorlagen).
pub struct Webhook {
    url: Url,
    token: Option<String>,
    http: Http,
}

pub fn webhook_payload(m: &Message, now: chrono::DateTime<chrono::Utc>) -> Value {
    json!({
        "version": 1,
        "event": "patchwatch.notification",
        "title": clip(&m.title, 250),
        "text": clip(&m.body, 4000),
        "priority": m.priority,
        "tags": m.tags,
        "time": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

#[async_trait]
impl Channel for Webhook {
    fn kind(&self) -> &'static str {
        "webhook"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        let body = webhook_payload(m, chrono::Utc::now());
        self.http
            .send(Method::POST, &self.url, self.token.as_deref(), &[], &body)
            .await
    }
}

/// Live im Browser: Das Ereignis geht über Postgres NOTIFY an die WebSocket-Clients.
pub struct Browser {
    pool: PgPool,
}

#[async_trait]
impl Channel for Browser {
    fn kind(&self) -> &'static str {
        "browser"
    }
    async fn send(&self, m: &Message) -> Result<(), SendError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|_| SendError::Unreachable)?;
        let level = if m.priority >= 4 {
            "crit"
        } else if m.priority == 3 {
            "warn"
        } else {
            "info"
        };
        live::publish(
            &mut conn,
            &json!({ "type": "notification", "title": clip(&m.title, 200), "body": clip(&m.body, 500), "level": level }),
        )
        .await;
        Ok(())
    }
}

/// Raum-ID im Matrix-Format `!opaque:server`.
pub fn valid_room_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('!') else {
        return false;
    };
    let Some((local, server)) = rest.split_once(':') else {
        return false;
    };
    s.len() <= 255
        && !local.is_empty()
        && !server.is_empty()
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._=-/+".contains(c))
        && server
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
}

/// Baut einen Kanal aus gespeicherter Konfiguration und (entschlüsseltem) Geheimnis.
pub fn build(
    kind: &str,
    config: &Value,
    secret: Option<String>,
    http: Http,
    pool: &PgPool,
) -> Result<Box<dyn Channel>, SendError> {
    Ok(match kind {
        "ntfy" => {
            let topic = cfg_str(config, "topic")
                .ok_or_else(|| SendError::Config("Topic fehlt".into()))?
                .to_owned();
            Box::new(Ntfy {
                url: cfg_url(config, "url", "Server-URL")?,
                topic,
                token: secret.filter(|s| !s.is_empty()),
                http,
            })
        }
        "gotify" => Box::new(Gotify {
            url: cfg_url(config, "url", "Server-URL")?,
            token: need_secret(secret, "App-Token")?,
            http,
        }),
        "matrix" => {
            let room_id = cfg_str(config, "room_id")
                .ok_or_else(|| SendError::Config("Raum-ID fehlt".into()))?
                .to_owned();
            if !valid_room_id(&room_id) {
                return Err(SendError::Config(
                    "Raum-ID: erwartet !kennung:server".into(),
                ));
            }
            Box::new(Matrix {
                homeserver: cfg_url(config, "homeserver", "Homeserver-URL")?,
                room_id,
                token: need_secret(secret, "Access-Token")?,
                http,
            })
        }
        "discord" => {
            let raw = need_secret(secret, "Webhook-URL")?;
            let url = ssrf::parse_url(&raw, true)
                .map_err(|e| SendError::Config(format!("Webhook-URL: {}", e.message())))?;
            if url.scheme() != "https" {
                return Err(SendError::Config(
                    "Webhook-URL: nur https:// ist erlaubt".into(),
                ));
            }
            Box::new(Discord { webhook: url, http })
        }
        "smtp" => Box::new(super::smtp::Smtp::new(
            config,
            secret,
            http.allowed_hosts.clone(),
        )?),
        "telegram" => {
            let token = need_secret(secret, "Bot-Token")?;
            if !valid_telegram_token(&token) {
                return Err(SendError::Config("Bot-Token: ungültiges Format".into()));
            }
            let chat_id = cfg_str(config, "chat_id")
                .ok_or_else(|| SendError::Config("Chat-ID fehlt".into()))?;
            if !valid_chat_id(chat_id) {
                return Err(SendError::Config("Chat-ID: Zahl oder @name".into()));
            }
            let base = Url::parse(TELEGRAM_API).map_err(|_| SendError::Unreachable)?;
            Box::new(Telegram {
                base,
                token,
                chat_id: chat_id.to_owned(),
                http,
            })
        }
        "slack" => {
            let raw = need_secret(secret, "Webhook-URL")?;
            let webhook = parse_slack_webhook(&raw)
                .map_err(|e| SendError::Config(format!("Webhook-URL: {e}")))?;
            Box::new(Slack { webhook, http })
        }
        "webhook" => Box::new(Webhook {
            url: cfg_url(config, "url", "URL")?,
            token: secret.filter(|s| !s.is_empty()),
            http,
        }),
        "browser" => Box::new(Browser { pool: pool.clone() }),
        other => return Err(SendError::Config(format!("unbekannter Kanal {other}"))),
    })
}

/// Prüft, ob die Konfiguration für den Betrieb reicht (ohne Netzwerk, ohne Geheimnis im Klartext).
/// Für die Speichern-Validierung: `has_secret` sagt, ob ein Geheimnis vorhanden sein wird.
pub fn validate_config(kind: &str, config: &Value, has_secret: bool) -> Result<(), String> {
    match kind {
        "ntfy" => {
            cfg_url(config, "url", "Server-URL").map_err(|e| e.summary())?;
            let topic = cfg_str(config, "topic").ok_or("Topic fehlt")?;
            if !(1..=64).contains(&topic.len())
                || !topic
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
            {
                return Err("Topic: 1–64 Zeichen aus A–Z, a–z, 0–9, _ und -".into());
            }
        }
        "gotify" => {
            cfg_url(config, "url", "Server-URL").map_err(|e| e.summary())?;
            if !has_secret {
                return Err("App-Token fehlt".into());
            }
        }
        "matrix" => {
            cfg_url(config, "homeserver", "Homeserver-URL").map_err(|e| e.summary())?;
            let room = cfg_str(config, "room_id").ok_or("Raum-ID fehlt")?;
            if !valid_room_id(room) {
                return Err("Raum-ID: erwartet !kennung:server".into());
            }
            if !has_secret {
                return Err("Access-Token fehlt".into());
            }
        }
        // Die Webhook-URL (Geheimnis) wird beim Speichern separat geprüft.
        "discord" => {
            if !has_secret {
                return Err("Webhook-URL fehlt".into());
            }
        }
        "smtp" => {
            super::smtp::parse(config)?;
        }
        "telegram" => {
            let chat_id = cfg_str(config, "chat_id").ok_or("Chat-ID fehlt")?;
            if !valid_chat_id(chat_id) {
                return Err("Chat-ID: Zahl oder @name".into());
            }
            if !has_secret {
                return Err("Bot-Token fehlt".into());
            }
        }
        "slack" => {
            if !has_secret {
                return Err("Webhook-URL fehlt".into());
            }
        }
        "webhook" => {
            cfg_url(config, "url", "URL").map_err(|e| e.summary())?;
        }
        "browser" => {}
        other => return Err(format!("unbekannter Kanal {other}")),
    }
    Ok(())
}

/// Prüft ein neues Geheimnis auf Format (beim Speichern; für Kanäle mit Geheimnis in der URL besonders streng).
pub fn validate_secret(kind: &str, secret: &str) -> Result<(), String> {
    match kind {
        "discord" => match ssrf::parse_url(secret, true) {
            Ok(u) if u.scheme() == "https" => Ok(()),
            Ok(_) => Err("Webhook-URL: nur https:// ist erlaubt".into()),
            Err(e) => Err(format!("Webhook-URL: {}", e.message())),
        },
        "slack" => parse_slack_webhook(secret)
            .map(|_| ())
            .map_err(|e| format!("Webhook-URL: {e}")),
        "telegram" if !valid_telegram_token(secret) => Err("Bot-Token: ungültiges Format".into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_ids() {
        assert!(valid_room_id("!abcDEF123:matrix.example.org"));
        assert!(valid_room_id("!a-b_c:example.org:8448"));
        for bad in [
            "abc:server",
            "!:server",
            "!abc:",
            "!abc",
            "!ab c:server",
            "!abc:ser ver",
            "!a/../b:s\n",
        ] {
            assert!(!valid_room_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn summaries_never_contain_details() {
        assert_eq!(SendError::Unreachable.summary(), "nicht erreichbar");
        assert_eq!(SendError::Http(401).summary(), "HTTP 401");
    }

    #[test]
    fn clip_respects_chars() {
        assert_eq!(clip("äöü", 5), "äöü");
        assert_eq!(clip("äöüäöü", 4), "äöü…");
    }

    #[test]
    fn config_validation_per_kind() {
        let ok = |k: &str, c: Value, s: bool| validate_config(k, &c, s);
        assert!(ok(
            "ntfy",
            json!({"url": "https://ntfy.sh", "topic": "patchwatch"}),
            false
        )
        .is_ok());
        assert!(ok(
            "ntfy",
            json!({"url": "https://ntfy.sh", "topic": "a b"}),
            false
        )
        .is_err());
        assert!(ok(
            "ntfy",
            json!({"url": "https://ntfy.sh?token=x", "topic": "t"}),
            false
        )
        .is_err());
        assert!(ok("gotify", json!({"url": "https://g.example"}), false).is_err());
        assert!(ok("gotify", json!({"url": "https://g.example"}), true).is_ok());
        assert!(ok(
            "matrix",
            json!({"homeserver": "https://m.example", "room_id": "!r:m.example"}),
            true
        )
        .is_ok());
        assert!(ok(
            "matrix",
            json!({"homeserver": "https://m.example", "room_id": "r"}),
            true
        )
        .is_err());
        assert!(ok("discord", json!({}), false).is_err());
        assert!(ok("discord", json!({}), true).is_ok());
        assert!(ok("browser", json!({}), false).is_ok());
        assert!(ok("pager", json!({}), true).is_err());
    }

    #[test]
    fn new_channel_validation() {
        let ok = |k: &str, c: Value, s: bool| validate_config(k, &c, s);
        let tok = "123456789:AAE_abcdefghijklmnopqrstuvwxyz012345";
        assert!(valid_telegram_token(tok));
        for bad in [
            "",
            "abc",
            "123:short",
            "12345678:has space xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "x:AAE_abcdefghijklmnopqrstuvwxyz012345",
        ] {
            assert!(!valid_telegram_token(bad), "{bad}");
        }
        for good in ["12345", "-100123456", "@mein_kanal"] {
            assert!(valid_chat_id(good), "{good}");
        }
        for bad in ["", "-", "@ab", "12a", "@a b cde", "1\n2"] {
            assert!(!valid_chat_id(bad), "{bad:?}");
        }
        assert!(ok("telegram", json!({"chat_id": "42"}), true).is_ok());
        assert!(ok("telegram", json!({"chat_id": "42"}), false).is_err());
        assert!(ok("telegram", json!({}), true).is_err());
        assert!(validate_secret("telegram", "nope").is_err());
        assert!(validate_secret("telegram", tok).is_ok());
        assert!(ok("slack", json!({}), true).is_ok());
        assert!(ok("slack", json!({}), false).is_err());
        assert!(ok(
            "webhook",
            json!({"url": "https://hook.example.org/x"}),
            false
        )
        .is_ok());
        assert!(ok(
            "webhook",
            json!({"url": "https://hook.example.org/x?k=1"}),
            false
        )
        .is_err());
        assert!(ok("webhook", json!({}), false).is_err());
    }

    #[test]
    fn slack_webhook_host_is_fixed_and_text_escaped() {
        assert!(parse_slack_webhook("https://hooks.slack.com/services/T0/B0/xyz").is_ok());
        for bad in [
            "http://hooks.slack.com/services/T0/B0/xyz",
            "https://hooks.slack.com.evil.example/services/T0/B0/xyz",
            "https://evil.example/services/T0/B0/xyz",
            "https://hooks.slack.com/other",
            "https://user@hooks.slack.com/services/a",
            "https://127.0.0.1/services/a",
        ] {
            assert!(parse_slack_webhook(bad).is_err(), "{bad}");
        }
        assert_eq!(slack_escape("<!channel> a&b"), "&lt;!channel&gt; a&amp;b");
    }

    #[test]
    fn webhook_payload_has_fixed_schema() {
        let m = Message {
            title: "T".into(),
            body: "B".into(),
            priority: 4,
            tags: vec!["warning"],
        };
        let v = webhook_payload(&m, chrono::DateTime::from_timestamp(0, 0).unwrap());
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["event", "priority", "tags", "text", "time", "title", "version"]
        );
        assert_eq!(v["version"], 1);
        assert_eq!(v["time"], "1970-01-01T00:00:00Z");
        assert_eq!(SendError::Smtp(535).summary(), "SMTP 535");
    }
}
