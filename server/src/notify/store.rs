//! Persistenz der Kanäle (Tabelle `notification_channels`) und "effektive" Kanäle.
//!
//! Wirksam ist die Zeile aus der Datenbank (Werte aus der UI haben Vorrang). Gibt es für `ntfy` keine
//! Zeile, aber ntfy-Umgebungsvariablen, gelten diese als Voreinstellung (`from_env`).

use super::channels::{self, Channel, Http, KINDS};
use super::{crypto, events};
use crate::config::Config;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct Effective {
    pub kind: String,
    pub enabled: bool,
    pub config: Value,
    /// Verschlüsseltes Geheimnis aus der Datenbank.
    pub secret: Option<Vec<u8>>,
    /// Geheimnis aus der Server-Konfiguration (nur bei `from_env`).
    pub env_secret: Option<String>,
    pub events: Vec<String>,
    pub summary_time: Option<NaiveTime>,
    pub timezone: Option<String>,
    pub last_error: Option<String>,
    pub last_ok_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub from_env: bool,
}

impl Effective {
    pub fn secret_set(&self) -> bool {
        self.secret.is_some() || self.env_secret.is_some()
    }

    pub fn subscribes(&self, event: &str) -> bool {
        self.events.iter().any(|e| e == event)
    }

    /// Entschlüsseltes Geheimnis (Server-Konfiguration oder Datenbank).
    pub fn secret_plain(&self, cfg: &Config) -> Result<Option<String>> {
        if let Some(s) = &self.env_secret {
            return Ok(Some(s.clone()));
        }
        let Some(blob) = &self.secret else {
            return Ok(None);
        };
        let key = cfg
            .secret_key
            .as_ref()
            .context("PATCHWATCH_SECRET_KEY fehlt, gespeichertes Geheimnis nicht lesbar")?;
        crypto::decrypt(key.bytes(), &self.kind, blob).map(Some)
    }

    /// Baut den sendefähigen Kanal.
    pub fn build(
        &self,
        cfg: &Config,
        pool: &PgPool,
    ) -> Result<Box<dyn Channel>, channels::SendError> {
        let secret = self
            .secret_plain(cfg)
            .map_err(|e| channels::SendError::Config(e.to_string()))?;
        let http = Http {
            allowed_hosts: cfg.notify_allowed_hosts.clone(),
            // Werte aus der Server-Konfiguration vertraut der Admin (wie bisher).
            trusted: self.from_env,
        };
        channels::build(&self.kind, &self.config, secret, http, pool)
    }
}

/// Voreinstellung für noch nicht gespeicherte Kanäle.
fn default_events(kind: &str) -> Vec<String> {
    events::ALL
        .iter()
        .filter(|e| kind != "browser" || **e != events::DAILY_SUMMARY)
        .map(|e| (*e).to_owned())
        .collect()
}

fn empty(kind: &str) -> Effective {
    Effective {
        kind: kind.to_owned(),
        enabled: false,
        config: json!({}),
        secret: None,
        env_secret: None,
        events: default_events(kind),
        summary_time: None,
        timezone: None,
        last_error: None,
        last_ok_at: None,
        updated_at: None,
        from_env: false,
    }
}

type Row = (
    String,
    bool,
    Value,
    Option<Vec<u8>>,
    Vec<String>,
    Option<NaiveTime>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
);

/// Alle fünf Kanäle (gespeichert, aus der Umgebung vorbelegt oder leer), in fester Reihenfolge.
pub async fn load_all(pool: &PgPool, cfg: &Config) -> Result<Vec<Effective>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT kind, enabled, config, secret, events, summary_time, timezone, last_error, last_ok_at, updated_at \
         FROM notification_channels",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for kind in KINDS {
        if let Some(r) = rows.iter().find(|r| r.0 == kind) {
            out.push(Effective {
                kind: r.0.clone(),
                enabled: r.1,
                config: r.2.clone(),
                secret: r.3.clone(),
                env_secret: None,
                events: r.4.clone(),
                summary_time: r.5,
                timezone: r.6.clone(),
                last_error: r.7.clone(),
                last_ok_at: r.8,
                updated_at: Some(r.9),
                from_env: false,
            });
        } else if kind == "ntfy" && cfg.ntfy.enabled() {
            let mut e = empty(kind);
            e.enabled = true;
            e.from_env = true;
            e.config = json!({ "url": cfg.ntfy.url, "topic": cfg.ntfy.topic });
            e.env_secret = cfg.ntfy.token.as_ref().map(|t| t.expose().to_owned());
            out.push(e);
        } else {
            out.push(empty(kind));
        }
    }
    Ok(out)
}

pub async fn load(pool: &PgPool, cfg: &Config, kind: &str) -> Result<Option<Effective>> {
    Ok(load_all(pool, cfg)
        .await?
        .into_iter()
        .find(|e| e.kind == kind))
}

/// Eingabe beim Speichern. `secret`: `Some` setzt/ersetzt, `clear_secret` entfernt, sonst bleibt es.
pub struct Update {
    pub enabled: bool,
    pub config: Value,
    pub secret: Option<String>,
    pub clear_secret: bool,
    pub events: Vec<String>,
    pub summary_time: Option<NaiveTime>,
    pub timezone: Option<String>,
}

/// Speichert den Kanal; das Geheimnis wird mit dem Kanalnamen als Associated Data verschlüsselt.
pub async fn save(pool: &PgPool, cfg: &Config, kind: &str, up: Update) -> Result<()> {
    let existing: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT secret FROM notification_channels WHERE kind = $1")
            .bind(kind)
            .fetch_optional(pool)
            .await?
            .flatten();
    let secret = if up.clear_secret {
        None
    } else if let Some(plain) = &up.secret {
        let key = cfg.secret_key.as_ref().context(
            "PATCHWATCH_SECRET_KEY ist nicht gesetzt, Geheimnisse können nicht gespeichert werden",
        )?;
        Some(crypto::encrypt(key.bytes(), kind, plain)?)
    } else {
        existing
    };
    if !KINDS.contains(&kind) {
        bail!("unbekannter Kanal");
    }
    sqlx::query(
        "INSERT INTO notification_channels (kind, enabled, config, secret, events, summary_time, timezone, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now()) \
         ON CONFLICT (kind) DO UPDATE SET enabled = $2, config = $3, secret = $4, events = $5, \
           summary_time = $6, timezone = $7, updated_at = now(), last_error = NULL",
    )
    .bind(kind)
    .bind(up.enabled)
    .bind(&up.config)
    .bind(secret)
    .bind(&up.events)
    .bind(up.summary_time)
    .bind(&up.timezone)
    .execute(pool)
    .await?;
    Ok(())
}

/// Merkt das Ergebnis des letzten Versands (nur generische Texte). Aus der Umgebung vorbelegte Kanäle haben keine Zeile.
pub async fn record_result(pool: &PgPool, kind: &str, result: Result<(), &str>) {
    let r = match result {
        Ok(()) => {
            sqlx::query("UPDATE notification_channels SET last_error = NULL, last_ok_at = now() WHERE kind = $1")
                .bind(kind)
                .execute(pool)
                .await
        }
        Err(e) => {
            sqlx::query("UPDATE notification_channels SET last_error = $2 WHERE kind = $1")
                .bind(kind)
                .bind(e)
                .execute(pool)
                .await
        }
    };
    if let Err(e) = r {
        tracing::warn!(error = %e, "Kanalstatus konnte nicht gespeichert werden");
    }
}
