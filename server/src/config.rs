use anyhow::{bail, Context, Result};
use chrono::NaiveTime;
use serde::Deserialize;
use std::fmt;

/// String, der in Debug/Logs nie im Klartext erscheint.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Ntfy {
    pub url: Option<String>,
    pub topic: Option<String>,
    pub token: Option<Secret>,
}

impl Ntfy {
    pub fn enabled(&self) -> bool {
        self.url.is_some() && self.topic.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub database_url: Option<Secret>,
    pub listen: String,
    /// Cookie mit `Secure`-Flag (hinter TLS-Proxy; nur für lokale Entwicklung abschalten).
    pub cookie_secure: bool,
    /// Client-IP aus dem letzten `X-Forwarded-For`-Eintrag (nur hinter vertrauenswürdigem Proxy).
    pub trust_proxy: bool,
    pub session_ttl_hours: i64,
    pub stale_after_hours: i64,
    pub report_retention_days: i64,
    pub timezone: String,
    /// Uhrzeit der Tageszusammenfassung, "HH:MM" in `timezone`.
    pub daily_summary_time: String,
    pub ntfy: Ntfy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: None,
            listen: "0.0.0.0:8080".into(),
            cookie_secure: true,
            trust_proxy: false,
            session_ttl_hours: 12,
            stale_after_hours: 26,
            report_retention_days: 180,
            timezone: "Europe/Berlin".into(),
            daily_summary_time: "08:00".into(),
            ntfy: Ntfy::default(),
        }
    }
}

impl Config {
    pub fn tz(&self) -> chrono_tz::Tz {
        self.timezone.parse().unwrap_or(chrono_tz::UTC)
    }

    pub fn summary_time(&self) -> NaiveTime {
        NaiveTime::parse_from_str(&self.daily_summary_time, "%H:%M").unwrap_or_default()
    }

    pub fn database_url(&self) -> Result<&str> {
        self.database_url
            .as_ref()
            .map(Secret::expose)
            .context("database_url fehlt (PATCHWATCH_DATABASE_URL oder DATABASE_URL)")
    }

    /// Datei (TOML, optional) und danach Umgebungsvariablen `PATCHWATCH_*`.
    pub fn load() -> Result<Self> {
        let path = std::env::var("PATCHWATCH_CONFIG").ok().or_else(|| {
            let p = "/etc/patchwatch/server.toml";
            std::path::Path::new(p).exists().then(|| p.to_owned())
        });
        let text = match path {
            Some(p) => {
                Some(std::fs::read_to_string(&p).with_context(|| format!("{p} nicht lesbar"))?)
            }
            None => None,
        };
        Self::from_sources(text.as_deref(), &|k| std::env::var(k).ok())
    }

    pub fn from_sources(file: Option<&str>, env: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let mut c: Config = match file {
            Some(t) => toml::from_str(t).context("Konfigurationsdatei ungültig")?,
            None => Config::default(),
        };
        // Leere Variablen (z. B. `${VAR:-}` in docker-compose) zählen als nicht gesetzt.
        let env = |k: &str| env(k).filter(|v| !v.is_empty());
        let s = |k: &str| env(&format!("PATCHWATCH_{k}"));
        if let Some(v) = s("DATABASE_URL").or_else(|| env("DATABASE_URL")) {
            c.database_url = Some(Secret(v));
        }
        if let Some(v) = s("LISTEN") {
            c.listen = v;
        }
        if let Some(v) = s("COOKIE_SECURE") {
            c.cookie_secure = parse_bool("COOKIE_SECURE", &v)?;
        }
        if let Some(v) = s("TRUST_PROXY") {
            c.trust_proxy = parse_bool("TRUST_PROXY", &v)?;
        }
        if let Some(v) = s("TIMEZONE") {
            c.timezone = v;
        }
        if let Some(v) = s("DAILY_SUMMARY_TIME") {
            c.daily_summary_time = v;
        }
        if let Some(v) = s("STALE_AFTER_HOURS") {
            c.stale_after_hours = v.parse().context("STALE_AFTER_HOURS")?;
        }
        if let Some(v) = s("REPORT_RETENTION_DAYS") {
            c.report_retention_days = v.parse().context("REPORT_RETENTION_DAYS")?;
        }
        if let Some(v) = s("NTFY_URL") {
            c.ntfy.url = Some(v);
        }
        if let Some(v) = s("NTFY_TOPIC") {
            c.ntfy.topic = Some(v);
        }
        if let Some(v) = s("NTFY_TOKEN") {
            c.ntfy.token = Some(Secret(v));
        }
        c.validate()?;
        Ok(c)
    }

    fn validate(&self) -> Result<()> {
        if self.timezone.parse::<chrono_tz::Tz>().is_err() {
            bail!("unbekannte timezone {:?}", self.timezone);
        }
        if NaiveTime::parse_from_str(&self.daily_summary_time, "%H:%M").is_err() {
            bail!("daily_summary_time muss HH:MM sein");
        }
        if self.stale_after_hours < 1
            || self.report_retention_days < 1
            || self.session_ttl_hours < 1
        {
            bail!(
                "stale_after_hours, report_retention_days und session_ttl_hours müssen >= 1 sein"
            );
        }
        if let Some(u) = &self.ntfy.url {
            if !(u.starts_with("https://") || u.starts_with("http://")) {
                bail!("ntfy.url muss mit http(s):// beginnen");
            }
        }
        if self.ntfy.url.is_some() != self.ntfy.topic.is_some() {
            bail!("ntfy.url und ntfy.topic nur gemeinsam setzen");
        }
        Ok(())
    }
}

fn parse_bool(name: &str, v: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => bail!("{name} erwartet true/false"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn defaults_and_env_override() {
        let c = Config::from_sources(
            Some("listen = \"127.0.0.1:9000\"\ncookie_secure = false"),
            &env_of(&[
                ("PATCHWATCH_LISTEN", "0.0.0.0:1"),
                ("DATABASE_URL", "postgres://u:pw@h/db"),
            ]),
        )
        .unwrap();
        assert_eq!(c.listen, "0.0.0.0:1");
        assert!(!c.cookie_secure);
        assert_eq!(c.stale_after_hours, 26);
        assert_eq!(c.report_retention_days, 180);
        assert_eq!(c.database_url().unwrap(), "postgres://u:pw@h/db");
    }

    #[test]
    fn empty_env_values_count_as_unset() {
        let c = Config::from_sources(
            None,
            &env_of(&[
                ("PATCHWATCH_NTFY_URL", ""),
                ("PATCHWATCH_NTFY_TOPIC", ""),
                ("PATCHWATCH_NTFY_TOKEN", ""),
            ]),
        )
        .unwrap();
        assert!(!c.ntfy.enabled());
        assert!(c.ntfy.token.is_none());
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let c = Config::from_sources(
            None,
            &env_of(&[
                ("DATABASE_URL", "postgres://u:geheim@h/db"),
                ("PATCHWATCH_NTFY_TOKEN", "tk_geheim"),
            ]),
        )
        .unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("geheim"), "{dbg}");
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(
            Config::from_sources(None, &env_of(&[("PATCHWATCH_TIMEZONE", "Mars/Base")])).is_err()
        );
        assert!(
            Config::from_sources(None, &env_of(&[("PATCHWATCH_DAILY_SUMMARY_TIME", "8 Uhr")]))
                .is_err()
        );
        assert!(
            Config::from_sources(None, &env_of(&[("PATCHWATCH_NTFY_URL", "https://ntfy.sh")]))
                .is_err()
        );
    }
}
