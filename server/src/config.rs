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

/// 32-Byte-Schlüssel für die Verschlüsselung gespeicherter Geheimnisse (Base64 in der Konfiguration).
#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse(s: &str) -> Result<Self> {
        use base64::Engine;
        let t = s.trim();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(t)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t))
            .context("secret_key ist kein gültiges Base64")?;
        let key: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret_key muss genau 32 Byte lang sein (Base64)"))?;
        Ok(Self(key))
    }
}

impl TryFrom<String> for SecretKey {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(***)")
    }
}

/// CVE-Feeds: Intervall, aktive Quellen, Limits. URLs sind überschreibbar (Tests, Spiegel).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CveConfig {
    pub enabled: bool,
    pub interval_minutes: u64,
    /// Startwert der Quellen: "ubuntu", "debian" (eingebaut); weitere verwaltet die UI (Tabelle `cve_sources`).
    pub sources: Vec<String>,
    pub ubuntu_url: String,
    pub debian_url: String,
    pub osv_url: String,
    pub nvd_url: String,
    pub kev_url: String,
    /// Seiten (je 20 CVEs, ca. 3,7 MB) beim allerersten Ubuntu-Abruf.
    pub ubuntu_backfill_pages: u32,
    /// Obergrenze an Seiten pro Lauf; wird sie vor dem Cursor erreicht, gilt der Abruf als fehlgeschlagen.
    pub ubuntu_max_pages: u32,
    pub ubuntu_max_page_bytes: u64,
    pub debian_max_bytes: u64,
    pub request_timeout_secs: u64,
    pub retries: u32,
    pub retry_base_delay_ms: u64,
}

impl Default for CveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 60,
            sources: vec!["ubuntu".into(), "debian".into()],
            ubuntu_url: "https://ubuntu.com".into(),
            debian_url: "https://security-tracker.debian.org/tracker/data/json".into(),
            osv_url: "https://api.osv.dev".into(),
            nvd_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
            kev_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".into(),
            ubuntu_backfill_pages: 5,
            ubuntu_max_pages: 50,
            ubuntu_max_page_bytes: 32 * 1024 * 1024,
            debian_max_bytes: 200 * 1024 * 1024,
            request_timeout_secs: 120,
            retries: 3,
            retry_base_delay_ms: 2000,
        }
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
    pub cve: CveConfig,
    /// Schlüssel für Geheimnisse der Benachrichtigungskanäle (`PATCHWATCH_SECRET_KEY`, 32 Byte Base64,
    /// z. B. `openssl rand -base64 32`). Ohne Schlüssel lassen sich in der UI keine Geheimnisse speichern.
    pub secret_key: Option<SecretKey>,
    /// Hosts/IPs, die Kanäle trotz privater Adresse erreichen dürfen (exakte Übereinstimmung).
    /// Loopback und Link-Local (inkl. 169.254.169.254) bleiben immer gesperrt.
    pub notify_allowed_hosts: Vec<String>,
    /// Zusätzliche Origins (exakt, z. B. `https://ui.example.org`), die den Live-WebSocket öffnen dürfen.
    /// Standard: nur die Origin, die zum `Host`-Header passt.
    pub allowed_origins: Vec<String>,
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
            cve: CveConfig::default(),
            secret_key: None,
            notify_allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
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
        if let Some(v) = s("SECRET_KEY") {
            c.secret_key = Some(SecretKey::parse(&v)?);
        }
        if let Some(v) = s("NOTIFY_ALLOWED_HOSTS") {
            c.notify_allowed_hosts = v
                .split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .filter(|x| !x.is_empty())
                .collect();
        }
        if let Some(v) = s("ALLOWED_ORIGINS") {
            c.allowed_origins = v
                .split(',')
                .map(|x| x.trim().trim_end_matches('/').to_ascii_lowercase())
                .filter(|x| !x.is_empty())
                .collect();
        }
        if let Some(v) = s("CVE_ENABLED") {
            c.cve.enabled = parse_bool("CVE_ENABLED", &v)?;
        }
        if let Some(v) = s("CVE_INTERVAL_MINUTES") {
            c.cve.interval_minutes = v.parse().context("CVE_INTERVAL_MINUTES")?;
        }
        if let Some(v) = s("CVE_SOURCES") {
            c.cve.sources = v
                .split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .filter(|x| !x.is_empty())
                .collect();
        }
        if let Some(v) = s("CVE_UBUNTU_URL") {
            c.cve.ubuntu_url = v;
        }
        if let Some(v) = s("CVE_DEBIAN_URL") {
            c.cve.debian_url = v;
        }
        if let Some(v) = s("CVE_OSV_URL") {
            c.cve.osv_url = v;
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
        if self.cve.interval_minutes < 5 {
            bail!("cve.interval_minutes muss >= 5 sein");
        }
        if let Some(bad) = self
            .cve
            .sources
            .iter()
            .find(|s| !["ubuntu", "debian", "osv"].contains(&s.as_str()))
        {
            bail!("unbekannte CVE-Quelle {bad:?} (erlaubt: ubuntu, debian, osv)");
        }
        for u in [
            &self.cve.ubuntu_url,
            &self.cve.debian_url,
            &self.cve.osv_url,
        ] {
            if !(u.starts_with("https://") || u.starts_with("http://")) {
                bail!("CVE-Feed-URLs müssen mit http(s):// beginnen");
            }
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
    fn cve_defaults_and_overrides() {
        let c = Config::default();
        assert!(c.cve.enabled && c.cve.interval_minutes == 60);
        assert_eq!(c.cve.sources, ["ubuntu", "debian"]);
        let c = Config::from_sources(
            None,
            &env_of(&[
                ("PATCHWATCH_CVE_SOURCES", "Ubuntu, osv"),
                ("PATCHWATCH_CVE_INTERVAL_MINUTES", "30"),
            ]),
        )
        .unwrap();
        assert_eq!(c.cve.sources, ["ubuntu", "osv"]);
        assert_eq!(c.cve.interval_minutes, 30);
        assert!(
            Config::from_sources(None, &env_of(&[("PATCHWATCH_CVE_SOURCES", "redhat")])).is_err()
        );
        assert!(
            Config::from_sources(None, &env_of(&[("PATCHWATCH_CVE_INTERVAL_MINUTES", "1")]))
                .is_err()
        );
    }

    #[test]
    fn secret_key_and_allowed_hosts() {
        use base64::Engine;
        let good = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let good: &'static str = Box::leak(good.into_boxed_str());
        let c = Config::from_sources(None, &|k: &str| match k {
            "PATCHWATCH_SECRET_KEY" => Some(good.to_owned()),
            "PATCHWATCH_NOTIFY_ALLOWED_HOSTS" => Some("Gotify.lan, 10.0.0.5,".to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.secret_key.as_ref().unwrap().bytes(), &[7u8; 32]);
        assert_eq!(c.notify_allowed_hosts, ["gotify.lan", "10.0.0.5"]);
        assert!(!format!("{c:?}").contains(good));
        // Falsche Länge oder kein Base64: Start schlägt mit klarer Meldung fehl.
        for bad in ["kurz", "%%%"] {
            assert!(
                Config::from_sources(None, &|k: &str| (k == "PATCHWATCH_SECRET_KEY")
                    .then(|| bad.to_owned()))
                .is_err()
            );
        }
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
