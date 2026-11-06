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

/// OpenID Connect (Authorization-Code-Flow mit PKCE). Ohne Allow-List (E-Mails oder Domains) bleibt es abgeschaltet:
/// Sonst könnte sich jeder Benutzer des Identity Providers als Admin anmelden.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Oidc {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<Secret>,
    /// Muss beim Provider eingetragen sein, z. B. `https://patchwatch.example.org/api/v1/auth/oidc/callback`.
    pub redirect_url: Option<String>,
    /// Anzeigename des Providers auf dem Anmelde-Button.
    pub name: Option<String>,
    pub scopes: Option<String>,
    pub allowed_emails: Vec<String>,
    pub allowed_domains: Vec<String>,
}

impl Oidc {
    pub fn enabled(&self) -> bool {
        self.issuer.is_some()
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
    /// Horizont des Ubuntu-Erstabrufs in Tagen (nach `updated`; Umgebungsvariable
    /// `PATCHWATCH_CVE_UBUNTU_HORIZON_DAYS`). Der Erstabruf lädt in mehreren Läufen alles, was seitdem geändert
    /// wurde, und gilt erst danach als vollständig. 0 = gesamte Liste.
    pub ubuntu_horizon_days: u32,
    /// Obergrenze an Seiten pro Lauf (Umgebungsvariable `PATCHWATCH_CVE_UBUNTU_MAX_PAGES`). Wird sie vor dem
    /// Cursor erreicht, speichert der Lauf seinen Fortschritt und der nächste setzt dort fort; die Quelle gilt
    /// bis zum Ende dieses Rückstandsabbaus als unvollständig.
    pub ubuntu_max_pages: u32,
    pub ubuntu_max_page_bytes: u64,
    /// Ubuntu-Betriebsart (`PATCHWATCH_CVE_UBUNTU_MODE`): `hybrid` (Standard: tägliche OVAL-Massendaten für behobene
    /// Fälle plus stündlich die ersten Seiten von `cves.json` für offene) oder `api` (nur der alte Rückstandsabbau
    /// durch tiefes Blättern, Rückfallweg).
    pub ubuntu_mode: String,
    /// Basis-URL der OVAL-Dateien (`PATCHWATCH_CVE_UBUNTU_OVAL_URL`), Muster `<basis>/com.ubuntu.<release>.cve.oval.xml.bz2`.
    pub ubuntu_oval_url: String,
    /// Zusätzliche Releases für den Massenimport, außer denen auf den Ubuntu-Hosts
    /// (`PATCHWATCH_CVE_UBUNTU_BULK_RELEASES`, kommagetrennt).
    pub ubuntu_bulk_releases: Vec<String>,
    /// Standard-Intervall des täglichen Massenimports in Minuten (in der UI je Quelle änderbar, mindestens 15).
    pub ubuntu_bulk_interval_minutes: u64,
    /// Grenzen einer OVAL-Datei: komprimiert, entpackt, Gesamtdauer in Sekunden.
    pub ubuntu_oval_max_bytes: u64,
    pub ubuntu_oval_max_xml_bytes: u64,
    pub ubuntu_oval_timeout_secs: u64,
    /// Seiten je stündlichem Abruf von `cves.json` und Start-Seitengröße (5 bis 20; bei Fehlern schrumpft sie).
    pub ubuntu_incremental_pages: u32,
    pub ubuntu_page_size: u32,
    /// Zeitlimit je Seitenanfrage des stündlichen Abrufs (Sekunden); die Quelle antwortet teils erst nach 25 s und mehr.
    pub ubuntu_page_timeout_secs: u64,
    pub debian_max_bytes: u64,
    /// Pause zwischen zwei Ubuntu-Seiten in Millisekunden (Umgebungsvariable
    /// `PATCHWATCH_CVE_UBUNTU_PAGE_PAUSE_MS`): höchstens eine Anfrage gleichzeitig, dazwischen Luft für die Quelle.
    pub ubuntu_page_pause_ms: u64,
    /// Ein Abruf ohne Fortschritt (keine Seite geladen) länger als so viele Sekunden gilt als hängend und wird
    /// freigegeben (`PATCHWATCH_CVE_STALL_TIMEOUT_SECS`).
    pub stall_timeout_secs: u64,
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
            ubuntu_horizon_days: 365,
            ubuntu_max_pages: 100,
            ubuntu_max_page_bytes: 32 * 1024 * 1024,
            debian_max_bytes: 200 * 1024 * 1024,
            ubuntu_mode: "hybrid".into(),
            ubuntu_oval_url: "https://security-metadata.canonical.com/oval".into(),
            ubuntu_bulk_releases: Vec::new(),
            ubuntu_bulk_interval_minutes: 1440,
            ubuntu_oval_max_bytes: 64 * 1024 * 1024,
            ubuntu_oval_max_xml_bytes: 1024 * 1024 * 1024,
            ubuntu_oval_timeout_secs: 900,
            ubuntu_incremental_pages: 10,
            ubuntu_page_size: 20,
            ubuntu_page_timeout_secs: 90,
            ubuntu_page_pause_ms: 2000,
            stall_timeout_secs: 30 * 60,
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
    pub oidc: Oidc,
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
            oidc: Oidc::default(),
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
        if let Some(v) = s("OIDC_ISSUER") {
            c.oidc.issuer = Some(v.trim_end_matches('/').to_owned());
        }
        if let Some(v) = s("OIDC_CLIENT_ID") {
            c.oidc.client_id = Some(v);
        }
        if let Some(v) = s("OIDC_CLIENT_SECRET") {
            c.oidc.client_secret = Some(Secret(v));
        }
        if let Some(v) = s("OIDC_REDIRECT_URL") {
            c.oidc.redirect_url = Some(v);
        }
        if let Some(v) = s("OIDC_NAME") {
            c.oidc.name = Some(v);
        }
        if let Some(v) = s("OIDC_SCOPES") {
            c.oidc.scopes = Some(v);
        }
        let list = |v: String| -> Vec<String> {
            v.split(',')
                .map(|x| x.trim().to_ascii_lowercase())
                .filter(|x| !x.is_empty())
                .collect()
        };
        if let Some(v) = s("OIDC_ALLOWED_EMAILS") {
            c.oidc.allowed_emails = list(v);
        }
        if let Some(v) = s("OIDC_ALLOWED_DOMAINS") {
            c.oidc.allowed_domains = list(v);
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
        if let Some(v) = s("CVE_UBUNTU_MAX_PAGES") {
            c.cve.ubuntu_max_pages = v.parse().context("CVE_UBUNTU_MAX_PAGES")?;
        }
        if let Some(v) = s("CVE_UBUNTU_PAGE_PAUSE_MS") {
            c.cve.ubuntu_page_pause_ms = v.parse().context("CVE_UBUNTU_PAGE_PAUSE_MS")?;
        }
        if let Some(v) = s("CVE_UBUNTU_MODE") {
            c.cve.ubuntu_mode = v;
        }
        if let Some(v) = s("CVE_UBUNTU_OVAL_URL") {
            c.cve.ubuntu_oval_url = v;
        }
        if let Some(v) = s("CVE_UBUNTU_BULK_RELEASES") {
            c.cve.ubuntu_bulk_releases = v
                .split(',')
                .map(|r| r.trim().to_owned())
                .filter(|r| !r.is_empty())
                .collect();
        }
        if let Some(v) = s("CVE_UBUNTU_BULK_INTERVAL_MINUTES") {
            c.cve.ubuntu_bulk_interval_minutes =
                v.parse().context("CVE_UBUNTU_BULK_INTERVAL_MINUTES")?;
        }
        if let Some(v) = s("CVE_UBUNTU_INCREMENTAL_PAGES") {
            c.cve.ubuntu_incremental_pages = v.parse().context("CVE_UBUNTU_INCREMENTAL_PAGES")?;
        }
        if let Some(v) = s("CVE_UBUNTU_PAGE_TIMEOUT_SECS") {
            c.cve.ubuntu_page_timeout_secs = v.parse().context("CVE_UBUNTU_PAGE_TIMEOUT_SECS")?;
        }
        if let Some(v) = s("CVE_UBUNTU_PAGE_SIZE") {
            c.cve.ubuntu_page_size = v.parse().context("CVE_UBUNTU_PAGE_SIZE")?;
        }
        if let Some(v) = s("CVE_STALL_TIMEOUT_SECS") {
            c.cve.stall_timeout_secs = v.parse().context("CVE_STALL_TIMEOUT_SECS")?;
        }
        if let Some(v) = s("CVE_UBUNTU_HORIZON_DAYS") {
            c.cve.ubuntu_horizon_days = v.parse().context("CVE_UBUNTU_HORIZON_DAYS")?;
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
        let o = &self.oidc;
        if o.enabled() {
            let local =
                |u: &str| u.starts_with("http://localhost") || u.starts_with("http://127.0.0.1");
            let issuer = o.issuer.as_deref().unwrap_or_default();
            if !(issuer.starts_with("https://") || local(issuer)) {
                bail!("OIDC_ISSUER muss mit https:// beginnen");
            }
            if o.client_id.is_none() || o.client_secret.is_none() || o.redirect_url.is_none() {
                bail!("OIDC: OIDC_CLIENT_ID, OIDC_CLIENT_SECRET und OIDC_REDIRECT_URL sind nötig");
            }
            if o.allowed_emails.is_empty() && o.allowed_domains.is_empty() {
                bail!("OIDC: OIDC_ALLOWED_EMAILS oder OIDC_ALLOWED_DOMAINS setzen (wer darf sich anmelden?)");
            }
        }
        if self.cve.interval_minutes < 5 {
            bail!("cve.interval_minutes muss >= 5 sein");
        }
        if self.cve.ubuntu_horizon_days > 36_500 {
            bail!("cve.ubuntu_horizon_days (PATCHWATCH_CVE_UBUNTU_HORIZON_DAYS) darf höchstens 36500 sein");
        }
        if !["hybrid", "api"].contains(&self.cve.ubuntu_mode.as_str()) {
            bail!("cve.ubuntu_mode (PATCHWATCH_CVE_UBUNTU_MODE) muss hybrid oder api sein");
        }
        if !(15..=10_080).contains(&self.cve.ubuntu_bulk_interval_minutes) {
            bail!("cve.ubuntu_bulk_interval_minutes muss zwischen 15 und 10080 liegen");
        }
        if !(1..=100).contains(&self.cve.ubuntu_incremental_pages) {
            bail!("cve.ubuntu_incremental_pages muss zwischen 1 und 100 liegen");
        }
        if !(1..=600).contains(&self.cve.ubuntu_page_timeout_secs) {
            bail!("cve.ubuntu_page_timeout_secs muss zwischen 1 und 600 liegen");
        }
        if !(5..=20).contains(&self.cve.ubuntu_page_size) {
            bail!(
                "cve.ubuntu_page_size muss zwischen 5 und 20 liegen (die API erlaubt höchstens 20)"
            );
        }
        if let Some(bad) = self.cve.ubuntu_bulk_releases.iter().find(|r| {
            r.is_empty()
                || !r
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        }) {
            bail!("cve.ubuntu_bulk_releases: ungültiger Codename {bad:?} (nur Kleinbuchstaben und Ziffern)");
        }
        if self.cve.ubuntu_page_pause_ms > 60_000 {
            bail!("cve.ubuntu_page_pause_ms (PATCHWATCH_CVE_UBUNTU_PAGE_PAUSE_MS) darf höchstens 60000 sein");
        }
        if !(1..=86_400).contains(&self.cve.stall_timeout_secs) {
            bail!("cve.stall_timeout_secs (PATCHWATCH_CVE_STALL_TIMEOUT_SECS) muss zwischen 1 und 86400 liegen");
        }
        if !(1..=2000).contains(&self.cve.ubuntu_max_pages) {
            bail!("cve.ubuntu_max_pages (PATCHWATCH_CVE_UBUNTU_MAX_PAGES) muss zwischen 1 und 2000 liegen");
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
        assert_eq!(c.cve.ubuntu_max_pages, 100);
        assert_eq!(c.cve.ubuntu_horizon_days, 365);
        let c = Config::from_sources(
            None,
            &env_of(&[("PATCHWATCH_CVE_UBUNTU_HORIZON_DAYS", "0")]),
        )
        .unwrap();
        assert_eq!(c.cve.ubuntu_horizon_days, 0);
        let c = Config::from_sources(None, &env_of(&[("PATCHWATCH_CVE_UBUNTU_MAX_PAGES", "250")]))
            .unwrap();
        assert_eq!(c.cve.ubuntu_max_pages, 250);
        for bad in ["0", "5000", "viele"] {
            assert!(
                Config::from_sources(None, &|k: &str| {
                    (k == "PATCHWATCH_CVE_UBUNTU_MAX_PAGES").then(|| bad.to_owned())
                })
                .is_err(),
                "{bad}"
            );
        }
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
