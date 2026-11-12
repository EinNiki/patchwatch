//! Ein gespeichertes Geheimnis gehört zu genau dem Ziel, für das es gespeichert wurde.
//!
//! Alle Stellen, an denen Adresse und Geheimnis getrennt abgelegt werden (CVE-Quellen mit Schlüssel, Benachrichtigungskanäle),
//! benutzen DIESE Funktionen. Ändert ein Admin Adresse, Host oder Port, wird das Geheimnis verworfen und muss neu eingegeben
//! werden; sonst ließe sich ein gespeicherter Schlüssel durch bloßes Umstellen der Adresse an einen fremden Server schicken.
//! Ausnahme: der neue Host ist exakt der offizielle Host des Typs und das Schema ist https.
//! Geheimnisse gehen nie über http://, außer der Host steht ausdrücklich in `notify_allowed_hosts`.

use super::ssrf;
use reqwest::Url;
use serde_json::Value;

/// Ziel eines Geheimnisses: Host (klein geschrieben), Port und ob die Verbindung verschlüsselt ist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

impl Target {
    /// Aus einer URL. Groß-/Kleinschreibung des Hosts, ein ausdrücklicher Standardport (:443) und der Pfad ändern das Ziel nicht.
    pub fn from_url(raw: &str) -> Option<Self> {
        let url = Url::parse(raw.trim()).ok()?;
        let secure = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        Some(Self {
            host: url
                .host_str()?
                .trim_matches(['[', ']'])
                .to_ascii_lowercase(),
            port: url.port_or_known_default()?,
            secure,
        })
    }

    /// Für Dienste ohne URL (SMTP: Verbindung ist immer TLS/STARTTLS, siehe `smtp::parse`).
    pub fn from_host_port(host: &str, port: &str) -> Option<Self> {
        let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        Some(Self {
            host,
            port: port.trim().parse().ok()?,
            secure: true,
        })
    }

    /// Das Ziel ist der offizielle Host (ohne abweichenden Port) per https.
    fn is_official(&self, official_host: Option<&str>) -> bool {
        self.secure && self.port == 443 && official_host.is_some_and(|h| h == self.host)
    }
}

/// Offizieller Host je Typ (nur dort darf ein Geheimnis nach einer Adressänderung bleiben, wenn die neue Adresse genau er ist).
pub fn official_host(kind: &str) -> Option<&'static str> {
    match kind {
        "nvd" => Some("services.nvd.nist.gov"),
        "ntfy" => Some("ntfy.sh"),
        _ => None,
    }
}

/// Darf das gespeicherte Geheimnis beim Wechsel von `old` auf `new` bleiben?
/// `None` heißt "keine eigene Adresse" und gilt als die Standardadresse des Typs (`official`).
pub fn survives(
    kind: &str,
    old: Option<&Target>,
    new: Option<&Target>,
    official: Option<&Target>,
) -> bool {
    let official_host = official_host(kind);
    let (old, new) = (old.or(official), new.or(official));
    let (Some(old), Some(new)) = (old, new) else {
        // Ohne erkennbares Ziel (alt oder neu) gibt es keinen Grund, das Geheimnis zu behalten.
        return false;
    };
    // Gleicher Host und Port bleibt; ein Wechsel von http auf https ist ebenfalls unkritisch, nie umgekehrt.
    let same = old.host == new.host && old.port == new.port && (new.secure || !old.secure);
    same || new.is_official(official_host)
}

/// Adressfeld(er) eines Kanals, die das Ziel des Geheimnisses bestimmen. `None`: der Kanal hat keine eigene Adresse
/// (Telegram: feste API, Slack/Discord: die URL ist selbst das Geheimnis).
pub fn channel_target(kind: &str, config: &Value) -> Option<Target> {
    let s = |k: &str| config.get(k).and_then(Value::as_str).map(str::trim);
    match kind {
        "ntfy" | "gotify" | "webhook" => Target::from_url(s("url")?),
        "matrix" => Target::from_url(s("homeserver")?),
        "smtp" => Target::from_host_port(s("host")?, s("port")?),
        _ => None,
    }
}

/// Kanal: Geheimnis verwerfen, weil sich Adresse/Host/Port geändert haben?
pub fn channel_drops_secret(kind: &str, old: &Value, new: &Value) -> bool {
    if !matches!(kind, "ntfy" | "gotify" | "webhook" | "matrix" | "smtp") {
        return false;
    }
    let official = official_host(kind).map(|h| Target {
        host: h.to_owned(),
        port: 443,
        secure: true,
    });
    !survives(
        kind,
        channel_target(kind, old).as_ref(),
        channel_target(kind, new).as_ref(),
        official.as_ref(),
    )
}

/// CVE-Quelle: Geheimnis verwerfen? `old`/`new` sind die gespeicherten Basis-Adressen (`None` = Standardadresse).
pub fn source_drops_secret(kind: &str, old: Option<&str>, new: Option<&str>) -> bool {
    let official = official_host(kind).map(|h| Target {
        host: h.to_owned(),
        port: 443,
        secure: true,
    });
    let parse = |u: Option<&str>| u.map(Target::from_url);
    // Eine unlesbare Adresse (Some(None)) gilt als anderes Ziel.
    let (o, n) = (parse(old), parse(new));
    if matches!(o, Some(None)) || matches!(n, Some(None)) {
        return true;
    }
    !survives(
        kind,
        o.flatten().as_ref(),
        n.flatten().as_ref(),
        official.as_ref(),
    )
}

/// Ein Geheimnis darf nie im Klartext über http:// laufen, außer der Host steht ausdrücklich in der Allowlist des Betreibers.
pub fn cleartext_problem(
    target: Option<&Target>,
    allowed_hosts: &[String],
) -> Option<&'static str> {
    let t = target?;
    if t.secure || ssrf::host_allowed(&t.host, allowed_hosts) {
        None
    } else {
        Some("Ein Schlüssel wird nie über http:// gesendet. Nutze https:// (oder trage den Host in PATCHWATCH_NOTIFY_ALLOWED_HOSTS ein).")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn same_target_in_other_spelling_keeps_the_secret() {
        for (a, b) in [
            ("https://a.example", "https://A.EXAMPLE:443/x/y"),
            ("https://a.example/p", "https://a.example"),
            ("http://gotify.lan:8080", "http://GOTIFY.lan:8080/z"),
        ] {
            assert!(!source_drops_secret("osv", Some(a), Some(b)), "{a} -> {b}");
        }
    }

    #[test]
    fn other_host_port_or_downgrade_drops_the_secret() {
        for (a, b) in [
            ("https://a.example", "https://b.example"),
            ("https://a.example", "https://a.example:8443"),
            ("https://a.example", "http://a.example"),
            ("https://a.example.evil.org", "https://a.example"),
            ("https://a.example", "not a url"),
        ] {
            assert!(source_drops_secret("osv", Some(a), Some(b)), "{a} -> {b}");
        }
        // http -> https wechselt auch den Port (80 -> 443): ein anderes Ziel, also verworfen; mit gleichem Port bleibt es.
        assert!(source_drops_secret(
            "osv",
            Some("http://a.example"),
            Some("https://a.example")
        ));
        assert!(!source_drops_secret(
            "osv",
            Some("http://a.example:443"),
            Some("https://a.example")
        ));
    }

    #[test]
    fn official_nvd_host_stays_valid_only_over_https() {
        let official = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        // Standardadresse <-> offizielle Adresse, auch in anderer Schreibweise.
        assert!(!source_drops_secret("nvd", None, None));
        assert!(!source_drops_secret("nvd", None, Some(official)));
        assert!(!source_drops_secret(
            "nvd",
            Some("https://8.8.8.8"),
            Some("HTTPS://Services.NVD.nist.gov:443/x")
        ));
        assert!(!source_drops_secret("nvd", Some("https://8.8.8.8"), None));
        // Nicht offiziell oder nicht https: verworfen.
        assert!(source_drops_secret("nvd", None, Some("https://8.8.8.8")));
        assert!(source_drops_secret(
            "nvd",
            Some("https://8.8.8.8"),
            Some("http://services.nvd.nist.gov")
        ));
        assert!(source_drops_secret(
            "nvd",
            None,
            Some("https://services.nvd.nist.gov.evil.org")
        ));
        // Ohne offiziellen Host (OSV) gibt es keine Ausnahme.
        assert!(source_drops_secret("osv", Some("https://8.8.8.8"), None));
    }

    #[test]
    fn channels_compare_host_and_port_only() {
        assert!(!channel_drops_secret(
            "gotify",
            &json!({"url": "https://g.example"}),
            &json!({"url": "https://G.example:443/a"})
        ));
        assert!(channel_drops_secret(
            "gotify",
            &json!({"url": "https://g.example"}),
            &json!({"url": "https://h.example"})
        ));
        assert!(channel_drops_secret(
            "gotify",
            &json!({"url": "https://g.example"}),
            &json!({})
        ));
        assert!(channel_drops_secret(
            "matrix",
            &json!({"homeserver": "https://m.example"}),
            &json!({"homeserver": "https://m.example:8448"})
        ));
        assert!(!channel_drops_secret(
            "smtp",
            &json!({"host": "mail.example", "port": "587"}),
            &json!({"host": "MAIL.example", "port": "587"})
        ));
        assert!(channel_drops_secret(
            "smtp",
            &json!({"host": "mail.example", "port": "587"}),
            &json!({"host": "mail.example", "port": "465"})
        ));
        // ntfy: offizieller Host ntfy.sh darf mit https neu gesetzt werden.
        assert!(!channel_drops_secret(
            "ntfy",
            &json!({"url": "https://ntfy.example"}),
            &json!({"url": "https://NTFY.sh"})
        ));
        assert!(channel_drops_secret(
            "ntfy",
            &json!({"url": "https://ntfy.sh"}),
            &json!({"url": "http://ntfy.sh"})
        ));
        // Kanäle ohne eigene Adresse: nichts zu verwerfen.
        assert!(!channel_drops_secret(
            "telegram",
            &json!({"chat_id": "1"}),
            &json!({"chat_id": "2"})
        ));
    }

    #[test]
    fn plain_http_is_refused_unless_the_host_is_allowlisted() {
        let t = Target::from_url("http://gotify.lan:8080").unwrap();
        assert!(cleartext_problem(Some(&t), &[]).is_some());
        assert!(cleartext_problem(Some(&t), &["other.lan".into()]).is_some());
        assert!(cleartext_problem(Some(&t), &["gotify.lan".into()]).is_none());
        let s = Target::from_url("https://x.example").unwrap();
        assert!(cleartext_problem(Some(&s), &[]).is_none());
        assert!(cleartext_problem(None, &[]).is_none());
    }
}
