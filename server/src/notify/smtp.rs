//! E-Mail-Kanal über SMTP (lettre, rustls, Zertifikate werden geprüft).
//!
//! * Nur STARTTLS oder TLS (kein Klartext), Ports 25, 465, 587, 2525.
//! * Header-Injection: Absender, Empfänger und Betreff werden als typisierte Werte gebaut (lettre kodiert sie);
//!   zusätzlich lehnen wir jedes Steuerzeichen (CR/LF/NUL …) schon in der Konfiguration ab, der Betreff wird bereinigt.
//! * SSRF wie bei den anderen Kanälen: der Host wird aufgelöst und geprüft (Loopback/Link-Local immer gesperrt, private
//!   Ziele nur bei exaktem Eintrag in `notify_allowed_hosts`); verbunden wird mit der geprüften IP, das Zertifikat wird
//!   gegen den konfigurierten Hostnamen geprüft.
//! * Fehler sind generisch (`nicht erreichbar`, `SMTP <Code>`), nie der Antworttext des Servers.

use super::channels::{Channel, SendError};
use super::messages::Message as Notice;
use super::ssrf;
use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use reqwest::Url;
use serde_json::Value;
use std::time::Duration;

pub const PORTS: [u16; 4] = [25, 465, 587, 2525];
const MAX_RECIPIENTS: usize = 10;
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Starttls,
    Tls,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: Option<String>,
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
}

fn field<'a>(config: &'a Value, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Kein Steuerzeichen (CR, LF, NUL, Tab …): sonst ließen sich Header einschleusen.
fn no_control(s: &str, what: &str) -> Result<(), String> {
    if s.chars().any(char::is_control) {
        Err(format!("{what}: keine Zeilenumbrüche oder Steuerzeichen"))
    } else {
        Ok(())
    }
}

fn valid_host(h: &str) -> bool {
    let bare = h.trim_matches(['[', ']']);
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    h.len() <= 253
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn mailbox(raw: &str, what: &str) -> Result<Mailbox, String> {
    no_control(raw, what)?;
    if raw.len() > 254 {
        return Err(format!("{what}: zu lang"));
    }
    raw.parse::<Mailbox>()
        .map_err(|_| format!("{what}: ungültige E-Mail-Adresse"))
}

/// Prüft die Konfiguration (ohne Netzwerk).
pub fn parse(config: &Value) -> Result<Settings, String> {
    let host = field(config, "host").ok_or("SMTP-Server fehlt")?;
    no_control(host, "SMTP-Server")?;
    if !valid_host(host) {
        return Err("SMTP-Server: nur Hostname oder IP-Adresse".into());
    }
    let port: u16 = field(config, "port")
        .ok_or("Port fehlt")?
        .parse()
        .map_err(|_| "Port: keine gültige Zahl")?;
    if !PORTS.contains(&port) {
        return Err("Port: erlaubt sind 25, 465, 587 und 2525".into());
    }
    let security = match field(config, "security") {
        Some("starttls") => Security::Starttls,
        Some("tls") => Security::Tls,
        _ => return Err("Verschlüsselung: starttls oder tls".into()),
    };
    let username = match field(config, "username") {
        Some(u) => {
            no_control(u, "Benutzer")?;
            if u.len() > 254 {
                return Err("Benutzer: zu lang".into());
            }
            Some(u.to_owned())
        }
        None => None,
    };
    let from = mailbox(field(config, "from").ok_or("Absender fehlt")?, "Absender")?;
    let list = field(config, "to").ok_or("Empfänger fehlt")?;
    no_control(list, "Empfänger")?;
    let to = list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| mailbox(s, "Empfänger"))
        .collect::<Result<Vec<_>, _>>()?;
    if to.is_empty() || to.len() > MAX_RECIPIENTS {
        return Err(format!(
            "Empfänger: 1 bis {MAX_RECIPIENTS} Adressen, durch Komma getrennt"
        ));
    }
    Ok(Settings {
        host: host.to_owned(),
        port,
        security,
        username,
        from,
        to,
    })
}

/// Betreff ohne Zeilenumbrüche und Steuerzeichen, begrenzt.
pub fn clean_subject(s: &str) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(200).collect()
}

pub fn build_message(s: &Settings, n: &Notice) -> Result<Message, SendError> {
    let mut b = Message::builder()
        .from(s.from.clone())
        .subject(format!("[patchwatch] {}", clean_subject(&n.title)));
    for r in &s.to {
        b = b.to(r.clone());
    }
    b.body(n.body.chars().take(4000).collect::<String>())
        .map_err(|_| SendError::Config("Nachricht nicht baubar".into()))
}

pub struct Smtp {
    settings: Settings,
    password: Option<String>,
    allowed_hosts: Vec<String>,
}

impl Smtp {
    pub fn new(
        config: &Value,
        password: Option<String>,
        allowed_hosts: Vec<String>,
    ) -> Result<Self, SendError> {
        let settings = parse(config).map_err(SendError::Config)?;
        Ok(Self {
            settings,
            password: password.filter(|p| !p.is_empty()),
            allowed_hosts,
        })
    }
}

/// Ob die Gegenstelle mit einem SMTP-Code geantwortet hat, nur der Code (nie der Text).
fn smtp_code(e: &lettre::transport::smtp::Error) -> Option<u16> {
    e.status().and_then(|c| c.to_string().parse().ok())
}

#[async_trait]
impl Channel for Smtp {
    fn kind(&self) -> &'static str {
        "smtp"
    }

    async fn send(&self, n: &Notice) -> Result<(), SendError> {
        let s = &self.settings;
        let message = build_message(s, n)?;
        // SSRF: Auflösen und prüfen, dann mit der geprüften IP verbinden.
        let host_for_url = if s.host.contains(':') {
            format!("[{}]", s.host.trim_matches(['[', ']']))
        } else {
            s.host.clone()
        };
        let url = Url::parse(&format!("http://{host_for_url}:{}/", s.port))
            .map_err(|_| SendError::Config("SMTP-Server ungültig".into()))?;
        let target = ssrf::resolve(url, &self.allowed_hosts).await.map_err(|e| {
            tracing::warn!(reason = ?e, "SMTP-Ziel abgelehnt");
            SendError::Unreachable
        })?;
        let cert_name = s.host.trim_matches(['[', ']']).to_owned();
        let mut last = SendError::Unreachable;
        for addr in &target.addrs {
            let params =
                TlsParameters::new(cert_name.clone()).map_err(|_| SendError::Unreachable)?;
            let tls = match s.security {
                Security::Starttls => Tls::Required(params),
                Security::Tls => Tls::Wrapper(params),
            };
            let mut b =
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(addr.ip().to_string())
                    .port(s.port)
                    .tls(tls)
                    .timeout(Some(TIMEOUT));
            if let (Some(u), Some(p)) = (&s.username, &self.password) {
                b = b.credentials(Credentials::new(u.clone(), p.clone()));
            }
            match b.build().send(message.clone()).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    // Nur die Art des Fehlers loggen, nie Serverantworten oder Zugangsdaten.
                    tracing::warn!(
                        permanent = e.is_permanent(),
                        transient = e.is_transient(),
                        "SMTP-Versand fehlgeschlagen"
                    );
                    last = smtp_code(&e).map_or(SendError::Unreachable, SendError::Smtp);
                    // Eine Antwort der Gegenstelle ist endgültig; nur bei Verbindungsfehlern die nächste Adresse versuchen.
                    if matches!(last, SendError::Smtp(_)) {
                        break;
                    }
                }
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> Value {
        json!({"host": "mail.example.org", "port": "587", "security": "starttls", "username": "pw",
               "from": "patchwatch <pw@example.org>", "to": "a@example.org, b@example.org"})
    }

    fn notice(title: &str) -> Notice {
        Notice {
            title: title.into(),
            body: "Text".into(),
            priority: 3,
            tags: vec![],
        }
    }

    #[test]
    fn valid_config_parses() {
        let s = parse(&cfg()).unwrap();
        assert_eq!(
            (s.port, s.security, s.to.len()),
            (587, Security::Starttls, 2)
        );
    }

    #[test]
    fn only_allowed_ports_and_encrypted_modes() {
        for port in ["22", "80", "443", "110", "0", "65536", "abc", "587 "] {
            let mut c = cfg();
            c["port"] = json!(port);
            // "587 " wird zu "587" getrimmt und ist gültig; alles andere nicht.
            assert_eq!(parse(&c).is_ok(), port == "587 ", "{port}");
        }
        for port in ["25", "465", "587", "2525"] {
            let mut c = cfg();
            c["port"] = json!(port);
            assert!(parse(&c).is_ok(), "{port}");
        }
        for sec in ["none", "plain", "", "STARTTLS", "ssl"] {
            let mut c = cfg();
            c["security"] = json!(sec);
            assert!(parse(&c).is_err(), "{sec}");
        }
    }

    #[test]
    fn header_injection_is_rejected_in_every_field() {
        let evil = "x@example.org\r\nBcc: spy@example.net";
        for (key, val) in [
            ("from", evil),
            ("from", "a@example.org\nBcc: spy@example.net"),
            ("to", evil),
            ("to", "ok@example.org,\r\nBcc: spy@example.net"),
            ("host", "mail.example.org\r\nRCPT TO:<spy@example.net>"),
            ("username", "pw\r\nX: y"),
        ] {
            let mut c = cfg();
            c[key] = json!(val);
            assert!(parse(&c).is_err(), "{key}={val:?}");
        }
    }

    #[test]
    fn subject_cannot_inject_headers() {
        let s = parse(&cfg()).unwrap();
        let m = build_message(
            &s,
            &notice("Host web1\r\nBcc: spy@example.net\r\nX-Evil: 1"),
        )
        .unwrap();
        let raw = String::from_utf8_lossy(&m.formatted()).into_owned();
        let head = raw.split("\r\n\r\n").next().unwrap();
        for line in head.lines() {
            assert!(
                !line.starts_with("Bcc:") && !line.starts_with("X-Evil:"),
                "eingeschleust: {line}"
            );
        }
        assert_eq!(clean_subject("a\r\nb\tc\0d"), "a b c d");
        assert_eq!(clean_subject(&"x".repeat(500)).chars().count(), 200);
        assert_eq!(head.matches("Subject:").count(), 1);
    }

    #[test]
    fn recipients_are_bounded() {
        let mut c = cfg();
        c["to"] = json!((0..11)
            .map(|i| format!("u{i}@example.org"))
            .collect::<Vec<_>>()
            .join(","));
        assert!(parse(&c).is_err());
        c["to"] = json!("");
        assert!(parse(&c).is_err());
        c["to"] = json!("kein-at-zeichen");
        assert!(parse(&c).is_err());
    }

    #[tokio::test]
    async fn internal_targets_are_blocked_before_any_connection() {
        for host in [
            "127.0.0.1",
            "localhost",
            "169.254.169.254",
            "::1",
            "0.0.0.0",
        ] {
            let mut c = cfg();
            c["host"] = json!(host);
            // Auch mit Eintrag in der Allowlist bleiben Loopback und Link-Local gesperrt.
            let smtp = Smtp::new(&c, Some("pw".into()), vec![host.into()]).unwrap();
            assert_eq!(
                smtp.send(&notice("t")).await,
                Err(SendError::Unreachable),
                "{host}"
            );
        }
        // Ein privates Ziel ohne Allowlist-Eintrag ebenso.
        let mut c = cfg();
        c["host"] = json!("10.1.2.3");
        let smtp = Smtp::new(&c, None, vec![]).unwrap();
        assert_eq!(smtp.send(&notice("t")).await, Err(SendError::Unreachable));
    }
}
