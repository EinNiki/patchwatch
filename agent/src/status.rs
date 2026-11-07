//! `patchwatch-agent status` und die Aufzeichnung des letzten Laufs. Gibt nie den Token aus, nur seinen Fingerabdruck.
use crate::config::Config;
use crate::error::AgentError;
use crate::token;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const LAST_RUN: &str = "last-run";
const DEFAULT_STATE_DIR: &str = "/var/lib/patchwatch-agent";

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Zustandsverzeichnis, in das systemd (`StateDirectory=`) schreiben lässt.
fn state_dir_env() -> Option<PathBuf> {
    let dir = std::env::var_os("STATE_DIRECTORY")?;
    let first = dir
        .to_string_lossy()
        .split(':')
        .next()
        .unwrap_or("")
        .to_owned();
    (!first.is_empty()).then(|| PathBuf::from(first))
}

/// Kurzform des Ergebnisses ohne Meldungstext (nie Geheimnisse): `ok`, `abgelehnt:<HTTP>`, `netzwerk`, `konfiguration`, `erfassung`.
pub fn outcome_word(r: &Result<(), AgentError>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(AgentError::Rejected(c)) => format!("abgelehnt:{c}"),
        Err(AgentError::Network(_)) => "netzwerk".into(),
        Err(AgentError::Config(_)) => "konfiguration".into(),
        Err(AgentError::Collect(_)) => "erfassung".into(),
        Err(AgentError::Exit(_)) => "fehler".into(),
    }
}

/// Ergebnis des Laufs festhalten (best effort; ohne Zustandsverzeichnis passiert nichts).
pub fn record_run(r: &Result<(), AgentError>) {
    if let Some(dir) = state_dir_env() {
        let _ = std::fs::write(
            dir.join(LAST_RUN),
            format!("{}\t{}\n", now_secs(), outcome_word(r)),
        );
    }
}

pub fn describe_outcome(word: &str) -> String {
    match word.split_once(':') {
        Some(("abgelehnt", c)) => format!("Server lehnte den Token ab (HTTP {c})"),
        _ => match word {
            "ok" => "Report gesendet".into(),
            "netzwerk" => "Server nicht erreichbar".into(),
            "konfiguration" => "Konfigurationsfehler".into(),
            "erfassung" => "Erfassung fehlgeschlagen".into(),
            other => format!(
                "unbekanntes Ergebnis ({})",
                other
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == ':')
                    .take(20)
                    .collect::<String>()
            ),
        },
    }
}

pub fn ago(secs: u64) -> String {
    match secs {
        0..=59 => "gerade eben".into(),
        60..=3599 => format!("vor {} Min.", secs / 60),
        3600..=86399 => format!("vor {} Std.", secs / 3600),
        _ => format!("vor {} Tg.", secs / 86400),
    }
}

/// HTTP-Datum (`Sun, 06 Nov 1994 08:49:37 GMT`) als Unix-Sekunden.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() != 6 || p[5] != "GMT" {
        return None;
    }
    let day: i64 = p[1].parse().ok()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == p[2])? as i64
        + 1;
    let year: i64 = p[3].parse().ok()?;
    let mut t = p[4].split(':');
    let (h, m, sec): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    // Tage seit 1970 (Howard Hinnant, days_from_civil)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + m * 60 + sec)
}

/// Rechte der Token-Datei prüfen: Warnungen bei mehr als 0600 oder falschem Besitzer.
pub fn permission_warnings(path: &Path) -> Vec<String> {
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return vec![];
    };
    let mut w = Vec::new();
    if m.file_type().is_symlink() {
        w.push("Die Token-Datei ist ein Symlink.".to_owned());
    }
    if m.mode() & 0o077 != 0 {
        w.push(format!(
            "Modus {:04o} ist weiter als 0600; Befehl: sudo chmod 0600 {}",
            m.mode() & 0o7777,
            path.display()
        ));
    }
    if m.uid() != 0 || m.gid() != 0 {
        w.push(format!(
            "Besitzer ist {}:{} statt root:root; Befehl: sudo chown root:root {}",
            m.uid(),
            m.gid(),
            path.display()
        ));
    }
    w
}

pub fn run(config_path: &Path, out: &mut dyn Write) -> Result<(), AgentError> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    w(
        out,
        format!("patchwatch-agent {}", env!("CARGO_PKG_VERSION")),
    );
    w(
        out,
        format!("Konfiguration:      {}", config_path.display()),
    );
    let cfg = Config::load(config_path)?;
    w(out, format!("Server:             {}", cfg.server_url));

    // Herkunft des Tokens in der Reihenfolge, in der der Agent ihn liest.
    let cred = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(|d| PathBuf::from(d).join("token"))
        .filter(|p| p.is_file());
    let (origin, file): (String, Option<PathBuf>) = if let Some(p) = cred {
        ("systemd-Credential".into(), Some(p))
    } else if let Some(p) = &cfg.token_file {
        (format!("Datei {}", p.display()), Some(p.clone()))
    } else if cfg.token.is_some() {
        ("agent.toml (Klartext im Konfigurationsfile; besser: sudo patchwatch-agent set-token --migrate)".into(), None)
    } else {
        ("keiner konfiguriert".into(), None)
    };
    w(out, format!("Token-Herkunft:     {origin}"));
    match cfg.resolve_token() {
        Ok(t) => w(
            out,
            format!(
                "Token-Fingerabdruck: {} (SHA-256, erste 8 Hex-Zeichen)",
                token::fingerprint(&t)
            ),
        ),
        Err(_) => w(
            out,
            "Token-Fingerabdruck: nicht lesbar (mit sudo ausführen?)".into(),
        ),
    }
    if let Some(f) = &file {
        let warns = permission_warnings(f);
        if warns.is_empty() {
            w(
                out,
                "Dateirechte:        in Ordnung (0600, root:root)".into(),
            );
        }
        for x in warns {
            w(out, format!("Dateirechte:        WARNUNG: {x}"));
        }
    }

    let dir = state_dir_env().unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    match std::fs::read_to_string(dir.join(LAST_RUN)) {
        Ok(s) => {
            let mut it = s.trim().splitn(2, '\t');
            let ts: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            let word = it.next().unwrap_or("?");
            w(
                out,
                format!(
                    "Letzter Lauf:       {}, {}",
                    ago(now_secs().saturating_sub(ts)),
                    describe_outcome(word)
                ),
            );
        }
        Err(_) => w(
            out,
            format!(
                "Letzter Lauf:       unbekannt (kein Eintrag in {})",
                dir.display()
            ),
        ),
    }

    // Erreichbarkeit: nur /healthz, ohne Token.
    let url = format!("{}/healthz", cfg.server_url.trim_end_matches('/'));
    let started = now_secs();
    match crate::send::http_agent(&cfg).get(&url).call() {
        Ok(resp) => {
            w(
                out,
                format!(
                    "Server erreichbar:  ja (/healthz, HTTP {})",
                    resp.status().as_u16()
                ),
            );
            let skew = resp
                .headers()
                .get("date")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_http_date)
                .map(|t| t - ((started + now_secs()) / 2) as i64);
            match skew {
                Some(s) if s.abs() > 60 => w(
                    out,
                    format!("Zeitabweichung:     {s:+} s (WARNUNG: mehr als 60 s, Uhr prüfen)"),
                ),
                Some(s) => w(out, format!("Zeitabweichung:     {s:+} s")),
                None => w(
                    out,
                    "Zeitabweichung:     unbekannt (keine Zeitangabe des Servers)".into(),
                ),
            }
        }
        Err(ureq::Error::StatusCode(c)) => w(
            out,
            format!("Server erreichbar:  Antwort mit HTTP {c} auf /healthz"),
        ),
        Err(_) => w(out, "Server erreichbar:  nein (keine Verbindung)".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_parses() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            parse_http_date("Sat, 07 Nov 2026 00:41:00 GMT"),
            Some(1_794_012_060)
        );
        assert_eq!(parse_http_date("kaputt"), None);
    }

    #[test]
    fn outcomes_never_carry_message_text() {
        assert_eq!(
            outcome_word(&Err(AgentError::Network("secret-url?token=abc".into()))),
            "netzwerk"
        );
        assert_eq!(
            outcome_word(&Err(AgentError::Rejected(401))),
            "abgelehnt:401"
        );
        assert_eq!(
            describe_outcome("abgelehnt:401"),
            "Server lehnte den Token ab (HTTP 401)"
        );
        assert_eq!(describe_outcome("ok"), "Report gesendet");
        assert_eq!(ago(30), "gerade eben");
        assert_eq!(ago(600), "vor 10 Min.");
    }
}
