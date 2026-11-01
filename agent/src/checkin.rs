//! `patchwatch-agent checkin`: fragt den Server, ob ein Report gewünscht ist, und sendet nur dann.
//!
//! Der Server kann dem Agent ausschließlich "Report jetzt senden" mitteilen. Es gibt keinen offenen
//! Port, und es wird nichts ausgeführt, was der Server liefert.
//!
//! Der systemd-Timer ruft den Befehl minütlich auf; das eigentliche Intervall (`checkin_interval_secs`)
//! prüft der Agent anhand eines Zeitstempels im `StateDirectory`.

use crate::config::Config;
use crate::error::AgentError;
use crate::send;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Der Timer feuert minütlich mit Verzögerung; ein Check-in darf deshalb etwas früher fällig sein.
const SLACK_SECS: u64 = 30;
const STATE_FILE: &str = "last-checkin";

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Abgeschaltet oder Intervall noch nicht erreicht: kein Netzwerkzugriff.
    Skipped,
    /// Check-in gesendet, kein Report gewünscht.
    NothingRequested,
    /// Check-in gesendet, Report erzeugt und gesendet.
    ReportSent,
}

/// Ist ein Check-in fällig? Ein Zeitstempel in der Zukunft (Uhr gestellt) gilt als fällig.
pub fn due(last: Option<u64>, now: u64, interval_secs: u64) -> bool {
    match last {
        None => true,
        Some(l) if l > now => true,
        Some(l) => now - l + SLACK_SECS >= interval_secs,
    }
}

/// Zustandsverzeichnis: `$STATE_DIRECTORY` (setzt systemd über `StateDirectory=`). Ohne Verzeichnis
/// (manueller Aufruf) ist jeder Aufruf fällig.
pub fn state_file() -> Option<PathBuf> {
    let dir = std::env::var_os("STATE_DIRECTORY")?;
    // Bei mehreren Verzeichnissen trennt systemd sie mit ':'.
    let first = dir.to_string_lossy().split(':').next()?.to_owned();
    (!first.is_empty()).then(|| Path::new(&first).join(STATE_FILE))
}

fn read_stamp(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Führt einen Check-in aus. `make_report` wird nur aufgerufen, wenn der Server einen Report wünscht.
pub fn run<R: Serialize>(
    cfg: &Config,
    token: &str,
    state: Option<&Path>,
    now: u64,
    make_report: impl FnOnce() -> Result<R, AgentError>,
) -> Result<Outcome, AgentError> {
    if !cfg.checkin_enabled {
        return Ok(Outcome::Skipped);
    }
    if let Some(path) = state {
        // Mit Long-Poll hält der Server die Anfrage offen; ein Intervall zwischen den Aufrufen ist dann nicht nötig.
        if cfg.checkin_wait_secs == 0 && !due(read_stamp(path), now, cfg.checkin_interval_secs) {
            return Ok(Outcome::Skipped);
        }
        // Zeitstempel vor dem Netzwerkzugriff: auch bei Fehlern gilt das Intervall, kein Hämmern auf den Server.
        if let Err(e) = std::fs::write(path, now.to_string()) {
            eprintln!(
                "patchwatch-agent: Zeitstempel {} nicht schreibbar: {e}",
                path.display()
            );
        }
    }
    if !send::ask_checkin(cfg, token)? {
        return Ok(Outcome::NothingRequested);
    }
    let report = make_report()?;
    send::send(cfg, token, &report)?;
    Ok(Outcome::ReportSent)
}

pub fn run_system<R: Serialize>(
    cfg: &Config,
    token: &str,
    make_report: impl FnOnce() -> Result<R, AgentError>,
) -> Result<Outcome, AgentError> {
    run(cfg, token, state_file().as_deref(), now_secs(), make_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn interval_logic() {
        assert!(due(None, 1000, 300));
        assert!(!due(Some(1000), 1100, 300));
        assert!(!due(Some(1000), 1269, 300));
        // Etwas früher als das Intervall ist erlaubt (Timer-Jitter).
        assert!(due(Some(1000), 1270, 300));
        assert!(due(Some(1000), 1300, 300));
        // Uhr zurückgestellt: fällig statt ewig blockiert.
        assert!(due(Some(5000), 1000, 300));
    }

    /// Minimaler HTTP-Server: beantwortet jede Anfrage der Reihe nach und merkt sich die Request-Zeilen.
    fn mock(responses: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for (code, body) in responses {
                let Ok((mut s, _)) = listener.accept() else {
                    return;
                };
                // Header und Body können in getrennten Paketen ankommen: bis Content-Length lesen.
                let mut data = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = s.read(&mut buf).unwrap_or(0);
                    data.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&data).to_string();
                    let Some(end) = text.find("\r\n\r\n") else {
                        if n == 0 {
                            break;
                        } else {
                            continue;
                        }
                    };
                    let len = text[..end]
                        .to_lowercase()
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0usize);
                    if data.len() >= end + 4 + len || n == 0 {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&data).to_string();
                log.lock().unwrap().push(req);
                let _ = write!(
                    s,
                    "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, seen)
    }

    fn cfg(url: &str, extra: &str) -> Config {
        Config::parse(&format!(
            "server_url = \"{url}\"\ninsecure_http = true\ntimeout_secs = 5\n{extra}"
        ))
        .unwrap()
    }

    fn report() -> Result<serde_json::Value, AgentError> {
        Ok(serde_json::json!({"schema_version": 1, "hostname": "h"}))
    }

    #[test]
    fn nothing_requested_means_no_report() {
        let (url, seen) = mock(vec![(200, r#"{"report_requested":false}"#)]);
        let out = run(
            &cfg(&url, ""),
            "pw_tok",
            None,
            1000,
            || -> Result<_, AgentError> { panic!("Report darf nicht erzeugt werden") }
                as fn() -> Result<serde_json::Value, AgentError>,
        );
        assert_eq!(out.unwrap(), Outcome::NothingRequested);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].starts_with("POST /api/v1/agent/checkin?wait=40 "));
        assert!(seen[0]
            .to_lowercase()
            .contains("authorization: bearer pw_tok"));
    }

    #[test]
    fn requested_report_is_sent_exactly_once() {
        let (url, seen) = mock(vec![(200, r#"{"report_requested":true}"#), (204, "")]);
        let out = run(&cfg(&url, ""), "pw_tok", None, 1000, report).unwrap();
        assert_eq!(out, Outcome::ReportSent);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].starts_with("POST /api/v1/agent/checkin?wait=40 "));
        assert!(seen[1].starts_with("POST /api/v1/report "));
        let body: serde_json::Value =
            serde_json::from_str(seen[1].split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["hostname"], "h");
    }

    #[test]
    fn server_can_only_say_yes_or_no() {
        // Zusatzfelder (Befehle, Pfade, …) werden ignoriert; ohne report_requested gilt "nein".
        let (url, seen) = mock(vec![(200, r#"{"run":"rm -rf /","path":"/etc/shadow"}"#)]);
        let out = run(&cfg(&url, ""), "t", None, 1, report).unwrap();
        assert_eq!(out, Outcome::NothingRequested);
        assert_eq!(seen.lock().unwrap().len(), 1);
        // Kein gültiges JSON: ebenfalls "nein".
        let (url, _) = mock(vec![(200, "<html>")]);
        assert_eq!(
            run(&cfg(&url, ""), "t", None, 1, report).unwrap(),
            Outcome::NothingRequested
        );
    }

    #[test]
    fn wrong_token_is_rejected_and_sends_no_report() {
        let (url, seen) = mock(vec![(401, r#"{"error":"nicht angemeldet"}"#)]);
        let err = run(&cfg(&url, ""), "pw_falsch", None, 1, report).unwrap_err();
        assert!(matches!(err, AgentError::Rejected(401)));
        assert_eq!(err.code(), 4);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn unreachable_server_is_a_network_error() {
        let err = run(&cfg("http://127.0.0.1:1", ""), "t", None, 1, report).unwrap_err();
        assert!(matches!(err, AgentError::Network(_)));
    }

    #[test]
    fn disabled_and_not_due_do_not_touch_the_network() {
        // Port 1 ist nicht erreichbar: ein Netzwerkzugriff würde als Fehler auffallen.
        let off = cfg("http://127.0.0.1:1", "checkin_enabled = false");
        assert_eq!(run(&off, "t", None, 1, report).unwrap(), Outcome::Skipped);

        let dir = std::env::temp_dir().join(format!("pw-agent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join(STATE_FILE);
        std::fs::write(&state, "1000").unwrap();
        let on = cfg(
            "http://127.0.0.1:1",
            "checkin_interval_secs = 300\ncheckin_wait_secs = 0",
        );
        assert_eq!(
            run(&on, "t", Some(&state), 1100, report).unwrap(),
            Outcome::Skipped
        );
        // Fällig: Zeitstempel wird vor dem Netzwerkzugriff erneuert, auch wenn dieser scheitert.
        assert!(run(&on, "t", Some(&state), 1400, report).is_err());
        assert_eq!(std::fs::read_to_string(&state).unwrap(), "1400");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
