use crate::config::Config;
use crate::error::AgentError;
use serde::Serialize;
use std::time::Duration;

/// Antworten des Servers sind winzig; alles darüber wird abgelehnt.
const MAX_RESPONSE_BYTES: u64 = 4096;

pub(crate) fn http_agent(cfg: &Config) -> ureq::Agent {
    http_agent_with(cfg, 0)
}

/// `extra_secs`: zusätzliche Wartezeit für Long-Poll-Anfragen.
fn http_agent_with(cfg: &Config, extra_secs: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(cfg.timeout_secs + extra_secs)))
        // Keine Redirects: der Authorization-Header soll den Zielserver nie verlassen.
        .max_redirects(0)
        .build()
        .into()
}

/// Fragt den Server, ob ein Report gewünscht ist. Gelesen wird ausschließlich `report_requested`;
/// jede andere oder fehlende Angabe gilt als "nein". Der Token taucht in keiner Fehlermeldung auf.
pub fn ask_checkin(cfg: &Config, token: &str) -> Result<bool, AgentError> {
    #[derive(serde::Deserialize)]
    struct Answer {
        #[serde(default)]
        report_requested: bool,
    }
    let agent = http_agent_with(cfg, cfg.checkin_wait_secs);
    let mut resp = match agent
        .post(&cfg.checkin_url())
        .header("Authorization", &format!("Bearer {token}"))
        .send_empty()
    {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(code)) => return Err(AgentError::Rejected(code)),
        Err(e) => return Err(AgentError::Network(e.to_string())),
    };
    let answer = resp
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json::<Answer>();
    Ok(answer.is_ok_and(|a| a.report_requested))
}

/// Sendet den Report per HTTPS POST mit Bearer-Token. Der Token taucht in keiner Fehlermeldung auf.
pub fn send<T: Serialize>(cfg: &Config, token: &str, report: &T) -> Result<(), AgentError> {
    let agent = http_agent(cfg);
    match agent
        .post(&cfg.report_url())
        .header("Authorization", &format!("Bearer {token}"))
        .send_json(report)
    {
        Ok(_) => Ok(()),
        Err(ureq::Error::StatusCode(code)) => Err(AgentError::Rejected(code)),
        Err(e) => Err(AgentError::Network(e.to_string())),
    }
}
