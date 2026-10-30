use crate::config::Config;
use crate::error::AgentError;
use crate::report::Report;
use std::time::Duration;

/// Sendet den Report per HTTPS POST mit Bearer-Token. Der Token taucht in keiner Fehlermeldung auf.
pub fn send(cfg: &Config, token: &str, report: &Report) -> Result<(), AgentError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(cfg.timeout_secs)))
        // Keine Redirects: der Authorization-Header soll den Zielserver nie verlassen.
        .max_redirects(0)
        .build()
        .into();
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
