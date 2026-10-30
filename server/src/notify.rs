use crate::config::Ntfy;
use crate::status::HostStatus;
use anyhow::{bail, Result};
use serde_json::json;

/// Sendet eine Nachricht über ntfy (JSON-Publish, damit UTF-8 im Titel funktioniert).
pub async fn send(
    http: &reqwest::Client,
    ntfy: &Ntfy,
    title: &str,
    message: &str,
    priority: u8,
    tags: &[&str],
) -> Result<()> {
    let (Some(url), Some(topic)) = (&ntfy.url, &ntfy.topic) else {
        return Ok(());
    };
    let mut req = http.post(url.trim_end_matches('/')).json(&json!({
        "topic": topic, "title": title, "message": message, "priority": priority, "tags": tags,
    }));
    if let Some(t) = &ntfy.token {
        req = req.bearer_auth(t.expose());
    }
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("ntfy nicht erreichbar: {}", e.without_url()))?;
    if !resp.status().is_success() {
        bail!("ntfy antwortete mit HTTP {}", resp.status());
    }
    Ok(())
}

pub struct Message {
    pub title: String,
    pub body: String,
    pub priority: u8,
    pub tags: Vec<&'static str>,
}

/// Nachricht für einen Statuswechsel; `None`, wenn nicht benachrichtigt werden soll.
pub fn status_change_message(name: &str, from: &str, to: &str) -> Option<Message> {
    // Erster Report eines gesunden Hosts ist keine Meldung wert.
    if from == "pending" && to == "ok" {
        return None;
    }
    let (priority, tags) = match to {
        "cve_vulnerable" | "security_updates" => (4, vec!["warning"]),
        "stale" => (3, vec!["hourglass"]),
        "ok" => (2, vec!["white_check_mark"]),
        _ => (3, vec!["information_source"]),
    };
    Some(Message {
        title: format!("{name}: {}", HostStatus::label_de(to)),
        body: format!(
            "Status: {} → {}",
            HostStatus::label_de(from),
            HostStatus::label_de(to)
        ),
        priority,
        tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_healthy_report_is_silent() {
        assert!(status_change_message("web1", "pending", "ok").is_none());
    }

    #[test]
    fn security_change_is_high_priority() {
        let m = status_change_message("web1", "ok", "security_updates").unwrap();
        assert_eq!(m.priority, 4);
        assert!(m.title.starts_with("web1:"));
        assert!(m.body.contains("aktuell"));
    }
}
