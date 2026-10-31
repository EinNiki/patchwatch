//! Nachrichtentexte: unabhängig vom Kanal. Welche Ereignisse welchen Kanal erreichen, steht in `events.rs`.

use crate::cve::eval::CveStatus;
use crate::status::HostStatus;

#[derive(Debug, Clone)]
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

fn str_of<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v.get(k).and_then(serde_json::Value::as_str).unwrap_or("")
}

/// Statuswechsel einer CVE auf einem Host (nur Watchlist-CVEs). UNKNOWN löst nie einen Alarm aus
/// (z. B. Proxmox-Kernel: "manuell prüfen" erscheint im UI, nicht per ntfy).
pub fn host_cve_message(p: &serde_json::Value) -> Option<Message> {
    let to = str_of(p, "to");
    if to == "unknown" || p.get("watched") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    let from = p
        .get("from")
        .and_then(serde_json::Value::as_str)
        .map_or("neu", CveStatus::label_de);
    let (priority, tags) = if to == "vulnerable" {
        (4, vec!["warning"])
    } else {
        (3, vec!["information_source"])
    };
    Some(Message {
        title: format!(
            "Watchlist {} auf {}: {}",
            str_of(p, "cve_id"),
            str_of(p, "host"),
            CveStatus::label_de(to)
        ),
        body: format!("{from} → {}", CveStatus::label_de(to)),
        priority,
        tags,
    })
}

/// Neue CVE oder geänderte Quellenangabe zu einer Watchlist-CVE.
pub fn cve_change_message(kind: &str, p: &serde_json::Value) -> Message {
    let changes: Vec<String> = p
        .get("changes")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(3)
        .map(|c| {
            let fix = c
                .get("fix_version")
                .and_then(serde_json::Value::as_str)
                .map(|f| format!(" ({f})"))
                .unwrap_or_default();
            format!(
                "{}/{}: {}{fix}",
                str_of(c, "release"),
                str_of(c, "package"),
                CveStatus::label_de(str_of(c, "to"))
            )
        })
        .collect();
    let what = if kind == "cve_new" {
        "neu in den Feeds"
    } else {
        "Quellenstatus geändert"
    };
    Message {
        title: format!(
            "Watchlist {}: {what} ({})",
            str_of(p, "cve_id"),
            str_of(p, "source")
        ),
        body: changes.join("\n"),
        priority: 3,
        tags: vec!["mag"],
    }
}

/// Tageszusammenfassung aus dem aktuellen Host-Bestand.
pub async fn daily_summary_message(pool: &sqlx::PgPool) -> sqlx::Result<Message> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, count(*) FROM hosts GROUP BY status ORDER BY status")
            .fetch_all(pool)
            .await?;
    let total: i64 = rows.iter().map(|r| r.1).sum();
    let attention: i64 = rows.iter().filter(|r| r.0 != "ok").map(|r| r.1).sum();
    let lines: Vec<String> = rows
        .iter()
        .map(|(s, n)| format!("{n} × {}", HostStatus::label_de(s)))
        .collect();
    let (title, priority) = if attention == 0 {
        (format!("Tagesübersicht: alle {total} Hosts aktuell"), 2)
    } else {
        (
            format!("Tagesübersicht: {attention} von {total} Hosts mit Handlungsbedarf"),
            3,
        )
    };
    let body = if lines.is_empty() {
        "Keine Hosts angelegt.".to_owned()
    } else {
        lines.join("\n")
    };
    Ok(Message {
        title,
        body,
        priority,
        tags: vec!["bar_chart"],
    })
}

pub fn test_message() -> Message {
    Message {
        title: "patchwatch: Testnachricht".to_owned(),
        body: "Wenn diese Nachricht ankommt, funktioniert der Kanal.".to_owned(),
        priority: 3,
        tags: vec!["white_check_mark"],
    }
}

pub fn feed_failing_message(p: &serde_json::Value) -> Message {
    Message {
        title: format!("CVE-Feed {} nicht erreichbar", str_of(p, "source")),
        body: format!(
            "{} Fehlversuche in Folge. Letzter Fehler: {}. Der alte Stand bleibt erhalten.",
            p.get("failures")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            str_of(p, "error")
        ),
        priority: 3,
        tags: vec!["warning"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_healthy_report_is_silent() {
        assert!(status_change_message("web1", "pending", "ok").is_none());
    }

    #[test]
    fn unknown_never_alerts_even_on_watchlist() {
        let p = |to: &str, watched: bool| serde_json::json!({"cve_id": "CVE-2024-1086", "host": "pve1", "from": null, "to": to, "watched": watched});
        assert!(host_cve_message(&p("unknown", true)).is_none());
        assert!(host_cve_message(&p("vulnerable", false)).is_none());
        let m = host_cve_message(&p("vulnerable", true)).unwrap();
        assert_eq!(m.priority, 4);
        assert!(m.title.contains("CVE-2024-1086") && m.title.contains("pve1"));
        assert!(
            host_cve_message(&p("fixed_installed_reboot_required", true))
                .unwrap()
                .title
                .contains("Neustart nötig")
        );
    }

    #[test]
    fn cve_and_feed_messages() {
        let p = serde_json::json!({"cve_id": "CVE-2024-1086", "source": "ubuntu",
            "changes": [{"release": "noble", "package": "linux", "from": "vulnerable", "to": "fixed", "fix_version": "6.8.0-35.35"}]});
        let m = cve_change_message("cve_status_changed", &p);
        assert!(
            m.body.contains("noble/linux: behoben (6.8.0-35.35)"),
            "{}",
            m.body
        );
        let f = feed_failing_message(
            &serde_json::json!({"source": "debian", "failures": 3, "error": "HTTP 503"}),
        );
        assert!(f.title.contains("debian") && f.body.contains("alte Stand"));
    }

    #[test]
    fn security_change_is_high_priority() {
        let m = status_change_message("web1", "ok", "security_updates").unwrap();
        assert_eq!(m.priority, 4);
        assert!(m.title.starts_with("web1:"));
        assert!(m.body.contains("aktuell"));
    }
}
