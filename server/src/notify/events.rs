//! Ereignisarten, die ein Kanal abonnieren kann, und die Zuordnung der internen Events dazu.

use super::messages::{
    cve_change_message, feed_failing_message, host_cve_message, status_change_message, Message,
};
use serde_json::Value;
use std::collections::HashSet;

pub const HOST_STATUS: &str = "host_status";
pub const AGENT_SILENT: &str = "agent_silent";
pub const WATCHLIST_CVE: &str = "watchlist_cve";
pub const FIX_AVAILABLE: &str = "fix_available";
pub const FEED_FAILING: &str = "feed_failing";
pub const DAILY_SUMMARY: &str = "daily_summary";

pub const ALL: [&str; 6] = [
    HOST_STATUS,
    AGENT_SILENT,
    WATCHLIST_CVE,
    FIX_AVAILABLE,
    FEED_FAILING,
    DAILY_SUMMARY,
];

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// Ordnet ein internes Event einer abonnierbaren Ereignisart und einer Nachricht zu.
/// `watched` sagt, ob die CVE des Events auf der Watchlist steht (nur dann gibt es CVE-Meldungen).
/// `None`: keine Benachrichtigung (z. B. UNKNOWN, auch Proxmox, oder nicht beobachtet).
/// `my_releases`: Release-Codenamen, die auf mindestens einem Host laufen. Eine Feed-Änderung zu „behoben“
/// zählt nur dann als `fix_available`, wenn mindestens eine betroffene Release dazugehört.
pub fn route(
    kind: &str,
    payload: &Value,
    watched: bool,
    my_releases: &HashSet<String>,
) -> Option<(&'static str, Message)> {
    match kind {
        "host_status_changed" => {
            let msg = status_change_message(
                str_of(payload, "name"),
                str_of(payload, "from"),
                str_of(payload, "to"),
            )?;
            let category = if str_of(payload, "to") == "stale" {
                AGENT_SILENT
            } else {
                HOST_STATUS
            };
            Some((category, msg))
        }
        "host_cve_status_changed" => {
            // UNKNOWN löst nie einen Alarm aus (steckt in host_cve_message).
            let msg = host_cve_message(payload)?;
            let category = match str_of(payload, "to") {
                "fixed" | "fixed_installed_reboot_required" => FIX_AVAILABLE,
                _ => WATCHLIST_CVE,
            };
            Some((category, msg))
        }
        "cve_new" | "cve_status_changed" => {
            if !watched {
                return None;
            }
            let fixed = payload
                .get("changes")
                .and_then(Value::as_array)
                .is_some_and(|c| {
                    c.iter().any(|c| {
                        str_of(c, "to") == "fixed" && my_releases.contains(str_of(c, "release"))
                    })
                });
            let category = if fixed { FIX_AVAILABLE } else { WATCHLIST_CVE };
            Some((category, cve_change_message(kind, payload)))
        }
        "feed_failing" => Some((FEED_FAILING, feed_failing_message(payload))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test hosts run "noble" only.
    fn route(kind: &str, payload: &Value, watched: bool) -> Option<(&'static str, Message)> {
        super::route(kind, payload, watched, &HashSet::from(["noble".to_owned()]))
    }

    #[test]
    fn stale_is_agent_silent_other_changes_are_host_status() {
        let ev = |to: &str| json!({"name": "web1", "from": "ok", "to": to});
        assert_eq!(
            route("host_status_changed", &ev("stale"), false).unwrap().0,
            AGENT_SILENT
        );
        assert_eq!(
            route("host_status_changed", &ev("security_updates"), false)
                .unwrap()
                .0,
            HOST_STATUS
        );
        // Erster Report eines gesunden Hosts bleibt still.
        assert!(route(
            "host_status_changed",
            &json!({"name": "w", "from": "pending", "to": "ok"}),
            false
        )
        .is_none());
    }

    #[test]
    fn host_cve_categories_and_unknown_is_silent() {
        let ev = |to: &str, watched: bool| json!({"cve_id": "CVE-2024-1", "host": "h", "from": "vulnerable", "to": to, "watched": watched});
        assert_eq!(
            route("host_cve_status_changed", &ev("vulnerable", true), true)
                .unwrap()
                .0,
            WATCHLIST_CVE
        );
        assert_eq!(
            route(
                "host_cve_status_changed",
                &ev("fixed_installed_reboot_required", true),
                true
            )
            .unwrap()
            .0,
            FIX_AVAILABLE
        );
        assert_eq!(
            route("host_cve_status_changed", &ev("fixed", true), true)
                .unwrap()
                .0,
            FIX_AVAILABLE
        );
        // Proxmox/unklare Lage: UNKNOWN erzeugt nie eine Meldung, auch nicht auf der Watchlist.
        assert!(route("host_cve_status_changed", &ev("unknown", true), true).is_none());
        assert!(route("host_cve_status_changed", &ev("vulnerable", false), false).is_none());
    }

    #[test]
    fn feed_changes_need_the_watchlist() {
        let ev = |to: &str| {
            json!({"cve_id": "CVE-2024-1", "source": "ubuntu",
            "changes": [{"release": "noble", "package": "linux", "from": "vulnerable", "to": to, "fix_version": "1"}]})
        };
        assert!(route("cve_status_changed", &ev("fixed"), false).is_none());
        assert_eq!(
            route("cve_status_changed", &ev("fixed"), true).unwrap().0,
            FIX_AVAILABLE
        );
        assert_eq!(
            route("cve_status_changed", &ev("fix_pending"), true)
                .unwrap()
                .0,
            WATCHLIST_CVE
        );
        assert_eq!(
            route("cve_new", &ev("vulnerable"), true).unwrap().0,
            WATCHLIST_CVE
        );
    }

    #[test]
    fn fix_available_needs_a_release_of_one_of_my_hosts() {
        let ev = |release: &str| {
            json!({"cve_id": "CVE-2024-1", "source": "ubuntu",
            "changes": [{"release": release, "package": "linux", "from": "vulnerable", "to": "fixed", "fix_version": "1"}]})
        };
        // A release no host runs is still a watchlist change, but no "fix available" for me.
        assert_eq!(
            route("cve_status_changed", &ev("focal"), true).unwrap().0,
            WATCHLIST_CVE
        );
        assert_eq!(
            route("cve_status_changed", &ev("noble"), true).unwrap().0,
            FIX_AVAILABLE
        );
        // No hosts at all: never fix_available from feed changes.
        let none = HashSet::new();
        assert_eq!(
            super::route("cve_status_changed", &ev("noble"), true, &none)
                .unwrap()
                .0,
            WATCHLIST_CVE
        );
    }

    #[test]
    fn feed_failing_and_unknown_kinds() {
        assert_eq!(
            route(
                "feed_failing",
                &json!({"source": "debian", "failures": 3, "error": "x"}),
                false
            )
            .unwrap()
            .0,
            FEED_FAILING
        );
        assert!(route("irgendwas", &json!({}), true).is_none());
    }
}
