use chrono::{DateTime, Duration, Utc};

/// Gesamtstatus eines Hosts, in absteigender Dringlichkeit (stale/pending zuerst).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    Pending,
    Stale,
    CveVulnerable,
    SecurityUpdates,
    RebootRequired,
    UpdatesPending,
    Ok,
}

impl HostStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Stale => "stale",
            Self::CveVulnerable => "cve_vulnerable",
            Self::SecurityUpdates => "security_updates",
            Self::RebootRequired => "reboot_required",
            Self::UpdatesPending => "updates_pending",
            Self::Ok => "ok",
        }
    }

    pub fn label_de(s: &str) -> &'static str {
        match s {
            "pending" => "noch kein Report",
            "stale" => "meldet sich nicht mehr",
            "cve_vulnerable" => "verwundbar (CVE)",
            "security_updates" => "Sicherheitsupdates offen",
            "reboot_required" => "Neustart nötig",
            "updates_pending" => "Updates offen",
            "ok" => "aktuell",
            _ => "unbekannt",
        }
    }
}

pub struct Snapshot {
    pub last_report_at: Option<DateTime<Utc>>,
    pub reboot_required_file: bool,
    pub reboot_needed_kernel: Option<bool>,
    pub updates_pending: i32,
    pub updates_security: i32,
    /// Mindestens eine CVE mit Status "vulnerable" für den laufenden Kernel.
    pub cve_vulnerable: bool,
}

pub fn derive(s: &Snapshot, now: DateTime<Utc>, stale_after: Duration) -> HostStatus {
    match s.last_report_at {
        None => HostStatus::Pending,
        Some(t) if now - t > stale_after => HostStatus::Stale,
        Some(_) if s.cve_vulnerable => HostStatus::CveVulnerable,
        Some(_) if s.updates_security > 0 => HostStatus::SecurityUpdates,
        Some(_) if s.reboot_required_file || s.reboot_needed_kernel == Some(true) => {
            HostStatus::RebootRequired
        }
        Some(_) if s.updates_pending > 0 => HostStatus::UpdatesPending,
        Some(_) => HostStatus::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(age_h: Option<i64>) -> (Snapshot, DateTime<Utc>) {
        let now = Utc::now();
        (
            Snapshot {
                last_report_at: age_h.map(|h| now - Duration::hours(h)),
                reboot_required_file: false,
                reboot_needed_kernel: Some(false),
                updates_pending: 0,
                updates_security: 0,
                cve_vulnerable: false,
            },
            now,
        )
    }

    fn st(s: &Snapshot, now: DateTime<Utc>) -> HostStatus {
        derive(s, now, Duration::hours(26))
    }

    #[test]
    fn never_reported_is_pending() {
        let (s, now) = snap(None);
        assert_eq!(st(&s, now), HostStatus::Pending);
    }

    #[test]
    fn stale_after_26_hours() {
        let (s, now) = snap(Some(25));
        assert_eq!(st(&s, now), HostStatus::Ok);
        let (s, now) = snap(Some(27));
        assert_eq!(st(&s, now), HostStatus::Stale);
    }

    #[test]
    fn priority_order() {
        let (mut s, now) = snap(Some(1));
        s.updates_pending = 3;
        assert_eq!(st(&s, now), HostStatus::UpdatesPending);
        s.reboot_needed_kernel = Some(true);
        assert_eq!(st(&s, now), HostStatus::RebootRequired);
        s.updates_security = 1;
        assert_eq!(st(&s, now), HostStatus::SecurityUpdates);
        s.cve_vulnerable = true;
        assert_eq!(st(&s, now), HostStatus::CveVulnerable);
    }

    #[test]
    fn reboot_required_file_counts() {
        let (mut s, now) = snap(Some(1));
        s.reboot_required_file = true;
        assert_eq!(st(&s, now), HostStatus::RebootRequired);
    }
}
