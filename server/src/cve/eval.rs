//! Bewertung eines Hosts gegen eine CVE. Reine Funktion ohne Datenbankzugriff.
//!
//! Grundsatz: Fehlende oder unklare Datenlage ergibt nie "grün", sondern `Unknown`.

use super::{is_kernel_source, SourceStatus};
use debversion::Version;
use serde_json::{json, Value};

/// Proxmox Security Advisories (Forum; URL geprüft, HTTP 200).
pub const PROXMOX_ADVISORIES_URL: &str = "https://forum.proxmox.com/forums/security-advisories.26/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CveStatus {
    Fixed,
    /// Fix ist installiert, läuft aber noch nicht: laufender Kernel ist älter.
    FixedInstalledRebootRequired,
    Vulnerable,
    FixPending,
    NotAffected,
    Unknown,
}

impl CveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::FixedInstalledRebootRequired => "fixed_installed_reboot_required",
            Self::Vulnerable => "vulnerable",
            Self::FixPending => "fix_pending",
            Self::NotAffected => "not_affected",
            Self::Unknown => "unknown",
        }
    }

    pub fn label_de(s: &str) -> &'static str {
        match s {
            "fixed" => "behoben",
            "fixed_installed_reboot_required" => "gefixt installiert, Neustart nötig",
            "vulnerable" => "verwundbar",
            "fix_pending" => "Fix angekündigt",
            "not_affected" => "nicht betroffen",
            _ => "unbekannt",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "fixed" => Self::Fixed,
            "fixed_installed_reboot_required" => Self::FixedInstalledRebootRequired,
            "vulnerable" => Self::Vulnerable,
            "fix_pending" => Self::FixPending,
            "not_affected" => Self::NotAffected,
            _ => Self::Unknown,
        }
    }
}

/// Kerneldaten eines Hosts; bewertet wird der **laufende** Kernel.
#[derive(Debug, Clone, Default)]
pub struct HostKernel {
    pub distro_id: String,
    pub codename: Option<String>,
    pub running_release: Option<String>,
    pub package: Option<String>,
    pub package_version: Option<String>,
    pub source: Option<String>,
    /// Version des neuesten installierten Kernel-Pakets.
    pub newest_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SourceRow {
    pub source: String,
    pub release: String,
    pub package: String,
    pub status: SourceStatus,
    pub fix_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub status: CveStatus,
    pub reason: String,
    pub sources: Vec<Value>,
}

fn unknown(reason: impl Into<String>, sources: Vec<Value>) -> Verdict {
    Verdict {
        status: CveStatus::Unknown,
        reason: reason.into(),
        sources,
    }
}

/// Proxmox-Kernel (`-pve`): dafür gibt es keine belastbare CVE-Quelle.
pub fn is_proxmox_kernel(h: &HostKernel) -> bool {
    h.running_release
        .as_deref()
        .is_some_and(|r| r.ends_with("-pve"))
        || h.package
            .as_deref()
            .is_some_and(|p| p.starts_with("proxmox-kernel") || p.starts_with("pve-kernel"))
}

/// Quellpaket im Tracker: `linux-signed*` verweist auf das jeweilige `linux*`-Quellpaket.
pub fn tracker_package(distro_id: &str, source: Option<&str>) -> Option<String> {
    const DEBIAN_SIGNED_ARCHES: &[&str] = &["amd64", "arm64", "i386"];
    let s = source?;
    if s == "linux-signed" {
        return Some("linux".into());
    }
    if let Some(rest) = s.strip_prefix("linux-signed-") {
        return Some(
            if distro_id == "debian" && DEBIAN_SIGNED_ARCHES.contains(&rest) {
                "linux".into()
            } else {
                format!("linux-{rest}")
            },
        );
    }
    is_kernel_source(s).then(|| s.to_owned())
}

fn source_json(r: &SourceRow) -> Value {
    json!({ "source": r.source, "release": r.release, "package": r.package,
            "status": r.status.as_str(), "fix_version": r.fix_version })
}

fn row_verdict(
    r: &SourceRow,
    installed: &Version,
    newest: Option<&Version>,
) -> (CveStatus, String) {
    let who = format!("{} ({}/{})", r.source, r.release, r.package);
    match r.status {
        SourceStatus::NotAffected => (CveStatus::NotAffected, format!("{who}: nicht betroffen.")),
        SourceStatus::Vulnerable => (
            CveStatus::Vulnerable,
            format!("{who}: betroffen, bisher kein Fix veröffentlicht."),
        ),
        SourceStatus::Unknown => (
            CveStatus::Unknown,
            format!("{who}: noch nicht bewertet oder unklar."),
        ),
        SourceStatus::FixPending => {
            let target = r
                .fix_version
                .as_deref()
                .map(|v| format!(" (voraussichtlich in {v})"))
                .unwrap_or_default();
            (
                CveStatus::FixPending,
                format!("{who}: Fix angekündigt{target}, noch nicht veröffentlicht."),
            )
        }
        SourceStatus::Fixed => {
            let Some(fix) = r
                .fix_version
                .as_deref()
                .and_then(|f| f.parse::<Version>().ok())
            else {
                return (
                    CveStatus::Unknown,
                    format!("{who}: als behoben markiert, aber ohne gültige Fix-Version."),
                );
            };
            if installed >= &fix {
                (
                    CveStatus::Fixed,
                    format!(
                        "{who}: behoben in {fix}; laufender Kernel {installed} enthält den Fix."
                    ),
                )
            } else if newest.is_some_and(|n| n >= &fix) {
                (
                    CveStatus::FixedInstalledRebootRequired,
                    format!("{who}: behoben in {fix}. Der Fix ist installiert, läuft aber noch nicht (laufend {installed}). Neustart nötig."),
                )
            } else {
                (
                    CveStatus::Vulnerable,
                    format!("{who}: behoben in {fix}, laufender Kernel {installed} ist älter. Update einspielen und neu starten."),
                )
            }
        }
    }
}

/// Bewertet den laufenden Kernel eines Hosts anhand aller Quelleneinträge zu einer CVE.
pub fn evaluate(h: &HostKernel, rows: &[SourceRow]) -> Verdict {
    if is_proxmox_kernel(h) {
        return unknown(
            format!(
                "Proxmox-Kernel ({}): Für -pve-Kernel gibt es keine belastbare CVE-Quelle. Manuell prüfen: {PROXMOX_ADVISORIES_URL}",
                h.running_release.as_deref().unwrap_or("-pve")
            ),
            vec![],
        );
    }
    let Some(codename) = h.codename.as_deref() else {
        return unknown("Release-Codename des Hosts ist unbekannt.", vec![]);
    };
    let Some(pkg) = tracker_package(&h.distro_id, h.source.as_deref()) else {
        return unknown(
            format!(
                "Kernel-Quellpaket nicht zuordenbar (Quelle: {}, Paket: {}).",
                h.source.as_deref().unwrap_or("-"),
                h.package.as_deref().unwrap_or("-")
            ),
            vec![],
        );
    };
    let Some(installed) = h
        .package_version
        .as_deref()
        .and_then(|v| v.parse::<Version>().ok())
    else {
        return unknown(
            "Version des laufenden Kernel-Pakets ist unbekannt oder ungültig.",
            vec![],
        );
    };
    let newest = h
        .newest_version
        .as_deref()
        .and_then(|v| v.parse::<Version>().ok());

    let mine: Vec<&SourceRow> = rows
        .iter()
        .filter(|r| r.release == codename && r.package == pkg)
        .collect();
    let sources: Vec<Value> = mine.iter().map(|r| source_json(r)).collect();
    if mine.is_empty() {
        return unknown(
            format!("Keine Daten der CVE-Quellen für {pkg} in {codename}."),
            sources,
        );
    }
    // Distributions-Tracker (ubuntu, debian) haben Vorrang vor der ergänzenden Quelle OSV.
    let row = mine
        .iter()
        .find(|r| r.source != "osv")
        .or_else(|| mine.first())
        .copied()
        .expect("mine ist nicht leer");
    let (status, reason) = row_verdict(row, &installed, newest.as_ref());
    Verdict {
        status,
        reason,
        sources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(
        distro: &str,
        codename: &str,
        release: &str,
        pkg: &str,
        source: &str,
        ver: &str,
        newest: Option<&str>,
    ) -> HostKernel {
        HostKernel {
            distro_id: distro.into(),
            codename: Some(codename.into()),
            running_release: Some(release.into()),
            package: Some(pkg.into()),
            package_version: Some(ver.into()),
            source: Some(source.into()),
            newest_version: newest.map(str::to_owned),
        }
    }

    fn row(src: &str, rel: &str, pkg: &str, st: SourceStatus, fix: Option<&str>) -> SourceRow {
        SourceRow {
            source: src.into(),
            release: rel.into(),
            package: pkg.into(),
            status: st,
            fix_version: fix.map(str::to_owned),
        }
    }

    fn ubuntu_2204(ver: &str, newest: Option<&str>) -> HostKernel {
        host(
            "ubuntu",
            "jammy",
            "5.15.0-100-generic",
            "linux-image-5.15.0-100-generic",
            "linux-signed",
            ver,
            newest,
        )
    }

    fn ubuntu_2404(ver: &str, newest: Option<&str>) -> HostKernel {
        host(
            "ubuntu",
            "noble",
            "6.8.0-31-generic",
            "linux-image-6.8.0-31-generic",
            "linux-signed",
            ver,
            newest,
        )
    }

    fn trixie(ver: &str, newest: Option<&str>) -> HostKernel {
        host(
            "debian",
            "trixie",
            "6.12.48+deb13-amd64",
            "linux-image-6.12.48+deb13-amd64",
            "linux-signed-amd64",
            ver,
            newest,
        )
    }

    use SourceStatus::*;

    #[test]
    fn ubuntu_22_04_fixed_vulnerable_and_reboot() {
        let rows = [row(
            "ubuntu",
            "jammy",
            "linux",
            Fixed,
            Some("5.15.0-105.115"),
        )];
        // Laufender Kernel enthält den Fix.
        let v = evaluate(
            &ubuntu_2204("5.15.0-107.117", Some("5.15.0-107.117")),
            &rows,
        );
        assert_eq!(v.status, CveStatus::Fixed, "{}", v.reason);
        // Fix installiert, aber noch nicht gebootet.
        let v = evaluate(
            &ubuntu_2204("5.15.0-100.110", Some("5.15.0-107.117")),
            &rows,
        );
        assert_eq!(v.status, CveStatus::FixedInstalledRebootRequired);
        assert!(v.reason.contains("Neustart nötig"));
        // Fix existiert, ist aber weder installiert noch läuft er.
        let v = evaluate(
            &ubuntu_2204("5.15.0-100.110", Some("5.15.0-100.110")),
            &rows,
        );
        assert_eq!(v.status, CveStatus::Vulnerable);
    }

    #[test]
    fn ubuntu_24_04_all_source_states() {
        let h = ubuntu_2404("6.8.0-31.31", Some("6.8.0-31.31"));
        let cases = [
            (
                row("ubuntu", "noble", "linux", Vulnerable, None),
                CveStatus::Vulnerable,
            ),
            (
                row(
                    "ubuntu",
                    "noble",
                    "linux",
                    FixPending,
                    Some("6.8.0-149.149"),
                ),
                CveStatus::FixPending,
            ),
            (
                row("ubuntu", "noble", "linux", NotAffected, None),
                CveStatus::NotAffected,
            ),
            (
                row("ubuntu", "noble", "linux", Unknown, None),
                CveStatus::Unknown,
            ),
            (
                row("ubuntu", "noble", "linux", Fixed, Some("6.8.0-31.31")),
                CveStatus::Fixed,
            ),
        ];
        for (r, want) in cases {
            assert_eq!(
                evaluate(&h, std::slice::from_ref(&r)).status,
                want,
                "{:?}",
                r.status
            );
        }
    }

    /// Hwe-Kernel auf 22.04: `linux-signed-hwe-6.8` -> `linux-hwe-6.8`, Version mit `~22.04.1`.
    #[test]
    fn ubuntu_hwe_kernel_uses_hwe_package_rows() {
        let h = host(
            "ubuntu",
            "jammy",
            "6.8.0-31-generic",
            "linux-image-6.8.0-31-generic",
            "linux-signed-hwe-6.8",
            "6.8.0-31.31~22.04.1",
            None,
        );
        let rows = [
            row("ubuntu", "jammy", "linux", Vulnerable, None),
            row(
                "ubuntu",
                "jammy",
                "linux-hwe-6.8",
                Fixed,
                Some("6.8.0-40.40~22.04.1"),
            ),
        ];
        let v = evaluate(&h, &rows);
        assert_eq!(v.status, CveStatus::Vulnerable);
        assert!(v.reason.contains("linux-hwe-6.8"));
        assert_eq!(v.sources.len(), 1);
    }

    #[test]
    fn debian_trixie_signed_source_maps_to_linux() {
        assert_eq!(
            tracker_package("debian", Some("linux-signed-amd64")).as_deref(),
            Some("linux")
        );
        let rows = [row("debian", "trixie", "linux", Fixed, Some("6.12.43-1"))];
        assert_eq!(
            evaluate(&trixie("6.12.48-1", None), &rows).status,
            CveStatus::Fixed
        );
        assert_eq!(
            evaluate(&trixie("6.12.30-1", None), &rows).status,
            CveStatus::Vulnerable
        );
        let open = [row("debian", "trixie", "linux", Vulnerable, None)];
        assert_eq!(
            evaluate(&trixie("6.12.48-1", None), &open).status,
            CveStatus::Vulnerable
        );
    }

    #[test]
    fn debian_rows_of_other_release_do_not_apply() {
        let rows = [row("debian", "bookworm", "linux", Fixed, Some("6.1.1-1"))];
        let v = evaluate(&trixie("6.12.48-1", None), &rows);
        assert_eq!(v.status, CveStatus::Unknown);
        assert!(v.reason.contains("Keine Daten"));
    }

    /// Proxmox 9: nie grün, immer UNKNOWN mit Hinweis und Link, egal was die Quellen sagen.
    #[test]
    fn proxmox_is_always_unknown_with_link() {
        let h = host(
            "debian",
            "trixie",
            "6.14.11-2-pve",
            "proxmox-kernel-6.14.11-2-pve-signed",
            "proxmox-kernel-6.14",
            "6.14.11-2",
            None,
        );
        let rows = [
            row("debian", "trixie", "linux", Fixed, Some("1.0")),
            row("debian", "trixie", "linux", NotAffected, None),
        ];
        for r in [&rows[..1], &rows[1..], &[]] {
            let v = evaluate(&h, r);
            assert_eq!(v.status, CveStatus::Unknown);
            assert!(v.reason.contains("Manuell prüfen"));
            assert!(v.reason.contains(PROXMOX_ADVISORIES_URL));
        }
        // Auch erkannt, wenn nur das Paket verrät, dass es ein Proxmox-Kernel ist.
        let mut h2 = h.clone();
        h2.running_release = Some("6.14.11-2".into());
        assert!(is_proxmox_kernel(&h2));
    }

    #[test]
    fn missing_data_is_never_green() {
        let rows = [row("ubuntu", "noble", "linux", Fixed, Some("6.8.0-35.35"))];
        let mut h = ubuntu_2404("6.8.0-31.31", None);
        h.codename = None;
        assert_eq!(evaluate(&h, &rows).status, CveStatus::Unknown);
        let mut h = ubuntu_2404("6.8.0-31.31", None);
        h.package_version = None;
        assert_eq!(evaluate(&h, &rows).status, CveStatus::Unknown);
        let mut h = ubuntu_2404("kein version", None);
        h.package_version = Some("kein version".into());
        assert_eq!(evaluate(&h, &rows).status, CveStatus::Unknown);
        let mut h = ubuntu_2404("6.8.0-31.31", None);
        h.source = None;
        assert_eq!(evaluate(&h, &rows).status, CveStatus::Unknown);
        assert_eq!(
            evaluate(&ubuntu_2404("6.8.0-31.31", None), &[]).status,
            CveStatus::Unknown
        );
        // "behoben" ohne gültige Version ist kein "behoben".
        let broken = [row("ubuntu", "noble", "linux", Fixed, None)];
        assert_eq!(
            evaluate(&ubuntu_2404("6.8.0-31.31", None), &broken).status,
            CveStatus::Unknown
        );
    }

    #[test]
    fn distro_tracker_wins_over_osv() {
        let h = ubuntu_2404("6.8.0-31.31", Some("6.8.0-31.31"));
        let rows = [
            row("osv", "noble", "linux", Vulnerable, None),
            row("ubuntu", "noble", "linux", NotAffected, None),
        ];
        let v = evaluate(&h, &rows);
        assert_eq!(v.status, CveStatus::NotAffected);
        assert_eq!(v.sources.len(), 2);
        // Ohne Distributions-Eintrag zählt OSV.
        assert_eq!(evaluate(&h, &rows[..1]).status, CveStatus::Vulnerable);
    }

    #[test]
    fn tracker_package_mapping() {
        assert_eq!(
            tracker_package("ubuntu", Some("linux-signed")).as_deref(),
            Some("linux")
        );
        assert_eq!(
            tracker_package("ubuntu", Some("linux-signed-hwe-6.8")).as_deref(),
            Some("linux-hwe-6.8")
        );
        assert_eq!(
            tracker_package("ubuntu", Some("linux-aws")).as_deref(),
            Some("linux-aws")
        );
        assert_eq!(
            tracker_package("ubuntu", Some("linux")).as_deref(),
            Some("linux")
        );
        assert_eq!(tracker_package("ubuntu", Some("openssl")), None);
        assert_eq!(tracker_package("ubuntu", None), None);
    }
}
