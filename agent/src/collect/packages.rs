use crate::cmd::Runner;
use crate::token::sha256;
use serde::Serialize;

/// Höchstzahl der gemeldeten Pakete; darüber wird abgeschnitten und `truncated` gesetzt.
pub const MAX_PACKAGES: usize = 20_000;

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
    pub source: Option<String>,
    pub source_version: Option<String>,
}

/// Installierte Pakete mit Hash über die gemeldete (sortierte) Liste.
#[derive(Debug, PartialEq, Eq)]
pub struct PackageSet {
    pub packages: Vec<Package>,
    /// Anzahl vor dem Abschneiden.
    pub total: usize,
    pub truncated: bool,
    /// SHA-256 (hex) über die kanonische, sortierte Liste; ändert sich nur, wenn sich die Pakete ändern.
    pub hash: String,
}

/// Eine Zeile von `dpkg-query` (Status, Name, Architektur, Version, Quellpaket, Quellversion).
/// Nur installierte Pakete (zweites Zeichen der Statuskürzel `i`: `ii`, `hi`); entfernte mit Konfigurationsresten (`rc`) nicht.
pub fn parse(out: &str) -> Vec<Package> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split('\t');
            let status = it.next()?;
            if status.chars().nth(1) != Some('i') {
                return None;
            }
            let (name, arch, version) = (it.next()?, it.next()?, it.next()?);
            let opt = |s: Option<&str>| s.filter(|v| !v.is_empty()).map(str::to_owned);
            (!name.is_empty() && !version.is_empty()).then(|| Package {
                name: name.to_owned(),
                version: version.to_owned(),
                arch: (!arch.is_empty()).then(|| arch.to_owned()),
                source: opt(it.next()),
                source_version: opt(it.next()),
            })
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sortiert (Name, Architektur, Version), schneidet bei `max` ab und bildet den Hash über genau die gemeldete Liste.
pub fn into_set(mut packages: Vec<Package>, max: usize) -> PackageSet {
    packages.sort_by(|a, b| (&a.name, &a.arch, &a.version).cmp(&(&b.name, &b.arch, &b.version)));
    let total = packages.len();
    let truncated = total > max;
    packages.truncate(max);
    let mut canon = String::new();
    for p in &packages {
        for part in [
            p.name.as_str(),
            p.arch.as_deref().unwrap_or(""),
            p.version.as_str(),
            p.source.as_deref().unwrap_or(""),
            p.source_version.as_deref().unwrap_or(""),
        ] {
            canon.push_str(part);
            canon.push('\t');
        }
        canon.push('\n');
    }
    PackageSet {
        hash: hex(&sha256(canon.as_bytes())),
        packages,
        total,
        truncated,
    }
}

pub fn collect(r: &dyn Runner) -> Option<PackageSet> {
    let out = r.run(
        "dpkg-query",
        &[
            "-W",
            "-f",
            "${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\n",
        ],
    )?;
    Some(into_set(parse(&out), MAX_PACKAGES))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/dpkg-query.debian-trixie");

    #[test]
    fn parses_installed_only_and_skips_broken_lines() {
        let p = parse(
            "ii \tbash\tamd64\t5.2.21-2\tbash\t5.2.21-2\nbroken\n\tx\nrc \told\tamd64\t1\told\t1\n",
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "bash");
        assert_eq!(p[0].arch.as_deref(), Some("amd64"));
        assert_eq!(p[0].source.as_deref(), Some("bash"));
    }

    #[test]
    fn fixture_keeps_held_and_multiarch_but_not_removed_packages() {
        let p = parse(FIXTURE);
        let names: Vec<_> = p.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"docker-ce"), "{names:?}");
        assert!(names.contains(&"iperf3"));
        // Gehaltenes Paket (hi) ist installiert.
        assert!(names.contains(&"openssh-server"));
        // Entfernt mit Konfigurationsresten (rc) und nur konfiguriertes (un) zählen nicht.
        assert!(!names.contains(&"oldtool"));
        assert!(!names.contains(&"gone"));
        // Multiarch: beide Architekturen bleiben erhalten (der Server entscheidet über die Zusammenführung).
        assert_eq!(p.iter().filter(|p| p.name == "libc6").count(), 2);
    }

    #[test]
    fn hash_ignores_input_order_and_changes_with_the_content() {
        let a = into_set(parse(FIXTURE), MAX_PACKAGES);
        let mut rev: Vec<Package> = parse(FIXTURE);
        rev.reverse();
        let b = into_set(rev, MAX_PACKAGES);
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.hash.len(), 64);
        let mut changed = parse(FIXTURE);
        changed[0].version.push('x');
        assert_ne!(into_set(changed, MAX_PACKAGES).hash, a.hash);
    }

    /// Fester Prüfwert für die in der Aufgabe genannte Grenze.
    #[test]
    fn limit_is_twenty_thousand() {
        assert_eq!(MAX_PACKAGES, 20_000);
        let lines: String = (0..20_005)
            .map(|i| format!("ii \tp{i:05}\tamd64\t1\t\t\n"))
            .collect();
        let set = into_set(parse(&lines), MAX_PACKAGES);
        assert_eq!(
            (set.packages.len(), set.total, set.truncated),
            (20_000, 20_005, true)
        );
    }

    #[test]
    fn list_is_cut_at_the_limit_and_the_hash_covers_what_is_sent() {
        let many: Vec<Package> = (0..30)
            .map(|i| Package {
                name: format!("pkg{i:03}"),
                version: "1".into(),
                arch: Some("amd64".into()),
                source: None,
                source_version: None,
            })
            .collect();
        let cut = into_set(many.clone(), 10);
        assert!(cut.truncated);
        assert_eq!((cut.packages.len(), cut.total), (10, 30));
        let direct = into_set(many[..10].to_vec(), 10);
        assert_eq!(cut.hash, direct.hash);
        assert!(!direct.truncated);
    }
}
