use crate::cmd::Runner;
use serde::Serialize;

/// Höchstzahl der mitgeschickten Einträge (Sicherheitsupdates stehen vorn).
const MAX_ITEMS: usize = 1000;

/// Art des Eintrags in der Simulation: Aktualisierung, neu zu installieren oder zu entfernen.
#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Upgrade,
    New,
    Remove,
}

/// Ein offenes Paket-Update.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct UpdateItem {
    pub name: String,
    pub kind: Kind,
    /// Installierte Version; `None` bei neu hinzukommenden Paketen.
    pub from: Option<String>,
    /// Verfügbare Version; `None` bei zu entfernenden Paketen.
    pub to: Option<String>,
    pub origin: String,
    pub security: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Updates {
    /// Aktualisierungen und neue Pakete (ohne Entfernungen), wie bisher.
    pub pending: u32,
    pub security: u32,
    /// Pakete, die die Simulation entfernen würde.
    pub remove: u32,
    pub items: Vec<UpdateItem>,
}

/// `Inst name [alt] (neu herkunft1, herkunft2 [arch])` -> Eintrag.
fn parse_inst(line: &str) -> Option<UpdateItem> {
    let rest = line.strip_prefix("Inst ")?;
    let (name, rest) = rest.split_once(' ')?;
    let (before, after) = rest.split_once('(')?;
    let from = before
        .trim()
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .map(str::to_owned);
    let after = after.split_once(')').map_or(after, |(a, _)| a);
    let (to, origin) = after.split_once(' ').unwrap_or((after, ""));
    // Architektur in eckigen Klammern am Ende der Herkunft entfernen.
    let origin = origin.rsplit_once(" [").map_or(origin, |(o, _)| o).trim();
    Some(UpdateItem {
        name: name.to_owned(),
        kind: if from.is_some() {
            Kind::Upgrade
        } else {
            Kind::New
        },
        from,
        to: Some(to.to_owned()),
        origin: origin.to_owned(),
        security: origin.to_ascii_lowercase().contains("security"),
    })
}

/// `Remv name [alt] ...` -> Eintrag zum Entfernen (ohne Herkunft, nie Sicherheit).
fn parse_remv(line: &str) -> Option<UpdateItem> {
    let rest = line.strip_prefix("Remv ")?;
    let (name, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let from = rest
        .trim()
        .strip_prefix('[')
        .and_then(|v| v.split_once(']'))
        .map(|(v, _)| v.to_owned());
    (!name.is_empty()).then(|| UpdateItem {
        name: name.to_owned(),
        kind: Kind::Remove,
        from,
        to: None,
        origin: String::new(),
        security: false,
    })
}

/// Liest die `Inst`- und `Remv`-Zeilen einer `apt-get -s`-Simulation; Security = Herkunft enthält "security".
pub fn parse_apt_simulation(out: &str) -> Updates {
    let mut items: Vec<UpdateItem> = out
        .lines()
        .filter_map(|l| parse_inst(l).or_else(|| parse_remv(l)))
        .collect();
    let remove = items.iter().filter(|i| i.kind == Kind::Remove).count() as u32;
    let pending = items.len() as u32 - remove;
    let security = items.iter().filter(|i| i.security).count() as u32;
    // Sicherheit zuerst, dann Art (Aktualisierung, neu, entfernen), dann Name; stabil und deterministisch.
    items.sort_by(|a, b| {
        b.security
            .cmp(&a.security)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.name.cmp(&b.name))
    });
    items.truncate(MAX_ITEMS);
    Updates {
        pending,
        security,
        remove,
        items,
    }
}

pub fn collect(r: &dyn Runner) -> Option<Updates> {
    let out = r.run(
        "apt-get",
        &["-s", "-o", "Debug::NoLocking=1", "dist-upgrade"],
    )?;
    Some(parse_apt_simulation(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(fixture: &str) -> (u32, u32) {
        let u = parse_apt_simulation(fixture);
        (u.pending, u.security)
    }

    #[test]
    fn ubuntu_22_04() {
        let f = include_str!("../../tests/fixtures/apt-sim.ubuntu-22.04");
        assert_eq!(counts(f), (3, 2));
    }

    #[test]
    fn debian_trixie() {
        let f = include_str!("../../tests/fixtures/apt-sim.debian-trixie");
        assert_eq!(counts(f), (2, 1));
    }

    #[test]
    fn nothing_to_do() {
        let u = parse_apt_simulation("Reading package lists...\n");
        assert_eq!((u.pending, u.security, u.items.len()), (0, 0, 0));
    }

    #[test]
    fn items_have_names_versions_and_origin() {
        let u = parse_apt_simulation(include_str!("../../tests/fixtures/apt-sim.ubuntu-22.04"));
        // Sicherheit zuerst, dann alphabetisch.
        let names: Vec<_> = u.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["libc6", "linux-image-5.15.0-118-generic", "vim"]);
        assert_eq!(u.items[0].from.as_deref(), Some("2.35-0ubuntu3.7"));
        assert_eq!(u.items[0].to.as_deref(), Some("2.35-0ubuntu3.8"));
        assert_eq!(
            u.items[0].origin,
            "Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security"
        );
        assert!(u.items[0].security);
        // Neues Paket ohne installierte Version.
        assert_eq!(u.items[1].from, None);
        assert_eq!(u.items[1].kind, Kind::New);
        assert_eq!(u.items[0].kind, Kind::Upgrade);
        assert!(!u.items[2].security);
    }

    #[test]
    fn removals_are_listed_apart_and_never_count_as_pending_or_security() {
        let u = parse_apt_simulation(include_str!("../../tests/fixtures/apt-sim.ubuntu-24.04"));
        assert_eq!((u.pending, u.security, u.remove), (5, 4, 2));
        let removed: Vec<_> = u
            .items
            .iter()
            .filter(|i| i.kind == Kind::Remove)
            .map(|i| (i.name.as_str(), i.from.as_deref(), i.to.as_deref()))
            .collect();
        assert_eq!(
            removed,
            [
                ("linux-image-6.8.0-40-generic", Some("6.8.0-40.40"), None),
                ("oldlib", Some("1.2-3"), None)
            ]
        );
        // Sicherheit zuerst, Entfernungen zuletzt; ESM-Herkunft gilt als Sicherheit.
        let names: Vec<_> = u.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names[..4],
            [
                "esm-tool",
                "libssl3t64",
                "openssl",
                "linux-image-6.8.0-60-generic"
            ]
        );
        assert_eq!(names[4], "nginx");
        assert!(
            u.items
                .iter()
                .find(|i| i.name == "esm-tool")
                .unwrap()
                .security
        );
    }

    #[test]
    fn simulation_never_runs_an_update_or_apt_update() {
        // Der Agent ruft ausschließlich die Simulation auf: `-s`, nie `install`, `upgrade` ohne `-s` oder `update`.
        let src = include_str!("updates.rs");
        let call = src
            .split("pub fn collect")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(call.contains("\"-s\""));
        assert!(!call.contains("\"update\"") && !call.contains("\"install\""));
    }
}
