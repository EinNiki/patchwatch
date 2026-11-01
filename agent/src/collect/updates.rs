use crate::cmd::Runner;
use serde::Serialize;

/// Höchstzahl der mitgeschickten Einträge (Sicherheitsupdates stehen vorn).
const MAX_ITEMS: usize = 1000;

/// Ein offenes Paket-Update.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct UpdateItem {
    pub name: String,
    /// Installierte Version; `None` bei neu hinzukommenden Paketen.
    pub from: Option<String>,
    pub to: String,
    pub origin: String,
    pub security: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Updates {
    pub pending: u32,
    pub security: u32,
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
        from,
        to: to.to_owned(),
        origin: origin.to_owned(),
        security: origin.to_ascii_lowercase().contains("security"),
    })
}

/// Liest die `Inst`-Zeilen einer `apt-get -s`-Simulation; Security = Herkunft enthält "security".
pub fn parse_apt_simulation(out: &str) -> Updates {
    let mut items: Vec<UpdateItem> = out.lines().filter_map(parse_inst).collect();
    let pending = items.len() as u32;
    let security = items.iter().filter(|i| i.security).count() as u32;
    // Sicherheit zuerst, danach nach Name; die Sortierung ist stabil und deterministisch.
    items.sort_by(|a, b| {
        b.security
            .cmp(&a.security)
            .then_with(|| a.name.cmp(&b.name))
    });
    items.truncate(MAX_ITEMS);
    Updates {
        pending,
        security,
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
        assert_eq!(u.items[0].to, "2.35-0ubuntu3.8");
        assert_eq!(
            u.items[0].origin,
            "Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security"
        );
        assert!(u.items[0].security);
        // Neues Paket ohne installierte Version.
        assert_eq!(u.items[1].from, None);
        assert!(!u.items[2].security);
    }
}
