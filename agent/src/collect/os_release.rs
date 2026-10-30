use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct OsInfo {
    pub id: String,
    pub version_id: Option<String>,
    pub codename: Option<String>,
    pub pretty_name: Option<String>,
}

/// Parst /etc/os-release (KEY=VALUE, Werte optional in Anführungszeichen).
pub fn parse(text: &str) -> Option<OsInfo> {
    let get = |key: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().trim_matches(|c| c == '"' || c == '\'').to_owned())
        })
    };
    Some(OsInfo {
        id: get("ID").filter(|s| !s.is_empty())?,
        version_id: get("VERSION_ID"),
        codename: get("VERSION_CODENAME").filter(|s| !s.is_empty()),
        pretty_name: get("PRETTY_NAME"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(fixture: &str, id: &str, ver: &str, codename: &str) {
        let o = parse(fixture).unwrap();
        assert_eq!(o.id, id);
        assert_eq!(o.version_id.as_deref(), Some(ver));
        assert_eq!(o.codename.as_deref(), Some(codename));
    }

    #[test]
    fn supported_distros() {
        case(
            include_str!("../../tests/fixtures/os-release.ubuntu-22.04"),
            "ubuntu",
            "22.04",
            "jammy",
        );
        case(
            include_str!("../../tests/fixtures/os-release.ubuntu-24.04"),
            "ubuntu",
            "24.04",
            "noble",
        );
        case(
            include_str!("../../tests/fixtures/os-release.debian-trixie"),
            "debian",
            "13",
            "trixie",
        );
        case(
            include_str!("../../tests/fixtures/os-release.proxmox-9"),
            "debian",
            "13",
            "trixie",
        );
    }

    #[test]
    fn missing_id_is_rejected() {
        assert!(parse("NAME=foo\n").is_none());
    }
}
