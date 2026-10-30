use crate::cmd::Runner;
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Updates {
    pub pending: u32,
    pub security: u32,
}

/// Zählt `Inst`-Zeilen einer `apt-get -s`-Simulation; Security = Herkunft enthält "security".
pub fn parse_apt_simulation(out: &str) -> Updates {
    let (mut pending, mut security) = (0, 0);
    for line in out.lines().filter(|l| l.starts_with("Inst ")) {
        pending += 1;
        if let Some((_, origin)) = line.split_once('(') {
            if origin.to_ascii_lowercase().contains("security") {
                security += 1;
            }
        }
    }
    Updates { pending, security }
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

    #[test]
    fn ubuntu_22_04() {
        let u = parse_apt_simulation(include_str!("../../tests/fixtures/apt-sim.ubuntu-22.04"));
        assert_eq!(
            u,
            Updates {
                pending: 3,
                security: 2
            }
        );
    }

    #[test]
    fn debian_trixie() {
        let u = parse_apt_simulation(include_str!("../../tests/fixtures/apt-sim.debian-trixie"));
        assert_eq!(
            u,
            Updates {
                pending: 2,
                security: 1
            }
        );
    }

    #[test]
    fn nothing_to_do() {
        assert_eq!(
            parse_apt_simulation("Reading package lists...\n"),
            Updates {
                pending: 0,
                security: 0
            }
        );
    }
}
