use crate::cmd::Runner;
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Proxmox {
    pub version: String,
}

/// "pve-manager/9.0.3/025864202ebb6109 (running kernel: ...)" -> "9.0.3"
pub fn parse_pveversion(out: &str) -> Option<Proxmox> {
    let rest = out.lines().next()?.strip_prefix("pve-manager/")?;
    let version = rest.split(['/', ' ']).next().filter(|v| !v.is_empty())?;
    Some(Proxmox {
        version: version.to_owned(),
    })
}

/// `None`, wenn `pveversion` fehlt (kein Proxmox).
pub fn collect(r: &dyn Runner) -> Option<Proxmox> {
    parse_pveversion(&r.run("pveversion", &[])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxmox_9() {
        let p =
            parse_pveversion(include_str!("../../tests/fixtures/pveversion.proxmox-9")).unwrap();
        assert_eq!(p.version, "9.0.3");
    }

    #[test]
    fn not_proxmox() {
        assert!(parse_pveversion("garbage").is_none());
    }
}
