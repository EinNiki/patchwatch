use crate::cmd::Runner;
use crate::collect::{kernel, os_release, packages, proxmox, system, updates};
use crate::config::Config;
use crate::error::AgentError;
use serde::Serialize;
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub agent_version: &'static str,
    pub hostname: String,
    pub collected_at_unix: u64,
    pub os: os_release::OsInfo,
    pub kernel: kernel::KernelInfo,
    pub reboot_required_file: bool,
    pub updates: Option<updates::Updates>,
    pub uptime_seconds: Option<u64>,
    pub proxmox: Option<proxmox::Proxmox>,
    /// Nur gesetzt, wenn `include_packages = true`.
    pub packages: Option<Vec<packages::Package>>,
}

/// Pfade des Systems; austauschbar für Tests.
pub struct Paths<'a> {
    pub os_release: &'a Path,
    pub hostname: &'a Path,
    pub boot: &'a Path,
    pub reboot_required: &'a Path,
    pub uptime: &'a Path,
}

pub fn system_paths() -> Paths<'static> {
    Paths {
        os_release: Path::new("/etc/os-release"),
        hostname: Path::new("/proc/sys/kernel/hostname"),
        boot: Path::new("/boot"),
        reboot_required: Path::new("/var/run/reboot-required"),
        uptime: Path::new("/proc/uptime"),
    }
}

pub fn build(r: &dyn Runner, p: &Paths, cfg: &Config) -> Result<Report, AgentError> {
    let read = |path: &Path| {
        std::fs::read_to_string(path)
            .map_err(|e| AgentError::Collect(format!("{} nicht lesbar: {e}", path.display())))
    };
    let os = os_release::parse(&read(p.os_release)?)
        .ok_or_else(|| AgentError::Collect("ID fehlt in os-release".into()))?;
    let hostname = read(p.hostname)?.trim().to_owned();
    if hostname.is_empty() {
        return Err(AgentError::Collect("Hostname ist leer".into()));
    }
    let release = r
        .run("uname", &["-r"])
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AgentError::Collect("uname -r fehlgeschlagen".into()))?;
    let collected_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    Ok(Report {
        schema_version: SCHEMA_VERSION,
        agent_version: env!("CARGO_PKG_VERSION"),
        hostname,
        collected_at_unix,
        os,
        kernel: kernel::collect(r, p.boot, &release),
        reboot_required_file: system::reboot_required_file(p.reboot_required),
        updates: updates::collect(r),
        uptime_seconds: std::fs::read_to_string(p.uptime)
            .ok()
            .and_then(|t| system::parse_uptime(&t)),
        proxmox: proxmox::collect(r),
        packages: if cfg.include_packages {
            packages::collect(r)
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    struct Fake(HashMap<String, String>);
    impl Runner for Fake {
        fn run(&self, prog: &str, args: &[&str]) -> Option<String> {
            let key = match prog {
                "uname" | "pveversion" | "apt-get" => prog.to_owned(),
                _ => format!("{prog} {}", args.last()?),
            };
            self.0.get(&key).cloned()
        }
    }

    /// Proxmox 9 End-to-End mit gefälschten Kommandos und Fixture-Dateien.
    #[test]
    fn proxmox_9_report() {
        let d = std::env::temp_dir().join(format!("pw-agent-{}-report", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("boot")).unwrap();
        fs::write(d.join("boot/vmlinuz-6.14.11-2-pve"), b"").unwrap();
        fs::write(
            d.join("os-release"),
            include_str!("../tests/fixtures/os-release.proxmox-9"),
        )
        .unwrap();
        fs::write(d.join("hostname"), "pve1\n").unwrap();
        fs::write(d.join("uptime"), "86400.5 100.0\n").unwrap();
        fs::write(d.join("reboot-required"), "").unwrap();

        let boot = d.join("boot");
        let mut m = HashMap::new();
        m.insert("uname".into(), "6.14.11-2-pve\n".into());
        m.insert(
            "pveversion".into(),
            include_str!("../tests/fixtures/pveversion.proxmox-9").into(),
        );
        m.insert(
            "apt-get".into(),
            include_str!("../tests/fixtures/apt-sim.debian-trixie").into(),
        );
        m.insert(
            format!("dpkg {}/vmlinuz-6.14.11-2-pve", boot.display()),
            format!(
                "proxmox-kernel-6.14.11-2-pve-signed: {}/vmlinuz-6.14.11-2-pve\n",
                boot.display()
            ),
        );
        m.insert(
            "dpkg-query proxmox-kernel-6.14.11-2-pve-signed".into(),
            "6.14.11-2\tproxmox-kernel-6.14\t6.14.11-2\n".into(),
        );
        let paths = Paths {
            os_release: &d.join("os-release"),
            hostname: &d.join("hostname"),
            boot: &boot,
            reboot_required: &d.join("reboot-required"),
            uptime: &d.join("uptime"),
        };
        let cfg = Config::parse("server_url = \"https://x\"\ntoken = \"t\"").unwrap();
        let rep = build(&Fake(m), &paths, &cfg).unwrap();

        assert_eq!(rep.hostname, "pve1");
        assert_eq!(rep.os.codename.as_deref(), Some("trixie"));
        assert_eq!(rep.proxmox.unwrap().version, "9.0.3");
        assert_eq!(rep.uptime_seconds, Some(86400));
        assert!(rep.reboot_required_file);
        assert_eq!(rep.updates.unwrap().security, 1);
        assert_eq!(rep.kernel.reboot_needed_kernel, Some(false));
        assert!(rep.packages.is_none());
    }
}
