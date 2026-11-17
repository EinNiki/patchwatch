use crate::cmd::Runner;
use crate::collect::{apt_lists, docker, kernel, os_release, packages, proxmox, system, updates};
use crate::config::Config;
use crate::error::AgentError;
use serde::Serialize;
use std::path::Path;

/// 2: Paket-Hash, Architektur, Art der Updates, Alter der Paketlisten. Felder sind optional; ein Server mit Schema 1 und 2 versteht beide.
pub const SCHEMA_VERSION: u32 = 2;

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
    /// Nur gesetzt, wenn `include_packages = true` (und beim Senden nur, wenn sich die Liste geändert hat).
    pub packages: Option<Vec<packages::Package>>,
    /// SHA-256 der Paketliste; der Server erkennt daran, ob er die Liste schon hat.
    pub packages_hash: Option<String>,
    /// Anzahl der installierten Pakete vor dem Abschneiden.
    pub packages_count: Option<u32>,
    /// Die Liste wurde auf `packages::MAX_PACKAGES` gekürzt.
    pub packages_truncated: bool,
    /// Alter der Paketlisten (Unix-Sekunden der jüngsten Liste); `None`, wenn nicht ermittelbar.
    pub apt_lists_updated_unix: Option<u64>,
    /// Nur mit `docker_enabled = true`; sonst fehlt der Block ganz (nicht `null`), der Bericht bleibt dann unverändert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker: Option<docker::DockerReport>,
}

/// Pfade des Systems; austauschbar für Tests.
pub struct Paths<'a> {
    pub os_release: &'a Path,
    pub hostname: &'a Path,
    pub boot: &'a Path,
    pub reboot_required: &'a Path,
    pub uptime: &'a Path,
    pub apt_lists: &'a Path,
}

pub fn system_paths() -> Paths<'static> {
    Paths {
        os_release: Path::new("/etc/os-release"),
        hostname: Path::new("/proc/sys/kernel/hostname"),
        boot: Path::new("/boot"),
        reboot_required: Path::new("/var/run/reboot-required"),
        uptime: Path::new("/proc/uptime"),
        apt_lists: Path::new("/var/lib/apt/lists"),
    }
}

pub fn build(r: &dyn Runner, p: &Paths, cfg: &Config) -> Result<Report, AgentError> {
    // Der Docker-Client entsteht nur bei eingeschaltetem Docker: sonst wird der Socket nie angefasst.
    if cfg.docker_enabled {
        let endpoint = crate::docker_client::Endpoint::parse(&cfg.docker_endpoint)
            .map_err(AgentError::Config)?;
        let client = crate::docker_client::HttpDocker::new(endpoint);
        return build_with(r, p, cfg, Some(&client));
    }
    build_with(r, p, cfg, None)
}

pub fn build_with(
    r: &dyn Runner,
    p: &Paths,
    cfg: &Config,
    docker_api: Option<&dyn crate::docker_client::DockerApi>,
) -> Result<Report, AgentError> {
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

    let set = if cfg.include_packages {
        packages::collect(r)
    } else {
        None
    };
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
        packages_hash: set.as_ref().map(|s| s.hash.clone()),
        packages_count: set.as_ref().map(|s| s.total as u32),
        packages_truncated: set.as_ref().is_some_and(|s| s.truncated),
        packages: set.map(|s| s.packages),
        apt_lists_updated_unix: apt_lists::newest_list_unix(p.apt_lists),
        docker: docker_api.map(docker::collect),
    })
}

/// Hilfen für Tests in anderen Modulen.
#[cfg(test)]
pub mod tests_support {
    use super::*;

    pub fn sample_report() -> Report {
        Report {
            schema_version: SCHEMA_VERSION,
            agent_version: "0.0.0",
            hostname: "h".into(),
            collected_at_unix: 0,
            os: os_release::OsInfo {
                id: "debian".into(),
                version_id: None,
                codename: None,
                pretty_name: None,
            },
            kernel: kernel::KernelInfo {
                running_release: "6.1.0".into(),
                running_package: None,
                newest_installed_release: None,
                newest_installed_package: None,
                reboot_needed_kernel: None,
            },
            reboot_required_file: false,
            updates: None,
            uptime_seconds: None,
            proxmox: None,
            packages: None,
            packages_hash: None,
            packages_count: None,
            packages_truncated: false,
            apt_lists_updated_unix: None,
            docker: None,
        }
    }
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
            apt_lists: &d.join("apt-lists"),
        };
        let cfg = Config::parse("server_url = \"https://x\"\ntoken = \"t\"").unwrap();
        // Paketlisten mit festem Zeitpunkt für das Alter.
        fs::create_dir_all(d.join("apt-lists")).unwrap();
        let list = fs::File::create(d.join("apt-lists/x_dists_trixie_InRelease")).unwrap();
        list.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
            .unwrap();
        let rep = build(&Fake(m.clone()), &paths, &cfg).unwrap();

        assert_eq!(rep.hostname, "pve1");
        assert_eq!(rep.os.codename.as_deref(), Some("trixie"));
        assert_eq!(rep.proxmox.unwrap().version, "9.0.3");
        assert_eq!(rep.uptime_seconds, Some(86400));
        assert!(rep.reboot_required_file);
        assert_eq!(rep.updates.unwrap().security, 1);
        assert_eq!(rep.kernel.reboot_needed_kernel, Some(false));
        assert!(rep.packages.is_none());
        assert!(rep.packages_hash.is_none() && !rep.packages_truncated);
        assert_eq!(rep.schema_version, 2);
        assert_eq!(rep.apt_lists_updated_unix, Some(1_700_000_000));

        // Mit include_packages: Liste, Hash und Anzahl stammen aus derselben Erfassung.
        let key = "dpkg-query ${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\n";
        m.insert(
            key.into(),
            include_str!("../tests/fixtures/dpkg-query.debian-trixie").into(),
        );
        let cfg =
            Config::parse("server_url = \"https://x\"\ntoken = \"t\"\ninclude_packages = true")
                .unwrap();
        let with = build(&Fake(m), &paths, &cfg).unwrap();
        let list = with.packages.as_ref().unwrap();
        assert_eq!(list.len(), 8);
        assert_eq!(with.packages_count, Some(8));
        assert_eq!(with.packages_hash.as_deref().map(str::len), Some(64));
        assert!(list.windows(2).all(|w| w[0].name <= w[1].name), "sortiert");
    }

    /// Docker aus: der Socket wird nie geöffnet (ein Lauscher zählt Verbindungen) und der Bericht hat keinen docker-Block.
    /// Docker an: genau eine Anfrage-Folge, der Block steht im Bericht.
    #[test]
    fn docker_socket_is_touched_only_when_enabled() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let d = std::env::temp_dir().join(format!("pw-agent-{}-dockerrep", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("boot")).unwrap();
        fs::write(
            d.join("os-release"),
            include_str!("../tests/fixtures/os-release.debian-trixie"),
        )
        .unwrap();
        fs::write(d.join("hostname"), "h\n").unwrap();
        fs::write(d.join("uptime"), "1.0 1.0\n").unwrap();
        let sock = d.join("docker.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                let mut s = s.unwrap();
                h2.fetch_add(1, Ordering::SeqCst);
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]");
            }
        });
        let paths = Paths {
            os_release: &d.join("os-release"),
            hostname: &d.join("hostname"),
            boot: &d.join("boot"),
            reboot_required: &d.join("none"),
            uptime: &d.join("uptime"),
            apt_lists: &d.join("none"),
        };
        let mut m = HashMap::new();
        m.insert("uname".into(), "6.12.0\n".into());
        let toml = |on: bool| {
            format!(
                "server_url = \"https://x\"\ntoken = \"t\"\ndocker_enabled = {on}\ndocker_endpoint = \"unix://{}\"",
                sock.display()
            )
        };
        let off = build(
            &Fake(m.clone()),
            &paths,
            &Config::parse(&toml(false)).unwrap(),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "Docker aus: kein Zugriff auf den Socket"
        );
        assert!(off.docker.is_none());
        assert!(!serde_json::to_string(&off).unwrap().contains("docker"));

        let on = build(&Fake(m), &paths, &Config::parse(&toml(true)).unwrap()).unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "nur die Containerliste, keine Images bei leerer Liste"
        );
        let dk = on.docker.unwrap();
        assert_eq!((dk.state, dk.containers.len()), ("ok", 0));
    }
}
