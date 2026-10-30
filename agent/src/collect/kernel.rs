use crate::cmd::Runner;
use debversion::Version;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PkgInfo {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub source_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KernelInfo {
    /// Ausgabe von `uname -r`.
    pub running_release: String,
    pub running_package: Option<PkgInfo>,
    pub newest_installed_release: Option<String>,
    pub newest_installed_package: Option<PkgInfo>,
    /// `None`, wenn sich das nicht sicher bestimmen lässt.
    pub reboot_needed_kernel: Option<bool>,
}

/// `dpkg -S`-Ausgabe: "paket[:arch]: /pfad". Diversions-Zeilen werden ignoriert.
pub fn parse_dpkg_s(out: &str) -> Option<String> {
    out.lines()
        .filter(|l| !l.starts_with("diversion"))
        .find_map(|l| {
            let (pkgs, _) = l.split_once(": /")?;
            let first = pkgs.split(", ").next()?;
            let name = first.split(':').next()?.trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
}

/// Zeile aus `dpkg-query -W -f '${Version}\t${source:Package}\t${source:Version}\n'`.
pub fn parse_pkg_info(name: &str, out: &str) -> Option<PkgInfo> {
    let line = out.lines().next()?;
    let mut it = line.split('\t');
    let version = it.next().filter(|v| !v.is_empty())?.to_owned();
    let opt = |s: Option<&str>| s.filter(|v| !v.is_empty()).map(str::to_owned);
    Some(PkgInfo {
        name: name.to_owned(),
        version,
        source: opt(it.next()),
        source_version: opt(it.next()),
    })
}

/// Variante (Flavour) eines Kernel-Releases: "6.8.0-31-generic" -> "generic", "6.14.11-2-pve" -> "pve".
pub fn flavor(release: &str) -> &str {
    match release.rsplit_once('-') {
        Some((_, tail)) if !tail.chars().all(|c| c.is_ascii_digit()) => tail,
        _ => "",
    }
}

fn query(r: &dyn Runner, name: &str) -> Option<PkgInfo> {
    let out = r.run(
        "dpkg-query",
        &[
            "-W",
            "-f",
            "${Version}\t${source:Package}\t${source:Version}\n",
            name,
        ],
    )?;
    parse_pkg_info(name, &out)
}

/// Löst das Paket zu einem Kernel-Release auf: erst `dpkg -S`, nur als Fallback `linux-image-`.
fn package_for_release(r: &dyn Runner, boot: &Path, release: &str) -> Option<PkgInfo> {
    let image = boot.join(format!("vmlinuz-{release}"));
    let by_file = r
        .run("dpkg", &["-S", &image.to_string_lossy()])
        .and_then(|o| parse_dpkg_s(&o))
        .and_then(|n| query(r, &n));
    by_file.or_else(|| query(r, &format!("linux-image-{release}")))
}

pub fn collect(r: &dyn Runner, boot: &Path, running_release: &str) -> KernelInfo {
    let running_package = package_for_release(r, boot, running_release);
    let want_flavor = flavor(running_release);

    let mut newest: Option<(Version, String, PkgInfo)> = None;
    let mut releases: Vec<String> = std::fs::read_dir(boot)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()?
                .strip_prefix("vmlinuz-")
                .map(str::to_owned)
        })
        .filter(|rel| flavor(rel) == want_flavor)
        .collect();
    if !releases.iter().any(|x| x == running_release) {
        releases.push(running_release.to_owned());
    }
    for rel in releases {
        let pkg = if rel == running_release {
            running_package.clone()
        } else {
            package_for_release(r, boot, &rel)
        };
        let Some(pkg) = pkg else { continue };
        let Ok(v) = pkg.version.parse::<Version>() else {
            continue;
        };
        if newest.as_ref().is_none_or(|(best, _, _)| v > *best) {
            newest = Some((v, rel, pkg));
        }
    }

    let running_version = running_package
        .as_ref()
        .and_then(|p| p.version.parse::<Version>().ok());
    let reboot_needed_kernel = match (&running_version, &newest) {
        (Some(run), Some((best, _, _))) => Some(best > run),
        _ => None,
    };
    let (newest_installed_release, newest_installed_package) = match newest {
        Some((_, rel, pkg)) => (Some(rel), Some(pkg)),
        None => (None, None),
    };
    KernelInfo {
        running_release: running_release.to_owned(),
        running_package,
        newest_installed_release,
        newest_installed_package,
        reboot_needed_kernel,
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
            self.0.get(&format!("{prog} {}", args.last()?)).cloned()
        }
    }

    fn boot_dir(name: &str, files: &[&str]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pw-agent-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        for f in files {
            fs::write(d.join(f), b"").unwrap();
        }
        d
    }

    #[test]
    fn dpkg_s_variants() {
        assert_eq!(
            parse_dpkg_s("linux-image-6.8.0-31-generic: /boot/vmlinuz-6.8.0-31-generic\n")
                .as_deref(),
            Some("linux-image-6.8.0-31-generic")
        );
        assert_eq!(
            parse_dpkg_s("proxmox-kernel-6.14.11-2-pve-signed: /boot/vmlinuz-6.14.11-2-pve\n")
                .as_deref(),
            Some("proxmox-kernel-6.14.11-2-pve-signed")
        );
        assert_eq!(
            parse_dpkg_s("diversion by x from: /boot/vmlinuz\nlinux-image-amd64:amd64: /boot/vmlinuz-6.12.48+deb13-amd64\n")
                .as_deref(),
            Some("linux-image-amd64")
        );
        assert_eq!(
            parse_dpkg_s("dpkg-query: no path found matching pattern /boot/x\n"),
            None
        );
    }

    #[test]
    fn flavors() {
        assert_eq!(flavor("6.8.0-31-generic"), "generic");
        assert_eq!(flavor("6.14.11-2-pve"), "pve");
        assert_eq!(flavor("6.12.48+deb13-amd64"), "amd64");
        assert_eq!(flavor("6.8.0-31"), "");
    }

    /// Proxmox 9: Paket heißt proxmox-kernel-...-pve-signed, laufender Kernel ist älter.
    #[test]
    fn proxmox_reboot_needed() {
        let boot = boot_dir(
            "pve",
            &[
                "vmlinuz-6.14.11-2-pve",
                "vmlinuz-6.14.11-4-pve",
                "vmlinuz-6.8.12-1-pve",
            ],
        );
        let b = boot.to_string_lossy();
        let mut m = HashMap::new();
        for (rel, pkg, ver) in [
            (
                "6.14.11-2-pve",
                "proxmox-kernel-6.14.11-2-pve-signed",
                "6.14.11-2",
            ),
            (
                "6.14.11-4-pve",
                "proxmox-kernel-6.14.11-4-pve-signed",
                "6.14.11-4",
            ),
        ] {
            m.insert(
                format!("dpkg {b}/vmlinuz-{rel}"),
                format!("{pkg}: {b}/vmlinuz-{rel}\n"),
            );
            m.insert(
                format!("dpkg-query {pkg}"),
                format!("{ver}\tproxmox-kernel-6.14\t{ver}\n"),
            );
        }
        let k = collect(&Fake(m), &boot, "6.14.11-2-pve");
        assert_eq!(
            k.running_package.unwrap().name,
            "proxmox-kernel-6.14.11-2-pve-signed"
        );
        assert_eq!(k.newest_installed_release.as_deref(), Some("6.14.11-4-pve"));
        assert_eq!(k.reboot_needed_kernel, Some(true));
    }

    /// Ubuntu 24.04: Fallback auf linux-image-<release>, wenn dpkg -S nichts liefert.
    #[test]
    fn ubuntu_fallback_and_up_to_date() {
        let boot = boot_dir("ubuntu", &["vmlinuz-6.8.0-31-generic"]);
        let mut m = HashMap::new();
        m.insert(
            "dpkg-query linux-image-6.8.0-31-generic".into(),
            "6.8.0-31.31\tlinux-signed\t6.8.0-31.31\n".into(),
        );
        let k = collect(&Fake(m), &boot, "6.8.0-31-generic");
        assert_eq!(
            k.running_package.unwrap().source.as_deref(),
            Some("linux-signed")
        );
        assert_eq!(k.reboot_needed_kernel, Some(false));
    }

    #[test]
    fn unknown_when_package_unresolvable() {
        let boot = boot_dir("none", &["vmlinuz-6.1.0-1-amd64"]);
        let k = collect(&Fake(HashMap::new()), &boot, "6.1.0-1-amd64");
        assert!(k.running_package.is_none());
        assert_eq!(k.reboot_needed_kernel, None);
    }
}
