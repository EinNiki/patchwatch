use std::path::Path;
use std::time::UNIX_EPOCH;

/// Zeitpunkt (Unix-Sekunden) der jüngsten Paketliste unter `dir` (`/var/lib/apt/lists`). Nur Metadaten werden gelesen,
/// nichts wird aktualisiert und `apt update` nie aufgerufen. `None`, wenn das Verzeichnis fehlt oder keine Liste enthält.
pub fn newest_list_unix(dir: &Path) -> Option<u64> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.contains("_Packages") || n.ends_with("_InRelease") || n.ends_with("_Release")
        })
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .filter_map(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::time::{Duration, SystemTime};

    fn touch(dir: &Path, name: &str, secs: u64) {
        let f = File::create(dir.join(name)).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn newest_package_list_wins_and_other_files_are_ignored() {
        let d = std::env::temp_dir().join(format!("pw-agent-{}-aptlists", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        touch(&d, "deb.debian.org_debian_dists_trixie_InRelease", 1_000);
        touch(
            &d,
            "deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages.lz4",
            2_000,
        );
        // Sperrdatei und Teilladung zählen nicht, auch wenn sie neuer sind.
        touch(&d, "lock", 9_000);
        touch(&d, "auxfiles", 9_500);
        assert_eq!(newest_list_unix(&d), Some(2_000));
        assert_eq!(newest_list_unix(&d.join("fehlt")), None);
        let _ = fs::remove_dir_all(&d);
    }
}
