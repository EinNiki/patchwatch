//! Merker für die Paketliste: Die volle Liste geht nur an den Server, wenn sich ihr Hash geändert hat.
//!
//! Der Hash der zuletzt vom Server akzeptierten Liste liegt im `StateDirectory`. Ohne beschreibbares Verzeichnis (manueller
//! Aufruf) wird die Liste immer gesendet. Der Hash wird erst nach erfolgreicher Übertragung übernommen (`packages-hash.pending`
//! wird beim Erstellen des Reports angelegt und nach HTTP 2xx zum Merker); sagt der Server, er brauche die Liste neu
//! (zum Beispiel nach einer Datenbank-Wiederherstellung), wird der Merker gelöscht.
use crate::report::Report;
use crate::send::Reply;
use std::path::{Path, PathBuf};

const SAVED: &str = "packages-hash";
const PENDING: &str = "packages-hash.pending";

/// `$STATE_DIRECTORY` (systemd `StateDirectory=`), bei mehreren Verzeichnissen das erste.
pub fn state_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("STATE_DIRECTORY")?;
    let first = dir.to_string_lossy().split(':').next()?.to_owned();
    (!first.is_empty()).then(|| PathBuf::from(first))
}

fn read(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Lässt die volle Liste weg, wenn der Server genau diesen Stand schon hat. Der Hash bleibt im Report.
pub fn gate(dir: Option<&Path>, report: &mut Report) {
    // Ein Rest eines früheren, nicht übertragenen Laufs darf nie als bestätigt gelten.
    if let Some(d) = dir {
        let _ = std::fs::remove_file(d.join(PENDING));
    }
    let (Some(d), Some(hash), Some(_)) = (dir, report.packages_hash.clone(), &report.packages)
    else {
        return;
    };
    if read(d, SAVED).as_deref() == Some(hash.as_str()) {
        report.packages = None;
    } else {
        // Best effort: gelingt das Schreiben nicht, wird die Liste beim nächsten Mal einfach wieder gesendet.
        let _ = std::fs::write(d.join(PENDING), &hash);
    }
}

/// Nach erfolgreicher Übertragung: den Hash übernehmen oder, wenn der Server die Liste neu will, den Merker löschen.
pub fn delivered(dir: Option<&Path>, reply: &Reply) {
    let Some(d) = dir else { return };
    if reply.need_packages {
        let _ = std::fs::remove_file(d.join(SAVED));
        let _ = std::fs::remove_file(d.join(PENDING));
    } else if d.join(PENDING).exists() {
        let _ = std::fs::rename(d.join(PENDING), d.join(SAVED));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::packages::{into_set, Package};
    use crate::report::tests_support::sample_report;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pw-agent-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn with_list(version: &str) -> Report {
        let set = into_set(
            vec![Package {
                name: "bash".into(),
                version: version.into(),
                arch: Some("amd64".into()),
                source: None,
                source_version: None,
            }],
            100,
        );
        let mut r = sample_report();
        r.packages_hash = Some(set.hash);
        r.packages = Some(set.packages);
        r
    }

    #[test]
    fn full_list_only_when_the_hash_changed() {
        let d = dir("pkgstate-change");
        // Erster Lauf: keine Merker, Liste geht mit; erst nach Erfolg gilt der Hash.
        let mut r = with_list("1");
        gate(Some(&d), &mut r);
        assert!(r.packages.is_some());
        assert!(
            read(&d, SAVED).is_none(),
            "vor der Übertragung nicht bestätigt"
        );
        delivered(Some(&d), &Reply::default());
        // Gleicher Stand: nur der Hash.
        let mut again = with_list("1");
        gate(Some(&d), &mut again);
        assert!(again.packages.is_none());
        assert!(again.packages_hash.is_some());
        // Geänderter Stand: wieder volle Liste.
        let mut changed = with_list("2");
        gate(Some(&d), &mut changed);
        assert!(changed.packages.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn failed_delivery_never_marks_the_list_as_known() {
        let d = dir("pkgstate-fail");
        let mut r = with_list("1");
        gate(Some(&d), &mut r);
        // Keine Übertragung (Fehler): `delivered` wird nicht aufgerufen. Der nächste Lauf sendet wieder die Liste.
        let mut next = with_list("1");
        gate(Some(&d), &mut next);
        assert!(next.packages.is_some());
        // Ein verwaister Merker eines Laufs ohne Liste darf nach einem späteren Erfolg nichts bestätigen.
        let mut disabled = sample_report();
        gate(Some(&d), &mut disabled);
        delivered(Some(&d), &Reply::default());
        assert!(read(&d, SAVED).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn server_can_ask_for_the_list_again() {
        let d = dir("pkgstate-need");
        let mut r = with_list("1");
        gate(Some(&d), &mut r);
        delivered(Some(&d), &Reply::default());
        let mut same = with_list("1");
        gate(Some(&d), &mut same);
        assert!(same.packages.is_none());
        // Die Antwort des Servers verlangt die Liste: Merker weg, der nächste Report enthält sie wieder.
        delivered(
            Some(&d),
            &Reply {
                need_packages: true,
            },
        );
        let mut after = with_list("1");
        gate(Some(&d), &mut after);
        assert!(after.packages.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn without_a_state_directory_the_list_is_always_sent() {
        let mut r = with_list("1");
        gate(None, &mut r);
        assert!(r.packages.is_some());
        delivered(None, &Reply::default());
    }
}
