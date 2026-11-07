//! Token des Agents: Prüfung, atomares Schreiben, Eingabewege, Migration aus `agent.toml`, Fingerabdruck.
//!
//! Grundsatz: Der Token wird nie ausgegeben (weder stdout noch stderr noch Journal) und nie als Kommandozeilen-Argument
//! angenommen. Fehlermeldungen nennen nie Teile des Tokens.
use crate::error::AgentError;
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DEFAULT_TOKEN_PATH: &str = "/etc/patchwatch/token";
/// Der Server erzeugt `pw_` + 43 Zeichen Base64-URL; großzügige Grenzen, damit ältere Tokens weiter gehen.
const PREFIX: &str = "pw_";
const MIN_LEN: usize = 16;
const MAX_LEN: usize = 128;

fn cfg_err(m: &str) -> AgentError {
    AgentError::Config(m.into())
}

/// Prüft das Format: `pw_` und Zeichen aus `A-Za-z0-9_-`, keine Leer- oder Steuerzeichen, Länge begrenzt.
/// Die Meldungen enthalten nie den Wert.
pub fn validate(token: &str) -> Result<(), AgentError> {
    if token.is_empty() {
        return Err(cfg_err("Token ist leer"));
    }
    if token.len() > MAX_LEN {
        return Err(cfg_err("Token ist zu lang"));
    }
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(cfg_err("Token enthält Leerzeichen oder Zeilenumbrüche"));
    }
    if token.len() < MIN_LEN || !token.starts_with(PREFIX) {
        return Err(cfg_err(
            "Token hat nicht das Format eines patchwatch-Tokens (pw_…)",
        ));
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(cfg_err(
            "Token enthält unzulässige Zeichen (erlaubt: A-Z a-z 0-9 _ -)",
        ));
    }
    Ok(())
}

/// Eingabe lesen (höchstens `MAX_LEN + 2` Bytes) und genau einen abschließenden Zeilenumbruch entfernen.
pub fn read_limited(mut src: impl Read) -> Result<String, AgentError> {
    let mut buf = Vec::new();
    src.by_ref()
        .take(MAX_LEN as u64 + 2)
        .read_to_end(&mut buf)
        .map_err(|_| cfg_err("Eingabe nicht lesbar"))?;
    let mut s = String::from_utf8(buf).map_err(|_| cfg_err("Eingabe ist kein gültiger Text"))?;
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    Ok(s)
}

/// Schaltet das Echo des Terminals ab und beim Verlassen wieder an (ohne neue Abhängigkeit über `stty`).
struct NoEcho;
impl NoEcho {
    fn new() -> Result<Self, AgentError> {
        let ok = std::process::Command::new("stty")
            .arg("-echo")
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            Ok(Self)
        } else {
            Err(cfg_err(
                "Das Echo des Terminals lässt sich nicht abschalten. Bitte --stdin oder --token-file verwenden",
            ))
        }
    }
}
impl Drop for NoEcho {
    fn drop(&mut self) {
        let _ = std::process::Command::new("stty").arg("echo").status();
        eprintln!();
    }
}

/// Interaktive Abfrage ohne Echo (nur an einem Terminal).
pub fn prompt() -> Result<String, AgentError> {
    if !std::io::stdin().is_terminal() {
        return Err(cfg_err(
            "Keine interaktive Eingabe möglich. Token per --stdin oder --token-file übergeben",
        ));
    }
    eprint!("Token (Eingabe bleibt unsichtbar): ");
    let _ = std::io::stderr().flush();
    let _guard = NoEcho::new()?;
    read_limited(std::io::stdin().lock())
}

/// Token aus einer Datei (für `--token-file`): nur normale Dateien, kein Symlink.
pub fn read_file(path: &Path) -> Result<String, AgentError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        AgentError::Config(format!("{} nicht lesbar: {}", path.display(), e.kind()))
    })?;
    if !meta.is_file() {
        return Err(cfg_err(
            "--token-file muss eine normale Datei sein (kein Link, kein Verzeichnis)",
        ));
    }
    if meta.len() > MAX_LEN as u64 + 2 {
        return Err(cfg_err("Token ist zu lang"));
    }
    let f = File::open(path).map_err(|e| {
        AgentError::Config(format!("{} nicht lesbar: {}", path.display(), e.kind()))
    })?;
    read_limited(f)
}

/// Effektive Benutzer-ID (aus /proc/self/status, ohne libc).
pub fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|r| r.split_whitespace().nth(1).map(str::to_owned))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(u32::MAX)
}

/// Prüft Ziel und Ordner vor dem Schreiben. Gibt Warnungen zurück (z. B. zu weite Rechte der alten Datei, werden beim
/// Ersetzen behoben); Fehler bei Symlinks, fremdem Besitzer und beschreibbarem Ordner.
pub fn check_target(target: &Path, euid: u32) -> Result<Vec<String>, AgentError> {
    let mut warn = Vec::new();
    let dir = target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dm = std::fs::metadata(dir).map_err(|e| {
        AgentError::Config(format!(
            "Ordner {} nicht lesbar: {}",
            dir.display(),
            e.kind()
        ))
    })?;
    if !dm.is_dir() {
        return Err(cfg_err("Zielordner ist kein Verzeichnis"));
    }
    if dm.mode() & 0o002 != 0 {
        return Err(AgentError::Config(format!(
            "Ordner {} ist für alle beschreibbar; Abbruch",
            dir.display()
        )));
    }
    if dm.uid() != euid && dm.uid() != 0 {
        return Err(AgentError::Config(format!(
            "Ordner {} gehört einem anderen Benutzer",
            dir.display()
        )));
    }
    match std::fs::symlink_metadata(target) {
        Ok(m) => {
            if m.file_type().is_symlink() {
                return Err(cfg_err("Die Token-Datei ist ein Symlink; aus Sicherheitsgründen wird sie nicht überschrieben"));
            }
            if !m.is_file() {
                return Err(cfg_err("Die Token-Datei ist keine normale Datei"));
            }
            if m.uid() != euid && m.uid() != 0 {
                return Err(cfg_err(
                    "Die Token-Datei gehört einem anderen Benutzer; als root ausführen (sudo)",
                ));
            }
            if m.mode() & 0o077 != 0 {
                warn.push(format!(
                    "Die bisherige Token-Datei hatte Modus {:04o}; die neue bekommt 0600.",
                    m.mode() & 0o7777
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(AgentError::Config(format!(
                "{} nicht prüfbar: {}",
                target.display(),
                e.kind()
            )))
        }
    }
    Ok(warn)
}

/// Atomar schreiben: temporäre Datei im selben Ordner (0600, `create_new`), fsync, rename, fsync des Ordners.
/// `chown_root`: Besitzer root:root (nur sinnvoll als root).
pub fn write_atomic(target: &Path, content: &str, chown_root: bool) -> Result<(), AgentError> {
    let mut data = content.as_bytes().to_vec();
    data.push(b'\n');
    write_inner(target, &data, 0o600, chown_root.then_some((0, 0)))
}

fn write_inner(
    target: &Path,
    data: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<(), AgentError> {
    let dir = target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| cfg_err("ungültiger Zielpfad"))?;
    let tmp = dir.join(format!(".{name}.tmp{}", std::process::id()));
    let io = |what: &str, e: std::io::Error| AgentError::Config(format!("{what}: {}", e.kind()));
    let result = (|| -> Result<(), AgentError> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| io("temporäre Datei nicht anlegbar", e))?;
        f.write_all(data)
            .map_err(|e| io("Schreiben fehlgeschlagen", e))?;
        f.sync_all().map_err(|e| io("fsync fehlgeschlagen", e))?;
        // Die Umask darf den Modus nie lockern (oder verengen): ausdrücklich setzen.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| io("chmod fehlgeschlagen", e))?;
        if let Some((u, g)) = owner {
            std::os::unix::fs::chown(&tmp, Some(u), Some(g))
                .map_err(|e| io("chown fehlgeschlagen", e))?;
        }
        std::fs::rename(&tmp, target).map_err(|e| io("Umbenennen fehlgeschlagen", e))?;
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| io("fsync des Ordners fehlgeschlagen", e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Wie `write_atomic`, für beliebigen Text (Sicherungskopie), Modus 0600.
pub fn write_atomic_text(target: &Path, text: &str) -> Result<(), AgentError> {
    write_inner(target, text.as_bytes(), 0o600, None)
}

/// Konfiguration ersetzen und dabei Modus und Besitzer der alten Datei behalten (Besitzer nur als root setzbar).
pub fn write_atomic_text_like(
    target: &Path,
    text: &str,
    mode: u32,
    owner: (u32, u32),
    chown: bool,
) -> Result<(), AgentError> {
    write_inner(target, text.as_bytes(), mode, chown.then_some(owner))
}

/// Token aus der Konfiguration entfernen und `token_file` setzen (zeilenweise; Kommentare bleiben). Gibt `None`
/// zurück, wenn kein `token = …` im Text steht. Zweiter Wert: die Sicherungskopie (gleicher Text, ohne Token).
pub fn migrate_config_text(text: &str, token_file: &Path) -> Option<(String, String)> {
    let is_token = |l: &str| {
        let t = l.trim_start();
        t.strip_prefix("token").is_some_and(|r| {
            r.trim_start().starts_with('=')
                && !r.starts_with(|c: char| c.is_alphanumeric() || c == '_')
        })
    };
    if !text.lines().any(is_token) {
        return None;
    }
    let has_file = text.lines().any(|l| {
        let t = l.trim_start();
        t.strip_prefix("token_file")
            .is_some_and(|r| r.trim_start().starts_with('='))
    });
    let kept: Vec<&str> = text.lines().filter(|l| !is_token(l)).collect();
    let mut backup = kept.join("\n");
    backup.push('\n');
    let mut new = kept.clone();
    let line;
    if !has_file {
        line = format!("token_file = \"{}\"", token_file.display());
        let at = new
            .iter()
            .position(|l| l.trim_start().starts_with("server_url"))
            .map_or(0, |i| i + 1);
        new.insert(at, &line);
    }
    let mut out = new.join("\n");
    out.push('\n');
    Some((out, backup))
}

/// SHA-256 (FIPS 180-4), nur für den Fingerabdruck; kleine, geprüfte Eigenimplementierung statt neuer Abhängigkeit.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Fingerabdruck: die ersten 8 Hex-Zeichen von SHA-256 (nie Teile des Tokens).
pub fn fingerprint(token: &str) -> String {
    sha256(token.as_bytes())
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn default_target(token_file: Option<&PathBuf>) -> PathBuf {
    token_file
        .cloned()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_TOKEN_PATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "pw_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pw-agent-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn sha256_known_vectors() {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(fingerprint("abc"), "ba7816bf");
    }

    #[test]
    fn validate_accepts_server_tokens_and_rejects_everything_else() {
        assert!(validate(GOOD).is_ok());
        assert!(validate("pw_cve-test-token-0123456789abcdef0123456789").is_ok());
        for bad in [
            "",
            "pw_ kurz",
            "pw_with space_0123456789abcdef",
            "pw_zeile\nzwei_0123456789ab",
            "pw_tab\t_0123456789abcdef",
            "abc_0123456789abcdefghijkl",
            "pw_umlautä_0123456789abcdef",
            "pw_$(rm)_0123456789abcdef",
            "pw_short",
        ] {
            let e = validate(bad).unwrap_err().to_string();
            assert!(
                !e.contains(bad.trim()) || bad.trim().is_empty(),
                "Fehlermeldung nennt den Wert: {e}"
            );
        }
        assert!(
            validate(&format!("pw_{}", "a".repeat(200))).is_err(),
            "zu lang"
        );
        assert!(
            validate(&format!("pw_{}", "a".repeat(125))).is_ok(),
            "genau 128 Zeichen"
        );
        assert!(validate(&format!("pw_{}", "a".repeat(126))).is_err());
    }

    #[test]
    fn input_is_limited_and_one_trailing_newline_is_removed() {
        assert_eq!(read_limited(&b"pw_x\n"[..]).unwrap(), "pw_x");
        assert_eq!(read_limited(&b"pw_x\r\n"[..]).unwrap(), "pw_x");
        assert_eq!(
            read_limited(&b"pw_x\n\n"[..]).unwrap(),
            "pw_x\n",
            "zweiter Umbruch bleibt und wird später abgelehnt"
        );
        let big = vec![b'a'; 100_000];
        let s = read_limited(&big[..]).unwrap();
        assert!(s.len() <= MAX_LEN + 2 && validate(&s).is_err());
        assert!(read_limited(&[0xff, 0xfe][..]).is_err());
    }

    #[test]
    fn write_is_atomic_0600_and_replaces_without_leftovers() {
        let d = tmpdir("write");
        let t = d.join("token");
        std::fs::write(&t, "alt\n").unwrap();
        std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o644)).unwrap();
        let warn = check_target(&t, effective_uid()).unwrap();
        assert_eq!(warn.len(), 1, "alte Rechte 0644 werden gemeldet");
        write_atomic(&t, GOOD, false).unwrap();
        assert_eq!(std::fs::read_to_string(&t).unwrap(), format!("{GOOD}\n"));
        assert_eq!(std::fs::metadata(&t).unwrap().mode() & 0o7777, 0o600);
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "keine temporären Reste: {names:?}");
    }

    #[test]
    fn umask_never_loosens_the_mode() {
        let d = tmpdir("umask");
        let t = d.join("token");
        write_atomic(&t, GOOD, false).unwrap();
        assert_eq!(std::fs::metadata(&t).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn symlink_and_foreign_targets_are_refused() {
        let d = tmpdir("symlink");
        let real = d.join("real");
        std::fs::write(&real, "x").unwrap();
        let link = d.join("token");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(check_target(&link, effective_uid()).is_err());
        assert!(
            check_target(&d.join("token2"), effective_uid()).is_ok(),
            "neue Datei ist in Ordnung"
        );
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            check_target(&d.join("neu"), effective_uid()).is_err(),
            "für alle beschreibbarer Ordner"
        );
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn failed_write_leaves_no_temp_file() {
        let d = tmpdir("fail");
        let t = d.join("sub").join("token");
        assert!(write_atomic(&t, GOOD, false).is_err());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
    }

    #[test]
    fn migration_moves_token_out_of_the_config_and_keeps_the_rest() {
        let text = "# Kommentar\nserver_url = \"https://pw.example\"\ntoken = \"pw_geheim\"\ninclude_packages = true\n";
        let (new, backup) = migrate_config_text(text, Path::new("/etc/patchwatch/token")).unwrap();
        assert!(!new.contains("pw_geheim") && !backup.contains("pw_geheim"));
        assert!(
            new.contains("token_file = \"/etc/patchwatch/token\"")
                && new.contains("include_packages = true")
                && new.contains("# Kommentar")
        );
        assert!(
            !backup.contains("token_file"),
            "Sicherung ist der alte Text ohne Token"
        );
        assert!(crate::config::Config::parse(&new).is_ok());
        // token_file schon vorhanden: nur den Eintrag entfernen
        let (n2, _) = migrate_config_text(
            "server_url = \"https://x\"\ntoken_file = \"/a\"\ntoken = \"pw_geheim\"\n",
            Path::new("/b"),
        )
        .unwrap();
        assert_eq!(n2.matches("token_file").count(), 1);
        assert!(migrate_config_text(
            "server_url = \"https://x\"\ntoken_file = \"/a\"\n",
            Path::new("/b")
        )
        .is_none());
    }
}
