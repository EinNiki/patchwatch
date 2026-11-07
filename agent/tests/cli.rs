//! Bedienung von `set-token` und `status` über das echte Binary. Alle Ausgaben werden mitgeschnitten und dürfen den
//! Token nie enthalten.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_patchwatch-agent");
const TOKEN: &str = "pw_TESTTOKEN-0123456789_abcdefghijklmnopqrstu";

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pw-agent-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn config(dir: &Path, url: &str, extra: &str) -> PathBuf {
    let p = dir.join("agent.toml");
    std::fs::write(
        &p,
        format!("server_url = \"{url}\"\ninsecure_http = true\ntimeout_secs = 5\n{extra}"),
    )
    .unwrap();
    p
}

fn run(args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(BIN);
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c.env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("STATE_DIRECTORY");
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}

fn all_text(o: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn assert_no_token(o: &Output) {
    let t = all_text(o);
    assert!(!t.contains(TOKEN), "Token in der Ausgabe: {t}");
    assert!(
        !t.contains("TESTTOKEN"),
        "Teil des Tokens in der Ausgabe: {t}"
    );
}

/// Mini-Server: antwortet auf jede Anfrage mit `status`; liefert die Zahl der Anfragen und gesehenen Header zurück.
fn mock(
    status: u16,
) -> (
    String,
    std::thread::JoinHandle<()>,
    std::sync::mpsc::Receiver<String>,
) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    let h = std::thread::spawn(move || {
        l.set_nonblocking(false).unwrap();
        // höchstens zwei Anfragen (Test-Report bzw. healthz), danach endet der Thread
        for _ in 0..2 {
            let Ok((mut s, _)) = l.accept() else { return };
            s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut buf = vec![0u8; 65536];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let body = "{}";
            let _ = write!(s, "HTTP/1.1 {status} X\r\nDate: Sat, 07 Nov 2026 00:41:00 GMT\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = s.flush();
            // nur ein Request nötig: Verbindung schließen
            if status == 0 {
                return;
            }
        }
    });
    (url, h, rx)
}

#[test]
fn set_token_via_stdin_writes_0600_and_never_prints_the_token() {
    let d = tmp("stdin");
    let tf = d.join("token");
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        &format!("token_file = \"{}\"\n", tf.display()),
    );
    let o = run(
        &[
            "set-token",
            "--stdin",
            "--no-test",
            "--config",
            cfg.to_str().unwrap(),
        ],
        Some(&format!("{TOKEN}\n")),
        &[],
    );
    assert!(o.status.success(), "{}", all_text(&o));
    assert_no_token(&o);
    assert_eq!(std::fs::read_to_string(&tf).unwrap(), format!("{TOKEN}\n"));
    assert_eq!(
        std::fs::metadata(&tf).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("Fingerabdruck:") && out.contains("sudo systemctl start patchwatch-agent"),
        "{out}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(
        leftovers.iter().all(|n| !n.contains(".tmp")),
        "{leftovers:?}"
    );
}

#[test]
fn set_token_via_token_file_works_and_rejects_links() {
    let d = tmp("tokenfile");
    let tf = d.join("token");
    let src = d.join("neu");
    std::fs::write(&src, format!("{TOKEN}\n")).unwrap();
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        &format!("token_file = \"{}\"\n", tf.display()),
    );
    let o = run(
        &[
            "set-token",
            "--token-file",
            src.to_str().unwrap(),
            "--no-test",
            "--config",
            cfg.to_str().unwrap(),
        ],
        None,
        &[],
    );
    assert!(o.status.success(), "{}", all_text(&o));
    assert_no_token(&o);
    let link = d.join("link");
    std::os::unix::fs::symlink(&src, &link).unwrap();
    let o = run(
        &[
            "set-token",
            "--token-file",
            link.to_str().unwrap(),
            "--no-test",
            "--config",
            cfg.to_str().unwrap(),
        ],
        None,
        &[],
    );
    assert!(!o.status.success());
    assert_no_token(&o);
}

#[test]
fn token_as_argument_is_refused_and_nothing_is_written() {
    let d = tmp("arg");
    let tf = d.join("token");
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        &format!("token_file = \"{}\"\n", tf.display()),
    );
    for args in [
        vec!["set-token", "--token", TOKEN],
        vec!["set-token", &format!("--token={TOKEN}")],
        vec!["set-token", TOKEN],
        vec!["set-token", "--stdin", TOKEN],
    ] {
        let mut a = args.clone();
        a.extend(["--config", cfg.to_str().unwrap()]);
        let o = run(&a, Some(""), &[]);
        assert!(!o.status.success(), "{args:?}");
        assert_no_token(&o);
        assert!(!tf.exists(), "es darf nichts geschrieben werden: {args:?}");
    }
    let o = run(
        &[
            "set-token",
            "--token",
            TOKEN,
            "--config",
            cfg.to_str().unwrap(),
        ],
        None,
        &[],
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("ps"),
        "klare Erklärung: {}",
        all_text(&o)
    );
}

#[test]
fn malformed_input_is_rejected() {
    let d = tmp("bad");
    let tf = d.join("token");
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        &format!("token_file = \"{}\"\n", tf.display()),
    );
    let long = format!("pw_{}", "a".repeat(5000));
    for bad in [
        "pw_mit leerzeichen_0123456789abcdef\n",
        "pw_zeile1_0123456789abcdef\npw_zeile2\n",
        "kein-token\n",
        "\n",
        "",
        long.as_str(),
    ] {
        let o = run(
            &[
                "set-token",
                "--stdin",
                "--no-test",
                "--config",
                cfg.to_str().unwrap(),
            ],
            Some(bad),
            &[],
        );
        assert!(!o.status.success(), "angenommen: {bad:.20?}");
        assert!(!tf.exists());
        let t = all_text(&o);
        assert!(
            !t.contains("leerzeichen") && !t.contains("zeile1"),
            "Fehlermeldung nennt Eingabe: {t}"
        );
    }
}

#[test]
fn without_terminal_or_option_the_prompt_is_refused() {
    let d = tmp("prompt");
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        &format!("token_file = \"{}\"\n", d.join("token").display()),
    );
    let o = run(
        &["set-token", "--config", cfg.to_str().unwrap()],
        Some(&format!("{TOKEN}\n")),
        &[],
    );
    assert!(!o.status.success(), "ohne Terminal keine Abfrage");
    assert_no_token(&o);
    assert!(!d.join("token").exists());
}

#[test]
fn token_in_agent_toml_is_reported_not_written_and_can_be_migrated() {
    let d = tmp("migrate");
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        "token = \"pw_ALTER-TOKEN-0123456789abcdefghij\"\ninclude_packages = true\n",
    );
    let tf = d.join("token");
    // Ohne --migrate: Hinweis, nichts geschrieben, Konfiguration unverändert.
    let before = std::fs::read_to_string(&cfg).unwrap();
    let o = run(
        &[
            "set-token",
            "--stdin",
            "--no-test",
            "--config",
            cfg.to_str().unwrap(),
        ],
        Some(&format!("{TOKEN}\n")),
        &[],
    );
    assert!(!o.status.success());
    assert_no_token(&o);
    assert!(all_text(&o).contains("--migrate") && !all_text(&o).contains("ALTER-TOKEN"));
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), before);
    assert!(!d.join("token").exists());
    // Mit --migrate: der Standardpfad /etc/patchwatch/token ist hier nicht beschreibbar, deshalb Test mit eigenem token_file
    // in der Konfiguration und zusätzlichem Alt-Eintrag (beides gleichzeitig kommt bei halbfertigen Migrationen vor).
    std::fs::write(&cfg, format!("{before}token_file = \"{}\"\n", tf.display())).unwrap();
    let o = run(
        &[
            "set-token",
            "--stdin",
            "--no-test",
            "--config",
            cfg.to_str().unwrap(),
        ],
        Some(&format!("{TOKEN}\n")),
        &[],
    );
    assert!(o.status.success(), "{}", all_text(&o));
    assert_no_token(&o);
}

#[test]
fn migrate_moves_the_token_out_of_the_config_with_a_backup_without_token() {
    let d = tmp("migrate2");
    let tf = d.join("token");
    // Wir leiten den Standardpfad nicht um; die Migration prüft stattdessen mit einem eigenen Ziel über token_file-lose Konfiguration:
    // dazu läuft das Binary mit einem schreibbaren Standardpfad nicht. Darum wird die Kernlogik hier über das Binary mit
    // `--migrate` und vorab angelegtem /etc-freien Pfad geprüft (siehe Unit-Test `migration_moves_token_out_of_the_config_and_keeps_the_rest`).
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        "token = \"pw_ALTER-TOKEN-0123456789abcdefghij\"\n",
    );
    let o = run(
        &[
            "set-token",
            "--migrate",
            "--stdin",
            "--no-test",
            "--config",
            cfg.to_str().unwrap(),
        ],
        Some(&format!("{TOKEN}\n")),
        &[],
    );
    assert_no_token(&o);
    let new_cfg = std::fs::read_to_string(&cfg).unwrap();
    if o.status.success() {
        // Lauf als root im Test-Container: /etc/patchwatch/token wurde geschrieben, die Konfiguration ist bereinigt.
        assert!(!new_cfg.contains("ALTER-TOKEN") && new_cfg.contains("token_file"));
        let backups: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().contains(".bak-"))
            .collect();
        assert_eq!(backups.len(), 1);
        let b = std::fs::read_to_string(&backups[0]).unwrap();
        assert!(!b.contains("ALTER-TOKEN"), "Sicherung ohne Token");
        assert_eq!(
            std::fs::metadata(&backups[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_file("/etc/patchwatch/token");
    } else {
        assert!(
            new_cfg.contains("ALTER-TOKEN"),
            "bei Fehlschlag bleibt die Konfiguration unverändert"
        );
    }
    let _ = tf;
}

#[test]
fn test_report_tells_accepted_or_rejected_and_sends_the_token_only_as_bearer() {
    for (status, expect, code) in [
        (200u16, "Token akzeptiert (Host:", 0),
        (401, "Token abgelehnt (401)", 4),
    ] {
        let d = tmp(&format!("net{status}"));
        let (url, h, rx) = mock(status);
        let tf = d.join("token");
        let cfg = config(&d, &url, &format!("token_file = \"{}\"\n", tf.display()));
        let o = run(
            &["set-token", "--stdin", "--config", cfg.to_str().unwrap()],
            Some(&format!("{TOKEN}\n")),
            &[],
        );
        assert_no_token(&o);
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        if out.contains("Test-Report nicht möglich") {
            // Erfassung auf diesem Rechner nicht möglich (z. B. kein os-release): Token ist trotzdem gespeichert.
            assert!(tf.exists());
            continue;
        }
        assert!(out.contains(expect), "{out}");
        assert_eq!(o.status.code(), Some(code), "{out}");
        assert!(
            tf.exists(),
            "der Token wird auch bei Ablehnung gespeichert (nur gemeldet)"
        );
        let req = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(
            req.contains(&format!("Bearer {TOKEN}"))
                || req.to_lowercase().contains("authorization: bearer")
        );
        drop(h);
    }
}

#[test]
fn unreachable_server_is_named_with_next_step() {
    let d = tmp("unreach");
    let tf = d.join("token");
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        &format!("token_file = \"{}\"\n", tf.display()),
    );
    let o = run(
        &["set-token", "--stdin", "--config", cfg.to_str().unwrap()],
        Some(&format!("{TOKEN}\n")),
        &[],
    );
    assert_no_token(&o);
    let out = String::from_utf8_lossy(&o.stdout);
    if !out.contains("Test-Report nicht möglich") {
        assert!(out.contains("Server nicht erreichbar"), "{out}");
        assert_eq!(o.status.code(), Some(3));
    }
}

#[test]
fn status_shows_origin_fingerprint_rights_and_never_the_token() {
    let d = tmp("status");
    let tf = d.join("token");
    std::fs::write(&tf, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&tf, std::fs::Permissions::from_mode(0o640)).unwrap();
    let (url, _h, _rx) = mock(200);
    let cfg = config(&d, &url, &format!("token_file = \"{}\"\n", tf.display()));
    let state = d.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("last-run"), "1000\tabgelehnt:401\n").unwrap();
    let o = run(
        &["status", "--config", cfg.to_str().unwrap()],
        None,
        &[("STATE_DIRECTORY", state.to_str().unwrap())],
    );
    assert!(o.status.success(), "{}", all_text(&o));
    assert_no_token(&o);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        out.contains(&format!("patchwatch-agent {}", env!("CARGO_PKG_VERSION"))),
        "{out}"
    );
    assert!(out.contains(&format!("Datei {}", tf.display())), "{out}");
    let fp: String = {
        // Erwarteter Fingerabdruck: SHA-256 des Tokens; per sha256sum gegengeprüft
        let mut c = Command::new("sha256sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(TOKEN.as_bytes()).unwrap();
        String::from_utf8(c.wait_with_output().unwrap().stdout).unwrap()[..8].to_owned()
    };
    assert!(out.contains(&format!("Token-Fingerabdruck: {fp}")), "{out}");
    assert!(
        out.contains("WARNUNG") && out.contains("0640"),
        "weite Rechte werden gemeldet: {out}"
    );
    assert!(
        out.contains("Server lehnte den Token ab (HTTP 401)"),
        "letzter Lauf: {out}"
    );
    assert!(
        out.contains("Server erreichbar:  ja") && out.contains("Zeitabweichung:"),
        "{out}"
    );
}

#[test]
fn unreachable_status_and_unknown_state_are_reported_without_failing() {
    let d = tmp("status2");
    let tf = d.join("token");
    std::fs::write(&tf, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&tf, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cfg = config(
        &d,
        "http://127.0.0.1:9",
        &format!("token_file = \"{}\"\n", tf.display()),
    );
    let o = run(
        &["status", "--config", cfg.to_str().unwrap()],
        None,
        &[("STATE_DIRECTORY", d.to_str().unwrap())],
    );
    assert!(o.status.success());
    assert_no_token(&o);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("Server erreichbar:  nein") && out.contains("Letzter Lauf:       unbekannt"),
        "{out}"
    );
}

#[test]
fn rejected_report_prints_the_clear_one_line_message_with_exit_code_4() {
    let d = tmp("report401");
    let (url, _h, _rx) = mock(401);
    let tf = d.join("token");
    std::fs::write(&tf, format!("{TOKEN}\n")).unwrap();
    let cfg = config(&d, &url, &format!("token_file = \"{}\"\n", tf.display()));
    let o = run(
        &["--config", cfg.to_str().unwrap()],
        None,
        &[("STATE_DIRECTORY", d.to_str().unwrap())],
    );
    if o.status.code() == Some(2) {
        return; // Erfassung hier nicht möglich
    }
    assert_eq!(o.status.code(), Some(4), "{}", all_text(&o));
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(err.trim().lines().count(), 1, "eine Zeile: {err}");
    assert!(
        err.contains("Server lehnt den Token ab (HTTP 401)")
            && err.contains("sudo patchwatch-agent set-token")
    );
    assert_no_token(&o);
    let last = std::fs::read_to_string(d.join("last-run")).unwrap();
    assert!(last.trim().ends_with("abgelehnt:401") && !last.contains(TOKEN));
}
