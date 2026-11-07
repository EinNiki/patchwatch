//! `patchwatch-agent set-token`: neuen Token sicher setzen (nie als Argument, nie ausgeben).
use crate::config::Config;
use crate::error::AgentError;
use crate::token::{self, DEFAULT_TOKEN_PATH};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    Prompt,
    Stdin,
    File(PathBuf),
}

#[derive(Debug)]
pub struct Opts {
    pub input: Input,
    pub migrate: bool,
    pub no_test: bool,
}

const NO_ARG_TOKEN: &str = "Der Token darf nicht als Kommandozeilen-Argument übergeben werden (er stünde in ps und in der Shell-History). \
Verwende die Abfrage ohne Echo (ohne Option), --stdin oder --token-file <Pfad>.";

/// Argumente nach `set-token`. Gibt nie ein Argument im Klartext wieder (es könnte der Token sein).
pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Opts, AgentError> {
    let mut input = Input::Prompt;
    let mut set = false;
    let (mut migrate, mut no_test) = (false, false);
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--token" => return Err(AgentError::Config(NO_ARG_TOKEN.into())),
            s if s.starts_with("--token=") => return Err(AgentError::Config(NO_ARG_TOKEN.into())),
            "--stdin" | "--token-file" if set => {
                return Err(AgentError::Config(
                    "Nur ein Eingabeweg erlaubt (--stdin oder --token-file)".into(),
                ))
            }
            "--stdin" => {
                input = Input::Stdin;
                set = true;
            }
            "--token-file" => {
                let p = it
                    .next()
                    .ok_or_else(|| AgentError::Config("--token-file braucht einen Pfad".into()))?;
                input = Input::File(PathBuf::from(p));
                set = true;
            }
            "--migrate" => migrate = true,
            "--no-test" => no_test = true,
            s if s.starts_with("--")
                && s.len() <= 24
                && s[2..].chars().all(|c| c.is_ascii_lowercase() || c == '-') =>
            {
                return Err(AgentError::Config(format!(
                    "unbekannte Option für set-token: {s}"
                )))
            }
            _ => {
                return Err(AgentError::Config(
                    "unerwartetes Argument (Token nie als Argument übergeben; siehe --help)".into(),
                ))
            }
        }
    }
    Ok(Opts {
        input,
        migrate,
        no_test,
    })
}

/// Test-Report mit dem neuen Token. `Ok(hostname)` bei Annahme.
fn test_report(cfg: &Config, token: &str) -> Result<String, AgentError> {
    let report = crate::report::build(&crate::cmd::System, &crate::report::system_paths(), cfg)?;
    crate::send::send(cfg, token, &report)?;
    Ok(report.hostname)
}

pub struct Outcome {
    pub code: u8,
}

/// Führt `set-token` aus. `read_input` liefert den Rohtext (Abfrage, stdin oder Datei).
pub fn run(
    config_path: &Path,
    opts: &Opts,
    euid: u32,
    read_input: &dyn Fn(&Input) -> Result<String, AgentError>,
    test: &dyn Fn(&Config, &str) -> Result<String, AgentError>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Outcome, AgentError> {
    let text = std::fs::read_to_string(config_path).map_err(|e| {
        AgentError::Config(format!(
            "{} nicht lesbar: {}",
            config_path.display(),
            e.kind()
        ))
    })?;
    let cfg = Config::parse(&text)?;

    // Token direkt in agent.toml: dort wird nichts hineingeschrieben; --migrate verschiebt ihn in die Datei.
    let inline = cfg.token.is_some() && cfg.token_file.is_none();
    if inline && !opts.migrate {
        let _ = writeln!(
            err,
            "Der Token steht direkt in {} (Klartext). set-token schreibt dort nichts hinein.\n\
             Mit `sudo patchwatch-agent set-token --migrate` wandert der Token in {DEFAULT_TOKEN_PATH} (0600, root:root), \
             der Eintrag verschwindet aus der Konfiguration, eine Sicherung ohne Token bleibt liegen.",
            config_path.display()
        );
        return Err(AgentError::Config(
            "Token in agent.toml: --migrate verwenden".into(),
        ));
    }
    if opts.migrate && !inline {
        let _ = writeln!(
            err,
            "Hinweis: --migrate ist nicht nötig (kein Token in agent.toml)."
        );
    }

    let raw = read_input(&opts.input)?;
    token::validate(&raw)?;
    let target = token::default_target(cfg.token_file.as_ref());
    for w in token::check_target(&target, euid)? {
        let _ = writeln!(err, "Hinweis: {w}");
    }

    // Migration: erst die Token-Datei, dann Sicherung (ohne Token), dann die neue Konfiguration.
    if inline && opts.migrate {
        let (new_cfg, backup) = token::migrate_config_text(&text, &target)
            .ok_or_else(|| AgentError::Config("kein token-Eintrag gefunden".into()))?;
        token::write_atomic(&target, &raw, euid == 0)?;
        let backup_path = PathBuf::from(format!(
            "{}.bak-{}",
            config_path.display(),
            crate::status::now_secs()
        ));
        token::write_atomic_text(&backup_path, &backup)?;
        let meta = std::fs::metadata(config_path)
            .map_err(|e| AgentError::Config(format!("{}: {}", config_path.display(), e.kind())))?;
        token::write_atomic_text_like(
            config_path,
            &new_cfg,
            meta.mode() & 0o7777,
            (meta.uid(), meta.gid()),
            euid == 0,
        )?;
        let _ = writeln!(
            out,
            "Konfiguration migriert: Token-Eintrag entfernt, token_file = {}",
            target.display()
        );
        let _ = writeln!(out, "Sicherung ohne Token: {}", backup_path.display());
    } else {
        token::write_atomic(&target, &raw, euid == 0)?;
    }
    let owner = if euid == 0 {
        "root:root"
    } else {
        "aktueller Benutzer (nicht root)"
    };
    let _ = writeln!(
        out,
        "Token gespeichert: {} (Modus 0600, {owner})",
        target.display()
    );
    let _ = writeln!(
        out,
        "Fingerabdruck: {} (SHA-256, erste 8 Hex-Zeichen)",
        token::fingerprint(&raw)
    );
    if euid != 0 {
        let _ = writeln!(err, "Hinweis: nicht als root ausgeführt; für den Dienst muss die Datei root:root gehören (sudo patchwatch-agent set-token).");
    }

    let mut code = 0;
    if opts.no_test {
        let _ = writeln!(out, "Test-Report übersprungen (--no-test).");
    } else {
        match test(&cfg, &raw) {
            Ok(host) => {
                let _ = writeln!(out, "Token akzeptiert (Host: {host})");
            }
            Err(AgentError::Rejected(c)) => {
                let _ = writeln!(
                    out,
                    "Token abgelehnt ({c}). Der Server kennt diesen Token nicht. Unter Agents in der Weboberfläche einen neuen Token erzeugen und erneut setzen."
                );
                code = 4;
            }
            Err(AgentError::Network(_)) => {
                let _ = writeln!(
                    out,
                    "Server nicht erreichbar ({}). Der Token ist gespeichert, aber nicht geprüft. Nächster Schritt: Netzwerk und server_url prüfen, dann `patchwatch-agent status`.",
                    cfg.server_url
                );
                code = 3;
            }
            Err(e) => {
                let _ = writeln!(out, "Test-Report nicht möglich ({e}). Der Token ist gespeichert, aber nicht geprüft.");
                code = e.code();
            }
        }
    }
    let _ = writeln!(
        out,
        "Der Dienst wurde nicht neu gestartet. Starten mit: sudo systemctl start patchwatch-agent"
    );
    Ok(Outcome { code })
}

/// Eingabe lesen: Abfrage, stdin oder Datei.
pub fn read_input(i: &Input) -> Result<String, AgentError> {
    match i {
        Input::Prompt => token::prompt(),
        Input::Stdin => token::read_limited(std::io::stdin().lock()),
        Input::File(p) => token::read_file(p),
    }
}

pub fn run_system(config_path: &Path, opts: &Opts) -> Result<u8, AgentError> {
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let o = run(
        config_path,
        opts,
        token::effective_uid(),
        &read_input,
        &test_report,
        &mut out,
        &mut err,
    )?;
    Ok(o.code)
}
