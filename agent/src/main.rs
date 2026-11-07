mod checkin;
mod cmd;
mod collect;
mod config;
mod error;
mod report;
mod send;
mod setcmd;
mod status;
mod token;

use error::AgentError;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "Verwendung: patchwatch-agent [checkin|status|set-token] [--config PFAD] [--dry-run]\n\
  (ohne Befehl)  Report erfassen und senden\n\
  checkin        Server fragen, ob ein Report gewünscht ist; nur dann senden\n\
  status         Version, Konfiguration, Token-Herkunft und -Fingerabdruck, Rechte, letzter Lauf, Erreichbarkeit\n\
  set-token      neuen Token setzen (Abfrage ohne Echo, --stdin oder --token-file PFAD; --migrate, --no-test).\n\
                 Der Token wird nie als Argument akzeptiert und nie ausgegeben.\n\
  --config PFAD  Konfigurationsdatei (Standard: /etc/patchwatch/agent.toml)\n\
  --dry-run      Report als JSON ausgeben, nichts senden\n\
  --version      Version anzeigen";

fn run() -> Result<(), AgentError> {
    let mut config_path = PathBuf::from(config::DEFAULT_PATH);
    let mut dry_run = false;
    let mut checkin_mode = false;
    let mut args = std::env::args().skip(1);
    let mut sub: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => {
                config_path = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| AgentError::Config("--config braucht einen Pfad".into()))?;
            }
            "--dry-run" => dry_run = true,
            "checkin" => checkin_mode = true,
            // Unterbefehle mit eigenen Optionen: der Rest wird dort ausgewertet (und nie im Klartext wiedergegeben).
            "status" | "set-token" if sub.is_none() => {
                sub = Some(a.clone());
                rest.extend(args.by_ref());
                break;
            }
            "--version" => {
                println!("patchwatch-agent {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => {
                return Err(AgentError::Config(format!(
                    "unbekannte Option {other}\n{USAGE}"
                )))
            }
        }
    }

    if let Some(sub) = sub {
        // `--config PFAD` darf auch hinter dem Unterbefehl stehen.
        if let Some(i) = rest.iter().position(|x| x == "--config") {
            if i + 1 >= rest.len() {
                return Err(AgentError::Config("--config braucht einen Pfad".into()));
            }
            config_path = PathBuf::from(rest.remove(i + 1));
            rest.remove(i);
        }
        if dry_run || checkin_mode {
            return Err(AgentError::Config(
                "--dry-run und checkin gelten nicht für diesen Unterbefehl".into(),
            ));
        }
        if sub == "status" {
            if !rest.is_empty() {
                return Err(AgentError::Config(
                    "status kennt keine weiteren Argumente".into(),
                ));
            }
            return status::run(&config_path, &mut std::io::stdout());
        }
        let opts = setcmd::parse_args(rest)?;
        let code = setcmd::run_system(&config_path, &opts)?;
        if code != 0 {
            return Err(AgentError::Exit(code));
        }
        return Ok(());
    }

    let cfg = config::Config::load(&config_path)?;
    let build = || report::build(&cmd::System, &report::system_paths(), &cfg);
    if checkin_mode {
        if dry_run {
            return Err(AgentError::Config(
                "--dry-run gilt nicht für checkin".into(),
            ));
        }
        if !cfg.checkin_enabled {
            return Ok(());
        }
        let token = cfg.resolve_token()?;
        let r = checkin::run_system(&cfg, &token, build).map(|_| ());
        if r.is_err() {
            status::record_run(&r);
        }
        return r;
    }
    let report = build()?;
    if dry_run {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| AgentError::Collect(e.to_string()))?;
        println!("{json}");
        return Ok(());
    }
    let token = cfg.resolve_token()?;
    let r = send::send(&cfg, &token, &report);
    status::record_run(&r);
    r
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // stderr landet bei systemd-Diensten im journald.
            if !matches!(e, AgentError::Exit(_)) {
                eprintln!("patchwatch-agent: {e}");
            }
            ExitCode::from(e.code())
        }
    }
}

#[cfg(test)]
mod dist_tests {
    /// install.sh bettet die Units ein; sie dürfen nicht von agent/dist abweichen.
    #[test]
    fn install_script_embeds_unit_files() {
        let script = include_str!("../dist/install.sh");
        assert!(script.contains(include_str!("../dist/patchwatch-agent.service")));
        assert!(script.contains(include_str!("../dist/patchwatch-agent.timer")));
        assert!(script.contains(include_str!("../dist/patchwatch-agent-checkin.service")));
        assert!(script.contains(include_str!("../dist/patchwatch-agent-checkin.timer")));
    }
}
