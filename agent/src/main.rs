mod checkin;
mod cmd;
mod collect;
mod config;
mod error;
mod report;
mod send;

use error::AgentError;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "Verwendung: patchwatch-agent [checkin] [--config PFAD] [--dry-run]\n\
  (ohne Befehl)  Report erfassen und senden\n\
  checkin        Server fragen, ob ein Report gewünscht ist; nur dann senden\n\
  --config PFAD  Konfigurationsdatei (Standard: /etc/patchwatch/agent.toml)\n\
  --dry-run      Report als JSON ausgeben, nichts senden\n\
  --version      Version anzeigen";

fn run() -> Result<(), AgentError> {
    let mut config_path = PathBuf::from(config::DEFAULT_PATH);
    let mut dry_run = false;
    let mut checkin_mode = false;
    let mut args = std::env::args().skip(1);
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
        checkin::run_system(&cfg, &token, build)?;
        return Ok(());
    }
    let report = build()?;
    if dry_run {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| AgentError::Collect(e.to_string()))?;
        println!("{json}");
        return Ok(());
    }
    let token = cfg.resolve_token()?;
    send::send(&cfg, &token, &report)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // stderr landet bei systemd-Diensten im journald.
            eprintln!("patchwatch-agent: {e}");
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
