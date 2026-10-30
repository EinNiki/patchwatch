use crate::error::AgentError;
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_PATH: &str = "/etc/patchwatch/agent.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server_url: String,
    /// Direkter Token (nur für Tests/Notfälle; besser `token_file` oder systemd-Credential).
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub include_packages: bool,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Erlaubt http:// (nur für lokale Entwicklung).
    #[serde(default)]
    pub insecure_http: bool,
}

fn default_timeout() -> u64 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, AgentError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| AgentError::Config(format!("{} nicht lesbar: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, AgentError> {
        let cfg: Config = toml::from_str(text).map_err(|e| AgentError::Config(e.to_string()))?;
        let url = cfg.server_url.as_str();
        let scheme_ok =
            url.starts_with("https://") || (cfg.insecure_http && url.starts_with("http://"));
        if !scheme_ok {
            return Err(AgentError::Config(
                "server_url muss mit https:// beginnen (http:// nur mit insecure_http = true)"
                    .into(),
            ));
        }
        if !(1..=300).contains(&cfg.timeout_secs) {
            return Err(AgentError::Config(
                "timeout_secs muss zwischen 1 und 300 liegen".into(),
            ));
        }
        Ok(cfg)
    }

    pub fn report_url(&self) -> String {
        format!("{}/api/v1/report", self.server_url.trim_end_matches('/'))
    }

    /// Reihenfolge: systemd-Credential, `token_file`, `token`.
    pub fn resolve_token(&self) -> Result<String, AgentError> {
        let from_credential = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(|d| PathBuf::from(d).join("token"))
            .filter(|p| p.is_file());
        let raw = if let Some(p) = from_credential.or_else(|| self.token_file.clone()) {
            std::fs::read_to_string(&p).map_err(|e| {
                AgentError::Config(format!("Token-Datei {} nicht lesbar: {e}", p.display()))
            })?
        } else {
            self.token
                .clone()
                .ok_or_else(|| AgentError::Config("kein Token konfiguriert".into()))?
        };
        let token = raw.trim().to_owned();
        if token.is_empty() || token.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(AgentError::Config(
                "Token ist leer oder enthält ungültige Zeichen".into(),
            ));
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_gets_defaults() {
        let c = Config::parse("server_url = \"https://pw.example.org/\"\ntoken = \"abc\"").unwrap();
        assert!(!c.include_packages);
        assert_eq!(c.timeout_secs, 30);
        assert_eq!(c.report_url(), "https://pw.example.org/api/v1/report");
    }

    #[test]
    fn rejects_plain_http_unless_allowed() {
        assert!(Config::parse("server_url = \"http://x\"").is_err());
        assert!(Config::parse("server_url = \"http://x\"\ninsecure_http = true").is_ok());
    }

    #[test]
    fn rejects_unknown_keys_and_bad_timeout() {
        assert!(Config::parse("server_url = \"https://x\"\nfoo = 1").is_err());
        assert!(Config::parse("server_url = \"https://x\"\ntimeout_secs = 0").is_err());
    }

    #[test]
    fn token_is_trimmed_and_validated() {
        let c = Config::parse("server_url = \"https://x\"\ntoken = \"  abc\\n\"").unwrap();
        // Ohne gesetztes CREDENTIALS_DIRECTORY greift `token`.
        if std::env::var_os("CREDENTIALS_DIRECTORY").is_none() {
            assert_eq!(c.resolve_token().unwrap(), "abc");
        }
        let bad = Config::parse("server_url = \"https://x\"\ntoken = \"a b\"").unwrap();
        if std::env::var_os("CREDENTIALS_DIRECTORY").is_none() {
            assert!(bad.resolve_token().is_err());
        }
    }
}
