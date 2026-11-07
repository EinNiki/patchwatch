use std::fmt;

/// Fehlerklassen mit festen Exit-Codes (1 Config, 2 Erfassung, 3 Netzwerk, 4 Server lehnt ab).
#[derive(Debug)]
pub enum AgentError {
    Config(String),
    Collect(String),
    Network(String),
    Rejected(u16),
    /// Nur ein Exit-Code (die Meldung wurde schon ausgegeben).
    Exit(u8),
}

impl AgentError {
    pub fn code(&self) -> u8 {
        match self {
            Self::Config(_) => 1,
            Self::Collect(_) => 2,
            Self::Network(_) => 3,
            Self::Rejected(_) => 4,
            Self::Exit(c) => *c,
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "Konfiguration: {m}"),
            Self::Collect(m) => write!(f, "Erfassung: {m}"),
            Self::Network(m) => write!(f, "Server nicht erreichbar: {m}"),
            // Eine Zeile (journald): Ursache und nächster Schritt, nie der Token selbst.
            Self::Rejected(c @ (401 | 403)) => write!(
                f,
                "Server lehnt den Token ab (HTTP {c}). Mögliche Ursachen: Token erneuert, Host gelöscht oder Datenbank zurückgesetzt. \
                 In der Weboberfläche unter Agents einen Token erzeugen und mit `sudo patchwatch-agent set-token` setzen."
            ),
            Self::Rejected(c) => write!(f, "Server lehnt Report ab (HTTP {c})"),
            Self::Exit(_) => write!(f, "beendet"),
        }
    }
}

impl std::error::Error for AgentError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_token_text_names_causes_and_next_step_in_one_line() {
        for code in [401u16, 403] {
            let e = AgentError::Rejected(code);
            let t = e.to_string();
            assert!(
                t.starts_with(&format!("Server lehnt den Token ab (HTTP {code})")),
                "{t}"
            );
            assert!(
                t.contains("Token erneuert")
                    && t.contains("Datenbank zurückgesetzt")
                    && t.contains("sudo patchwatch-agent set-token")
            );
            assert!(!t.contains('\n'), "eine Zeile im Journal");
            assert_eq!(e.code(), 4, "Exit-Code bleibt 4");
        }
        assert_eq!(
            AgentError::Rejected(500).to_string(),
            "Server lehnt Report ab (HTTP 500)"
        );
    }
}
