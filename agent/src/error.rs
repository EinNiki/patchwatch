use std::fmt;

/// Fehlerklassen mit festen Exit-Codes (1 Config, 2 Erfassung, 3 Netzwerk, 4 Server lehnt ab).
#[derive(Debug)]
pub enum AgentError {
    Config(String),
    Collect(String),
    Network(String),
    Rejected(u16),
}

impl AgentError {
    pub fn code(&self) -> u8 {
        match self {
            Self::Config(_) => 1,
            Self::Collect(_) => 2,
            Self::Network(_) => 3,
            Self::Rejected(_) => 4,
        }
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "Konfiguration: {m}"),
            Self::Collect(m) => write!(f, "Erfassung: {m}"),
            Self::Network(m) => write!(f, "Server nicht erreichbar: {m}"),
            Self::Rejected(c) => write!(f, "Server lehnt Report ab (HTTP {c})"),
        }
    }
}

impl std::error::Error for AgentError {}
