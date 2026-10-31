//! Geheimnisse in der URL (Telegram-Bot-Token): Sie dürfen weder in Logs noch in Fehlern auftauchen.
//! Eigene Test-Binary, damit der globale Log-Collector keine anderen Tests stört.

use patchwatch_server::notify::channels::{telegram_with_base, Http, SendError};
use patchwatch_server::notify::messages;
use std::io::Write;
use std::sync::{Arc, Mutex};

const TOKEN: &str = "123456789:AAE_abcdefghijklmnopqrstuvwxyz012345";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

#[tokio::test]
async fn telegram_token_never_reaches_logs_or_errors() {
    let cap = Capture::default();
    tracing_subscriber::fmt()
        .with_writer(cap.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .init();

    let http = Http {
        allowed_hosts: vec![],
        trusted: true,
    };
    // Verbindung scheitert (Port 1): der reqwest-Fehler enthielte ohne `without_url()` die komplette URL samt Token.
    let base = reqwest::Url::parse("http://127.0.0.1:1").unwrap();
    let ch = telegram_with_base(base, TOKEN.into(), "42", http.clone()).unwrap();
    let err = ch.send(&messages::test_message()).await.unwrap_err();
    assert_eq!(err, SendError::Unreachable);
    assert!(!err.summary().contains("AAE_"));
    assert!(!format!("{err:?}").contains("AAE_"));

    // Nicht-trusted: gesperrtes Ziel (Loopback) wird abgelehnt, ebenfalls ohne Token im Log.
    let base = reqwest::Url::parse("http://127.0.0.1:9").unwrap();
    let ch = telegram_with_base(
        base,
        TOKEN.into(),
        "42",
        Http {
            allowed_hosts: vec!["127.0.0.1".into()],
            trusted: false,
        },
    )
    .unwrap();
    assert_eq!(
        ch.send(&messages::test_message()).await.unwrap_err(),
        SendError::Unreachable
    );

    let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("Kanal-Versand fehlgeschlagen"),
        "Fehler wird geloggt: {logs}"
    );
    assert!(
        !logs.contains(TOKEN) && !logs.contains("AAE_") && !logs.contains("123456789"),
        "Token im Log: {logs}"
    );
    assert!(!logs.contains("/bot"), "URL-Pfad im Log: {logs}");
}
