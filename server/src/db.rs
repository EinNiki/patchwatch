//! Datenbankverbindung beim Start: begrenzte Wiederholungen, solange die Datenbank (noch) nicht erreichbar ist
//! (z. B. Postgres startet nach dem Server, ohne Compose oder Restart-Policy).

use crate::error::is_db_unavailable;
use std::future::Future;
use std::time::{Duration, Instant};

/// Wartezeiten beim Start: erster Abstand, größter Abstand, Gesamtdauer.
pub const STARTUP_FIRST_DELAY: Duration = Duration::from_secs(1);
pub const STARTUP_MAX_DELAY: Duration = Duration::from_secs(5);
pub const STARTUP_MAX_WAIT: Duration = Duration::from_secs(60);

/// Ruft `connect` erneut auf, solange der Fehler "Datenbank nicht erreichbar" bedeutet ([`is_db_unavailable`]) und
/// der nächste Versuch noch innerhalb von `max_wait` beginnt. Der Abstand verdoppelt sich von `first_delay` bis
/// höchstens `max_delay`. Andere Fehler (falsches Passwort, ungültige Adresse) brechen sofort ab.
pub async fn connect_with_retry<T, F, Fut>(
    mut connect: F,
    first_delay: Duration,
    max_delay: Duration,
    max_wait: Duration,
) -> Result<T, sqlx::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, sqlx::Error>>,
{
    let start = Instant::now();
    let mut delay = first_delay;
    let mut attempt = 1u32;
    loop {
        match connect().await {
            Ok(v) => return Ok(v),
            Err(e) if is_db_unavailable(&e) && start.elapsed() + delay <= max_wait => {
                tracing::warn!(
                    attempt,
                    error = %e,
                    retry_in_ms = delay.as_millis() as u64,
                    "Datenbank noch nicht erreichbar, neuer Versuch"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(max_delay);
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    const MS: Duration = Duration::from_millis(1);

    #[tokio::test]
    async fn retries_until_the_database_answers() {
        let calls = AtomicU32::new(0);
        let r = connect_with_retry(
            || async {
                if calls.fetch_add(1, Ordering::SeqCst) < 3 {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(42)
                }
            },
            MS,
            MS * 4,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(r.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn gives_up_after_max_wait() {
        let calls = AtomicU32::new(0);
        let t0 = Instant::now();
        let r: Result<(), _> = connect_with_retry(
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(sqlx::Error::PoolTimedOut)
            },
            MS * 10,
            MS * 20,
            MS * 100,
        )
        .await;
        assert!(matches!(r, Err(sqlx::Error::PoolTimedOut)));
        assert!(t0.elapsed() < Duration::from_secs(2));
        let n = calls.load(Ordering::SeqCst);
        assert!((2..=10).contains(&n), "{n} Versuche");
    }

    #[tokio::test]
    async fn other_errors_are_not_retried() {
        let calls = AtomicU32::new(0);
        let r: Result<(), _> = connect_with_retry(
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(sqlx::Error::Configuration("ungültige Adresse".into()))
            },
            MS,
            MS,
            Duration::from_secs(5),
        )
        .await;
        assert!(matches!(r, Err(sqlx::Error::Configuration(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
