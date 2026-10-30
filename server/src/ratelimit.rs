use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Einfaches Fixed-Window-Limit im Speicher (eine Instanz; für Login, Reports, API).
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    /// `Ok`, solange `limit` Anfragen je `window` nicht überschritten sind; sonst Wartezeit.
    pub fn check(&self, key: &str, limit: u32, window: Duration) -> Result<(), Duration> {
        let now = Instant::now();
        let mut map = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 10_000 {
            map.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = map.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        if entry.1 >= limit {
            return Err(window.saturating_sub(now.duration_since(entry.0)));
        }
        entry.1 += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_limit_and_separates_keys() {
        let rl = RateLimiter::default();
        let w = Duration::from_secs(60);
        assert!(rl.check("a", 2, w).is_ok());
        assert!(rl.check("a", 2, w).is_ok());
        assert!(rl.check("a", 2, w).is_err());
        assert!(rl.check("b", 2, w).is_ok());
    }

    #[test]
    fn window_resets() {
        let rl = RateLimiter::default();
        let w = Duration::from_millis(20);
        assert!(rl.check("a", 1, w).is_ok());
        assert!(rl.check("a", 1, w).is_err());
        std::thread::sleep(Duration::from_millis(30));
        assert!(rl.check("a", 1, w).is_ok());
    }
}
