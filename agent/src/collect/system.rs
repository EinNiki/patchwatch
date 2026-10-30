use std::path::Path;

/// Erste Zahl aus /proc/uptime in ganzen Sekunden.
pub fn parse_uptime(text: &str) -> Option<u64> {
    let secs: f64 = text.split_whitespace().next()?.parse().ok()?;
    (secs.is_finite() && secs >= 0.0).then_some(secs as u64)
}

pub fn reboot_required_file(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime() {
        assert_eq!(parse_uptime("12345.67 8910.11\n"), Some(12345));
        assert_eq!(parse_uptime(""), None);
        assert_eq!(parse_uptime("-1 2"), None);
    }
}
