//! Debian package version parsing and comparison following the dpkg rules
//! (Debian Policy 5.6.12): `[epoch:]upstream[-revision]`.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// Reasons a version string is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    BadEpoch,
    EmptyUpstream,
    UpstreamNotDigitStart,
    InvalidChar(char),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty version"),
            Self::BadEpoch => write!(f, "epoch is not a number"),
            Self::EmptyUpstream => write!(f, "empty upstream version"),
            Self::UpstreamNotDigitStart => write!(f, "upstream version must start with a digit"),
            Self::InvalidChar(c) => write!(f, "invalid character {c:?}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed Debian version. Ordering and equality follow dpkg semantics,
/// so `1.0` equals `0:1.0` and `1.0-0` equals `1.0`.
#[derive(Debug, Clone)]
pub struct Version {
    epoch: u32,
    upstream: String,
    revision: String,
}

impl Version {
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    pub fn upstream(&self) -> &str {
        &self.upstream
    }
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

impl FromStr for Version {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseError::Empty);
        }
        let (epoch, rest) = match s.split_once(':') {
            Some((e, r)) => (e.parse::<u32>().map_err(|_| ParseError::BadEpoch)?, r),
            None => (0, s),
        };
        // The revision is everything after the LAST hyphen.
        let (upstream, revision) = match rest.rsplit_once('-') {
            Some((u, r)) => (u, r),
            None => (rest, ""),
        };
        if upstream.is_empty() {
            return Err(ParseError::EmptyUpstream);
        }
        if !upstream.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(ParseError::UpstreamNotDigitStart);
        }
        let ok = |c: char| c.is_ascii_alphanumeric() || ".+-~:".contains(c);
        if let Some(bad) = upstream.chars().chain(revision.chars()).find(|c| !ok(*c)) {
            return Err(ParseError::InvalidChar(bad));
        }
        Ok(Self {
            epoch,
            upstream: upstream.to_owned(),
            revision: revision.to_owned(),
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}:", self.epoch)?;
        }
        write!(f, "{}", self.upstream)?;
        if !self.revision.is_empty() {
            write!(f, "-{}", self.revision)?;
        }
        Ok(())
    }
}

/// Sort weight of one character: `~` < end of string < letters < everything else.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

/// dpkg's `verrevcmp`: alternating non-digit and digit runs.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let mut first_diff = 0;
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let (ac, bc) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == 0 {
                first_diff = i32::from(a[i]) - i32::from(b[j]);
            }
            i += 1;
            j += 1;
        }
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| verrevcmp(&self.upstream, &other.upstream))
            .then_with(|| verrevcmp(&self.revision, &other.revision))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

/// Compares two version strings; fails if either is not a valid Debian version.
pub fn compare(a: &str, b: &str) -> Result<Ordering, ParseError> {
    Ok(a.parse::<Version>()?.cmp(&b.parse::<Version>()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        compare(a, b).unwrap()
    }

    #[test]
    fn ordering_table() {
        let cases = [
            ("1.0", "1.0", Equal),
            // Ubuntu-Kernel (mit dpkg --compare-versions gegengeprüft): numerisch, nicht textlich.
            ("7.0.0-39.39", "7.0.0-42.42", Less),
            ("7.0.0-100.100", "7.0.0-42.42", Greater),
            ("7.0.0-9.9", "7.0.0-10.10", Less),
            ("1:7.0.0-1", "7.0.0-99", Greater),
            ("7.0.0-42.42~rc1", "7.0.0-42.42", Less),
            ("1.0", "0:1.0", Equal),
            ("1.0-0", "1.0", Equal),
            ("1.0", "1.1", Less),
            ("1.9", "1.10", Less),
            ("1.0~rc1", "1.0", Less),
            ("1.0~~", "1.0~", Less),
            ("1.0~", "1.0", Less),
            ("1.0", "1.0a", Less),
            ("1.0a", "1.0+", Less),
            ("1.0+b1", "1.0", Greater),
            ("1:0.1", "2.0", Greater),
            ("2.0", "1:0.1", Less),
            ("1.0-1", "1.0-2", Less),
            ("1.0-1ubuntu1", "1.0-1", Greater),
            ("1.0-1~bpo12+1", "1.0-1", Less),
            ("007", "7", Equal),
            ("1.0.0", "1.0", Greater),
            ("1.a", "1.b", Less),
        ];
        for (a, b, want) in cases {
            assert_eq!(cmp(a, b), want, "{a} vs {b}");
            assert_eq!(cmp(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn kernel_versions() {
        // Ubuntu 22.04 / 24.04, Debian trixie and Proxmox style kernel versions.
        let cases = [
            ("5.15.0-100.110", "5.15.0-101.111", Less),
            ("5.15.0-99.109", "5.15.0-100.110", Less),
            ("6.8.0-31.31", "6.8.0-9.9", Greater),
            ("6.12.48-1", "6.12.57-1", Less),
            ("6.12.57-1", "6.12.57-1+deb13u1", Less),
            ("6.14.11-2", "6.14.11-4", Less),
            ("6.14.11-4", "6.17.2-1", Less),
            ("6.8.12-1~bpo12+1", "6.8.12-1", Less),
        ];
        for (a, b, want) in cases {
            assert_eq!(cmp(a, b), want, "{a} vs {b}");
        }
    }

    #[test]
    fn parsing() {
        let v: Version = "2:6.8.0-31.31".parse().unwrap();
        assert_eq!(
            (v.epoch(), v.upstream(), v.revision()),
            (2, "6.8.0", "31.31")
        );
        assert_eq!(v.to_string(), "2:6.8.0-31.31");
        // Only the last hyphen splits off the revision.
        let v: Version = "1.2-3-4".parse().unwrap();
        assert_eq!((v.upstream(), v.revision()), ("1.2-3", "4"));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!("".parse::<Version>(), Err(ParseError::Empty));
        assert_eq!("x:1".parse::<Version>(), Err(ParseError::BadEpoch));
        assert_eq!("-1".parse::<Version>(), Err(ParseError::EmptyUpstream));
        assert_eq!(
            "abc".parse::<Version>(),
            Err(ParseError::UpstreamNotDigitStart)
        );
        assert_eq!(
            "1.0 beta".parse::<Version>(),
            Err(ParseError::InvalidChar(' '))
        );
        assert!(compare("1.0", "").is_err());
    }
}
