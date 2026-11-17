//! Versionsvergleich von Image-Tags ohne Zusatzbibliothek. Es wird nur verglichen, was sicher vergleichbar ist:
//! Tags mit mindestens drei Zahlengliedern (`1.27.3`), gleichem Präfix (`v`) und gleicher Variante (`-alpine`).
//! Alles andere ist „gleitend“ (`latest`, `1.27`, `1`) oder „nicht vergleichbar“; nichts wird geraten.

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Version {
    /// `v` oder leer.
    prefix: String,
    nums: Vec<u32>,
    /// Alles nach dem Zahlenteil, z. B. `-alpine` (leer = Standardvariante).
    variant: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    /// Bewegt sich mit der Zeit (`latest`, `1.27`, `stable`): Vergleich über den Digest.
    Floating,
    /// Feste Version: Vergleich über die Tag-Liste.
    Fixed(Version),
    /// Weder noch (Datum, Hash, Vorabversion): wird nicht bewertet.
    Incomparable,
}

const PRE: [&str; 8] = [
    "rc", "beta", "alpha", "dev", "pre", "snapshot", "nightly", "preview",
];
/// Zahlenglieder über dieser Grenze sind Datumsangaben oder Build-Nummern (`20240101`), keine Versionen.
const MAX_PART: u64 = 9999;

fn is_pre(variant: &str) -> bool {
    variant
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| {
            let w = w.to_ascii_lowercase();
            // `rc1`, `beta2`: Schlüsselwort plus optionale Ziffern.
            PRE.iter().any(|p| {
                w.strip_prefix(p)
                    .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
            })
        })
}

/// Zerlegt einen Tag in Präfix, Zahlenglieder und Variante; `None`, wenn er nicht mit (v)Zahl beginnt.
fn split(tag: &str) -> Option<(String, Vec<u64>, String)> {
    let (prefix, rest) = match tag.strip_prefix('v') {
        Some(r) if r.starts_with(|c: char| c.is_ascii_digit()) => ("v", r),
        _ => ("", tag),
    };
    let end = rest
        .char_indices()
        .find(|(i, c)| {
            !(c.is_ascii_digit()
                || (*c == '.' && rest[i + 1..].starts_with(|n: char| n.is_ascii_digit())))
        })
        .map_or(rest.len(), |(i, _)| i);
    let (num, variant) = rest.split_at(end);
    if num.is_empty() || !num.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let nums: Option<Vec<u64>> = num.split('.').map(|p| p.parse().ok()).collect();
    Some((prefix.to_owned(), nums?, variant.to_owned()))
}

pub fn classify(tag: &str) -> Kind {
    let Some((prefix, nums, variant)) = split(tag) else {
        // `latest`, `stable`, `alpine`, Hash-Tags ohne führende Zahl: gleitend, solange es ein Wort ist.
        let word = tag
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '-' || c == '_');
        return if word {
            Kind::Floating
        } else {
            Kind::Incomparable
        };
    };
    if nums.iter().any(|n| *n > MAX_PART) || is_pre(&variant) {
        return Kind::Incomparable;
    }
    // Variante muss mit `-` oder `_` beginnen (sonst z. B. `1.2.3abc` oder `3e4f5a6` = wahrscheinlich ein Hash).
    if !variant.is_empty() && !variant.starts_with(['-', '_']) {
        return Kind::Incomparable;
    }
    if nums.len() < 3 {
        return Kind::Floating;
    }
    Kind::Fixed(Version {
        prefix,
        nums: nums.iter().map(|n| *n as u32).collect(),
        variant,
    })
}

/// Neueste Tags, getrennt nach Art des Sprungs. Jeder Wert ist der Tag-Name, wie er in der Registry steht.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Newest {
    pub patch: Option<String>,
    pub minor: Option<String>,
    pub major: Option<String>,
}

/// Neueste Patch-, Minor- und Major-Version zu `current` aus `tags`; berücksichtigt nur Tags mit gleichem Präfix, gleicher
/// Variante und gleicher Gliederzahl, ohne Vorabversionen.
pub fn newest(current: &Version, tags: &[String]) -> Newest {
    // Je Art des Sprungs der bisher beste Treffer (Zahlenglieder und Tag-Name).
    let mut best: [Option<(Vec<u32>, &String)>; 3] = [None, None, None];
    for name in tags {
        let Kind::Fixed(v) = classify(name) else {
            continue;
        };
        if v.prefix != current.prefix
            || v.variant != current.variant
            || v.nums.len() != current.nums.len()
            || v.nums <= current.nums
        {
            continue;
        }
        let slot = if v.nums[..2] == current.nums[..2] {
            0
        } else if v.nums[0] == current.nums[0] {
            1
        } else {
            2
        };
        if best[slot].as_ref().is_none_or(|(n, _)| *n < v.nums) {
            best[slot] = Some((v.nums, name));
        }
    }
    let [patch, minor, major] = best.map(|b| b.map(|(_, n)| n.clone()));
    Newest {
        patch,
        minor,
        major,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(t: &str) -> Version {
        match classify(t) {
            Kind::Fixed(v) => v,
            k => panic!("{t}: {k:?}"),
        }
    }
    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn floating_fixed_and_incomparable_tags() {
        for t in [
            "latest",
            "stable",
            "alpine",
            "1",
            "1.27",
            "17",
            "17-alpine",
            "1.27-alpine",
            "v1",
            "v1.2",
        ] {
            assert_eq!(classify(t), Kind::Floating, "{t}");
        }
        for t in [
            "1.27.3",
            "v2.5.0",
            "17.2.1-alpine",
            "1.2.3.4",
            "8.0.5_ubuntu",
            "2024.11.17",
        ] {
            assert!(matches!(classify(t), Kind::Fixed(_)), "{t}");
        }
        for t in [
            "20240101.1.2",
            "1.2.3-rc1",
            "1.2.3-beta.2",
            "1.2.3-RC",
            "1.2.3-nightly",
            "3e4f5a6",
            "a1b2c3d4e5f6",
            "1.2.3abc",
            "10000.1.2",
            "sha-abc123",
        ] {
            assert_eq!(classify(t), Kind::Incomparable, "{t}");
        }
    }

    #[test]
    fn patch_minor_and_major_are_reported_separately() {
        let cur = fixed("1.27.3");
        let all = tags(&[
            "1.27.3", "1.27.4", "1.27.10", "1.28.0", "1.28.2", "2.0.0", "2.1.5", "1.26.9",
            "latest", "1.27",
        ]);
        let n = newest(&cur, &all);
        assert_eq!(
            n,
            Newest {
                patch: Some("1.27.10".into()),
                minor: Some("1.28.2".into()),
                major: Some("2.1.5".into())
            }
        );
    }

    #[test]
    fn numeric_not_textual_order_and_nothing_newer_means_none() {
        let cur = fixed("1.9.0");
        assert_eq!(
            newest(&cur, &tags(&["1.10.0"])).minor.as_deref(),
            Some("1.10.0")
        );
        assert_eq!(
            newest(&fixed("2.0.0"), &tags(&["1.9.9", "2.0.0", "latest"])),
            Newest::default()
        );
    }

    #[test]
    fn prerelease_variant_and_prefix_are_respected() {
        let cur = fixed("17.2.1-alpine");
        let all = tags(&[
            "17.2.2",
            "17.2.2-alpine",
            "17.3.0-alpine3.20",
            "17.3.0-alpine",
            "17.4.0-rc1-alpine",
            "v17.9.0-alpine",
            "18.0.0-beta1-alpine",
        ]);
        let n = newest(&cur, &all);
        assert_eq!(
            (n.patch.as_deref(), n.minor.as_deref(), n.major.as_deref()),
            (Some("17.2.2-alpine"), Some("17.3.0-alpine"), None)
        );
        let v = fixed("v1.8.2");
        assert_eq!(
            newest(&v, &tags(&["1.9.0", "v1.9.0"])).minor.as_deref(),
            Some("v1.9.0")
        );
    }

    #[test]
    fn tags_with_a_different_number_of_parts_are_not_compared() {
        let cur = fixed("1.2.3");
        assert_eq!(
            newest(&cur, &tags(&["1.2.4.1", "1.3.0.0"])),
            Newest::default()
        );
    }
}
