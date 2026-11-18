//! Software findings describe installed packages, not the code running in a process.
//! No matching advisory is not evidence that a component is safe.
use crate::cve::eval::{CveStatus, SourceRow, Verdict};
use crate::cve::SourceStatus;
use debversion::Version;
use serde_json::json;

pub fn evaluate(version: Option<&str>, row: &SourceRow) -> Verdict {
    let sources = vec![json!({"source": row.source, "release": row.release,
        "package": row.package, "fix_version": row.fix_version})];
    let result = match row.status {
        SourceStatus::NotAffected => (CveStatus::NotAffected, "Laut Quelle nicht betroffen.".into()),
        SourceStatus::Vulnerable => (CveStatus::Vulnerable, "Laut Quelle betroffen; kein Fix veröffentlicht.".into()),
        SourceStatus::FixPending => (CveStatus::Vulnerable, "Betroffen; der angekündigte Fix ist noch nicht veröffentlicht.".into()),
        SourceStatus::Unknown => (CveStatus::Unknown, "Die Quelle hat das Paket noch nicht abschließend bewertet.".into()),
        SourceStatus::Fixed => match (
            version.and_then(|v| v.parse::<Version>().ok()),
            row.fix_version.as_deref().and_then(|v| v.parse::<Version>().ok()),
        ) {
            (Some(installed), Some(fix)) if installed >= fix => (CveStatus::Fixed,
                format!("Fix ab {fix}; Quellpaketversion {installed} ist installiert. Laufende Prozesse wurden nicht geprüft.")),
            (Some(installed), Some(fix)) => (CveStatus::Vulnerable,
                format!("Fix ab {fix}; installierte Quellpaketversion {installed} ist älter.")),
            _ => (CveStatus::Unknown, "Quellpaketversion oder Fix-Version fehlt oder ist ungültig.".into()),
        },
    };
    Verdict {
        status: result.0,
        reason: result.1,
        sources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(status: SourceStatus, fix: Option<&str>) -> SourceRow {
        SourceRow {
            source: "debian".into(),
            release: "trixie".into(),
            package: "nginx".into(),
            status,
            fix_version: fix.map(str::to_owned),
        }
    }

    #[test]
    fn respects_distribution_backports_and_epochs() {
        let r = row(SourceStatus::Fixed, Some("1:1.24.0-2+deb13u2"));
        assert_eq!(
            evaluate(Some("1:1.24.0-2+deb13u1"), &r).status,
            CveStatus::Vulnerable
        );
        assert_eq!(
            evaluate(Some("1:1.24.0-2+deb13u2"), &r).status,
            CveStatus::Fixed
        );
        assert_eq!(evaluate(Some("1.99.0-1"), &r).status, CveStatus::Vulnerable);
    }

    #[test]
    fn missing_versions_never_prove_a_fix() {
        assert_eq!(
            evaluate(None, &row(SourceStatus::Fixed, Some("2"))).status,
            CveStatus::Unknown
        );
        assert_eq!(
            evaluate(Some("2"), &row(SourceStatus::Fixed, None)).status,
            CveStatus::Unknown
        );
        assert_eq!(
            evaluate(Some("999"), &row(SourceStatus::FixPending, Some("2"))).status,
            CveStatus::Vulnerable
        );
    }
}
