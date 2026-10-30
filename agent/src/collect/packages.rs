use crate::cmd::Runner;
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub source_version: Option<String>,
}

pub fn parse(out: &str) -> Vec<Package> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split('\t');
            let (name, version) = (it.next()?, it.next()?);
            let opt = |s: Option<&str>| s.filter(|v| !v.is_empty()).map(str::to_owned);
            (!name.is_empty() && !version.is_empty()).then(|| Package {
                name: name.to_owned(),
                version: version.to_owned(),
                source: opt(it.next()),
                source_version: opt(it.next()),
            })
        })
        .collect()
}

pub fn collect(r: &dyn Runner) -> Option<Vec<Package>> {
    let out = r.run(
        "dpkg-query",
        &[
            "-W",
            "-f",
            "${Package}\t${Version}\t${source:Package}\t${source:Version}\n",
        ],
    )?;
    Some(parse(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lines_and_skips_broken_ones() {
        let p = parse("bash\t5.2.21-2\tbash\t5.2.21-2\nbroken\n\tx\n");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "bash");
        assert_eq!(p[0].source.as_deref(), Some("bash"));
    }
}
