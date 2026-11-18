//! Bounded extraction of inventory fields, not a full SBOM schema validator.
//! Missing identifiers remain visible and never become evidence of safety.
use packageurl::PackageUrl;
use serde_json::Value;
use std::collections::HashSet;

pub const MAX_COMPONENTS: usize = 5000;
pub const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct Component {
    pub reference: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub ecosystem: Option<String>,
    pub location: Option<String>,
}

pub struct Inventory {
    pub format: &'static str,
    pub spec_version: String,
    pub components: Vec<Component>,
}

pub fn text(value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err("Ein Textfeld ist leer, zu lang oder enthält Steuerzeichen.".into());
    }
    Ok(())
}

fn field(v: &Value, key: &str, max: usize) -> Result<Option<String>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            text(s, max)?;
            Ok(Some(s.clone()))
        }
        _ => Err(format!("{key} muss Text sein.")),
    }
}

/// Only these registry ecosystems can be queried without distribution context.
pub fn osv_ecosystem(ty: &str) -> Option<&'static str> {
    match ty {
        "npm" => Some("npm"),
        "cargo" => Some("crates.io"),
        "pypi" => Some("PyPI"),
        "maven" => Some("Maven"),
        "golang" => Some("Go"),
        "gem" => Some("RubyGems"),
        "nuget" => Some("NuGet"),
        "composer" => Some("Packagist"),
        _ => None,
    }
}

fn component(
    v: &Value,
    reference: String,
    purl: Option<String>,
    location: Option<String>,
) -> Result<Component, String> {
    text(&reference, 2048)?;
    let name = field(v, "name", 512)?.ok_or("Komponente ohne Namen.")?;
    let mut version = field(v, "version", 256)?;
    let mut ecosystem = None;
    let purl = match purl {
        Some(raw) => {
            text(&raw, 2048)?;
            let mut p: PackageUrl<'static> =
                raw.parse().map_err(|_| "Ungültige Package URL (PURL).")?;
            if let (Some(a), Some(b)) = (version.as_deref(), p.version()) {
                if a != b {
                    return Err(format!("Widersprüchliche Versionen bei {name}."));
                }
            }
            if version.is_none() {
                version = p.version().map(str::to_owned);
            }
            if p.version().is_none() {
                if let Some(ver) = version.as_deref() {
                    p.with_version(ver.to_owned())
                        .map_err(|_| "Ungültige PURL-Version.")?;
                }
            }
            ecosystem = Some(p.ty().to_owned());
            Some(p.to_string())
        }
        None => None,
    };
    if let Some(s) = &location {
        text(s, 2048)?;
    }
    Ok(Component {
        reference,
        name,
        version,
        purl,
        ecosystem,
        location,
    })
}

pub fn parse(bom: &Value) -> Result<Inventory, String> {
    let (format, spec_version, mut components) = if bom.get("bomFormat").and_then(Value::as_str)
        == Some("CycloneDX")
    {
        let spec = field(bom, "specVersion", 16)?.ok_or("CycloneDX specVersion fehlt.")?;
        if !["1.4", "1.5", "1.6", "1.7"].contains(&spec.as_str()) {
            return Err("Unterstützt werden CycloneDX JSON 1.4 bis 1.7.".into());
        }
        let mut out = Vec::new();
        let roots = bom
            .get("components")
            .map(|v| v.as_array().ok_or("components muss eine Liste sein."))
            .transpose()?;
        let mut pending: Vec<(&Value, String, usize)> = Vec::new();
        if let Some(root) = bom.pointer("/metadata/component") {
            pending.push((root, "root".into(), 0));
        }
        if let Some(roots) = roots {
            for (i, v) in roots.iter().enumerate() {
                pending.push((v, format!("components/{i}"), 0));
            }
        }
        while let Some((v, path, depth)) = pending.pop() {
            if out.len() >= MAX_COMPONENTS || depth > 32 {
                return Err("SBOM hat zu viele Komponenten oder ist zu tief verschachtelt.".into());
            }
            let reference =
                field(v, "bom-ref", 2048)?.unwrap_or_else(|| format!("patchwatch:{path}"));
            let location = v
                .pointer("/evidence/occurrences")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .map(|v| field(v, "location", 2048))
                .transpose()?
                .flatten();
            out.push(component(v, reference, field(v, "purl", 2048)?, location)?);
            if let Some(children) = v.get("components") {
                for (i, child) in children
                    .as_array()
                    .ok_or("components muss eine Liste sein.")?
                    .iter()
                    .enumerate()
                {
                    pending.push((child, format!("{path}/{i}"), depth + 1));
                }
                if pending.len() + out.len() > MAX_COMPONENTS {
                    return Err("SBOM enthält mehr als 5000 Komponenten.".into());
                }
            }
        }
        ("CycloneDX", spec, out)
    } else if let Some(spec) = bom.get("spdxVersion").and_then(Value::as_str) {
        if !["SPDX-2.2", "SPDX-2.3"].contains(&spec) {
            return Err("Unterstützt werden SPDX JSON 2.2 und 2.3.".into());
        }
        let packages = bom
            .get("packages")
            .and_then(Value::as_array)
            .ok_or("SPDX packages fehlt oder ist keine Liste.")?;
        if packages.len() > MAX_COMPONENTS {
            return Err("SBOM enthält mehr als 5000 Komponenten.".into());
        }
        let mut out = Vec::new();
        for v in packages {
            let reference = field(v, "SPDXID", 2048)?.ok_or("SPDX-Paket ohne SPDXID.")?;
            let mut purls = Vec::new();
            if let Some(refs) = v.get("externalRefs") {
                for r in refs
                    .as_array()
                    .ok_or("externalRefs muss eine Liste sein.")?
                {
                    if r.get("referenceType").and_then(Value::as_str) == Some("purl") {
                        purls.push(
                            field(r, "referenceLocator", 2048)?
                                .ok_or("PURL-Verweis ohne referenceLocator.")?,
                        );
                    }
                }
            }
            purls.sort();
            purls.dedup();
            if purls.len() > 1 {
                return Err(
                    "SPDX-Paket mit mehreren unterschiedlichen PURLs ist nicht eindeutig.".into(),
                );
            }
            let mut normalized = v.clone();
            normalized["version"] = v.get("versionInfo").cloned().unwrap_or(Value::Null);
            out.push(component(&normalized, reference, purls.pop(), None)?);
        }
        ("SPDX", spec.to_owned(), out)
    } else {
        return Err("Keine unterstützte CycloneDX- oder SPDX-JSON-Datei.".into());
    };
    let mut seen = HashSet::new();
    for c in &components {
        if !seen.insert(c.reference.clone()) {
            return Err("Komponentenreferenzen müssen innerhalb einer SBOM eindeutig sein.".into());
        }
    }
    components.sort_by(|a, b| a.reference.cmp(&b.reference));
    Ok(Inventory {
        format,
        spec_version,
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn nested_components_and_multiple_versions_survive() {
        let b = json!({"bomFormat":"CycloneDX","specVersion":"1.6","components":[
            {"bom-ref":"app","name":"app","components":[
                {"bom-ref":"one","name":"foo","version":"1","purl":"pkg:npm/foo@1"},
                {"bom-ref":"two","name":"foo","purl":"pkg:npm/foo@2"}]}]});
        let p = parse(&b).unwrap();
        assert_eq!(p.components.len(), 3);
        assert_eq!(p.components[2].version.as_deref(), Some("2"));
    }
    #[test]
    fn spdx_and_missing_identity_are_supported() {
        let b = json!({"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-A","name":"private-app"},
            {"SPDXID":"SPDXRef-B","name":"serde","versionInfo":"1.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/serde"}]}]});
        let p = parse(&b).unwrap();
        assert!(p.components[0].purl.is_none());
        assert_eq!(
            p.components[1].purl.as_deref(),
            Some("pkg:cargo/serde@1.0.0")
        );
    }
    #[test]
    fn rejects_ambiguous_or_malformed_components() {
        for c in [
            json!({"name":"x","version":"1","purl":"pkg:npm/x@2"}),
            json!({"name":"x\u{0000}"}),
            json!({"name":"x","purl":"https://example.org"}),
        ] {
            assert!(
                parse(&json!({"bomFormat":"CycloneDX","specVersion":"1.6","components":[c]}))
                    .is_err()
            );
        }
        assert!(parse(&json!({"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","bom-ref":"same"},{"name":"b","bom-ref":"same"}]})).is_err());
    }
}
