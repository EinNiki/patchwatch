use crate::error::{ApiError, ApiResult};
use crate::extract::ClientIp;
use crate::hostops;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;

/// 20.000 Pakete mit langen Versionen passen unter 8 MiB (typisch ca. 135 Byte je Paket).
pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_PACKAGES: usize = 30_000;
const MAX_UPDATE_ITEMS: usize = 1000;

#[derive(Deserialize)]
struct ReportIn {
    schema_version: u32,
    agent_version: Option<String>,
    hostname: String,
    os: OsIn,
    kernel: KernelIn,
    #[serde(default)]
    reboot_required_file: bool,
    updates: Option<UpdatesIn>,
    uptime_seconds: Option<i64>,
    proxmox: Option<ProxmoxIn>,
    packages: Option<Vec<PackageIn>>,
    /// Schema 2: Hash der Paketliste des Agents (die Liste selbst fehlt, wenn sie unverändert ist).
    packages_hash: Option<String>,
    packages_count: Option<i32>,
    #[serde(default)]
    packages_truncated: bool,
    /// Schema 2: Unix-Sekunden der jüngsten apt-Paketliste des Hosts.
    apt_lists_updated_unix: Option<i64>,
}

#[derive(Deserialize)]
struct OsIn {
    id: String,
    version_id: Option<String>,
    codename: Option<String>,
    pretty_name: Option<String>,
}

#[derive(Deserialize)]
struct PkgInfoIn {
    name: String,
    version: String,
    source: Option<String>,
    source_version: Option<String>,
}

#[derive(Deserialize)]
struct KernelIn {
    running_release: String,
    running_package: Option<PkgInfoIn>,
    newest_installed_release: Option<String>,
    newest_installed_package: Option<PkgInfoIn>,
    reboot_needed_kernel: Option<bool>,
}

#[derive(Deserialize)]
struct UpdatesIn {
    pending: i32,
    security: i32,
    /// Schema 2: Pakete, die die Simulation entfernen würde.
    remove: Option<i32>,
    /// Offene Updates im Einzelnen (neuere Agents); fehlt bei älteren.
    items: Option<Vec<UpdateItemIn>>,
}

#[derive(Deserialize)]
struct UpdateItemIn {
    name: String,
    /// Schema 2: `upgrade`, `new` oder `remove`; fehlt bei Schema 1 (dann aus `from` abgeleitet).
    kind: Option<String>,
    from: Option<String>,
    /// Bei zu entfernenden Paketen leer.
    to: Option<String>,
    origin: String,
    security: bool,
}

impl UpdateItemIn {
    fn kind(&self) -> &str {
        self.kind.as_deref().unwrap_or(if self.from.is_some() {
            "upgrade"
        } else {
            "new"
        })
    }
}

#[derive(Deserialize)]
struct ProxmoxIn {
    version: String,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Clone))]
struct PackageIn {
    name: String,
    version: String,
    /// Schema 2: Architektur.
    arch: Option<String>,
    source: Option<String>,
    source_version: Option<String>,
}

fn bad(msg: &str) -> ApiError {
    ApiError::BadRequest(msg.to_owned())
}

fn check(s: &str, max: usize, extra: &str, what: &str) -> ApiResult<()> {
    let ok = !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c));
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!("ungültiger Wert für {what}")))
    }
}

fn check_opt(s: &Option<String>, max: usize, extra: &str, what: &str) -> ApiResult<()> {
    s.as_deref().map_or(Ok(()), |v| check(v, max, extra, what))
}

const VERSION_CHARS: &str = ".+~:-_";
const NAME_CHARS: &str = ".+-_:";

fn check_pkg(p: &PkgInfoIn) -> ApiResult<()> {
    check(&p.name, 128, NAME_CHARS, "Paketname")?;
    check(&p.version, 128, VERSION_CHARS, "Paketversion")?;
    check_opt(&p.source, 128, NAME_CHARS, "Quellpaket")?;
    check_opt(&p.source_version, 128, VERSION_CHARS, "Quellversion")
}

fn validate(r: &ReportIn) -> ApiResult<()> {
    if !(1..=2).contains(&r.schema_version) {
        return Err(bad("nicht unterstützte schema_version"));
    }
    if let Some(h) = &r.packages_hash {
        if h.len() != 64
            || !h
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad("ungültiger Wert für packages_hash"));
        }
    }
    if r.packages_count
        .is_some_and(|c| !(0..=1_000_000).contains(&c))
    {
        return Err(bad("ungültige Paketanzahl"));
    }
    if r.apt_lists_updated_unix
        .is_some_and(|t| !(0..=4_102_444_800).contains(&t))
    {
        return Err(bad("ungültiger Zeitpunkt der Paketlisten"));
    }
    check_opt(&r.agent_version, 32, ".+-", "agent_version")?;
    check(&r.hostname, 253, "._-", "hostname")?;
    check(&r.os.id, 32, "._-", "os.id")?;
    check_opt(&r.os.version_id, 32, "._-", "os.version_id")?;
    check_opt(&r.os.codename, 32, "._-", "os.codename")?;
    if let Some(p) = &r.os.pretty_name {
        if p.len() > 128 || p.chars().any(char::is_control) {
            return Err(bad("ungültiger Wert für os.pretty_name"));
        }
    }
    check(
        &r.kernel.running_release,
        128,
        VERSION_CHARS,
        "kernel.running_release",
    )?;
    check_opt(
        &r.kernel.newest_installed_release,
        128,
        VERSION_CHARS,
        "kernel.newest_installed_release",
    )?;
    for p in [
        &r.kernel.running_package,
        &r.kernel.newest_installed_package,
    ]
    .into_iter()
    .flatten()
    {
        check_pkg(p)?;
    }
    if let Some(u) = &r.updates {
        if !(0..=100_000).contains(&u.pending)
            || !(0..=100_000).contains(&u.security)
            || u.security > u.pending
            || u.remove.is_some_and(|n| !(0..=100_000).contains(&n))
        {
            return Err(bad("ungültige Update-Zähler"));
        }
    }
    if let Some(items) = r.updates.as_ref().and_then(|u| u.items.as_ref()) {
        if items.len() > MAX_UPDATE_ITEMS {
            return Err(bad("zu viele Update-Einträge"));
        }
        for i in items {
            check(&i.name, 128, NAME_CHARS, "Update-Paketname")?;
            check_opt(&i.from, 128, VERSION_CHARS, "Update-Version")?;
            check_opt(&i.to, 128, VERSION_CHARS, "Update-Version")?;
            if !["upgrade", "new", "remove"].contains(&i.kind()) {
                return Err(bad("ungültige Update-Art"));
            }
            if i.kind() != "remove" && i.to.is_none() {
                return Err(bad("Update ohne verfügbare Version"));
            }
            if i.origin.len() > 200 || i.origin.chars().any(char::is_control) {
                return Err(bad("ungültige Update-Herkunft"));
            }
        }
    }
    if r.uptime_seconds.is_some_and(|u| u < 0) {
        return Err(bad("ungültige Uptime"));
    }
    if let Some(p) = &r.proxmox {
        check(&p.version, 64, ".+~-", "proxmox.version")?;
    }
    if let Some(pkgs) = &r.packages {
        if pkgs.len() > MAX_PACKAGES {
            return Err(bad("zu viele Pakete"));
        }
        for p in pkgs {
            check(&p.name, 128, NAME_CHARS, "Paketname")?;
            check(&p.version, 128, VERSION_CHARS, "Paketversion")?;
            check_opt(&p.arch, 32, "-_", "Architektur")?;
            check_opt(&p.source, 128, NAME_CHARS, "Quellpaket")?;
            check_opt(&p.source_version, 128, VERSION_CHARS, "Quellversion")?;
        }
    }
    Ok(())
}

/// Höchstgröße des Report-Rests ohne Paketliste (gespeichert in `reports.raw`).
const MAX_RAW_BYTES: usize = 64 * 1024;

/// Enthält ein Text oder ein Schlüssel im JSON-Wert ein NUL-Zeichen?
fn json_has_nul(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => super::has_nul(s),
        serde_json::Value::Array(a) => a.iter().any(json_has_nul),
        serde_json::Value::Object(o) => o.iter().any(|(k, v)| super::has_nul(k) || json_has_nul(v)),
        _ => false,
    }
}

/// Ordering key that makes ties deterministic and independent of the order in the report.
fn pkg_key(p: &PackageIn) -> (&str, &str, &str) {
    (
        p.version.as_str(),
        p.source.as_deref().unwrap_or(""),
        p.source_version.as_deref().unwrap_or(""),
    )
}

/// Does `new` replace `old` when two entries share one package name? Conservative on purpose: the host counts as
/// affected if ANY installed copy is affected, so the LOWER dpkg version wins. A version dpkg rules cannot parse
/// wins over a parsable one (it ends up as "unknown", never as "fixed"). Ties and two unparsable versions are
/// resolved by text, so the result does not depend on the order of the report.
fn replaces(old: &PackageIn, new: &PackageIn) -> bool {
    let parsable = |p: &PackageIn| debversion::compare(&p.version, &p.version).is_ok();
    match (parsable(old), parsable(new)) {
        (true, false) => return true,
        (false, true) => return false,
        (false, false) => return pkg_key(new) < pkg_key(old),
        (true, true) => {}
    }
    match debversion::compare(&old.version, &new.version) {
        Ok(std::cmp::Ordering::Greater) => true,
        Ok(std::cmp::Ordering::Less) => false,
        _ => pkg_key(new) < pkg_key(old),
    }
}

/// One entry per package name; for duplicates (same name on several architectures) the lowest version.
fn merge_duplicate_packages(all: &[PackageIn]) -> Vec<&PackageIn> {
    let mut best: std::collections::BTreeMap<&str, &PackageIn> = Default::default();
    for p in all {
        match best.entry(p.name.as_str()) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(p);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                if replaces(e.get(), p) {
                    e.insert(p);
                }
            }
        }
    }
    best.into_values().collect()
}

/// POST /api/v1/report: Authentifizierung per Bearer-Token (nur Hash in der DB), dann Validierung.
pub async fn post_report(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let host_id = super::agent::authenticate_host(&st, &ip, &headers, "report", 300).await?;

    let mut raw: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| bad("kein gültiges JSON"))?;
    let rep: ReportIn = serde_json::from_value(raw.clone())
        .map_err(|e| ApiError::BadRequest(format!("ungültiger Report: {e}")))?;
    validate(&rep)?;
    // Die Paketliste gehört nicht in die Historie.
    if let Some(o) = raw.as_object_mut() {
        o.remove("packages");
        if let Some(u) = o.get_mut("updates").and_then(|u| u.as_object_mut()) {
            u.remove("items");
        }
    }
    // Der Rest (auch unbekannte Felder) landet als jsonb in `reports.raw`: NUL würde dort einen Datenbankfehler (500)
    // auslösen, und beliebig große Zusatzfelder blähen die Historie auf.
    if json_has_nul(&raw) {
        return Err(bad("ungültige Zeichen im Report"));
    }
    if raw.to_string().len() > MAX_RAW_BYTES {
        return Err(bad("Report enthält zu viele Zusatzdaten"));
    }
    let now = Utc::now();
    let k = &rep.kernel;
    let (pkg, newest) = (
        k.running_package.as_ref(),
        k.newest_installed_package.as_ref(),
    );
    let reboot_needed = rep.reboot_required_file || k.reboot_needed_kernel == Some(true);
    let mut tx = st.pool.begin().await?;
    // Hat der Agent nur den Hash geschickt, der Server aber einen anderen Stand (oder keinen), fehlt die Liste hier:
    // der Agent soll sie beim nächsten Report mitsenden (z. B. nach einer Datenbank-Wiederherstellung).
    let stored_hash: Option<String> =
        sqlx::query_scalar("SELECT packages_hash FROM hosts WHERE id = $1 FOR UPDATE")
            .bind(host_id)
            .fetch_one(&mut *tx)
            .await?;
    let need_packages =
        rep.packages.is_none() && rep.packages_hash.is_some() && stored_hash != rep.packages_hash;
    sqlx::query(
        "UPDATE hosts SET last_report_at = $2, hostname = $3, os_id = $4, os_version = $5, os_codename = $6, \
         pretty_name = $7, running_kernel = $8, kernel_package = $9, kernel_package_version = $10, \
         kernel_source = $11, kernel_source_version = $12, newest_kernel = $13, newest_kernel_version = $14, \
         reboot_needed_kernel = $15, reboot_required_file = $16, updates_pending = $17, updates_security = $18, \
         uptime_seconds = $19, is_proxmox = $20, proxmox_version = $21, agent_version = $22, last_checkin_at = $2, updates_listed = $23, \
         updates_remove = $24, apt_lists_updated_at = to_timestamp($25), \
         report_requested_at = CASE WHEN $26 THEN $2 ELSE NULL END, report_dispatched_at = NULL WHERE id = $1",
    )
    .bind(host_id)
    .bind(now)
    .bind(&rep.hostname)
    .bind(&rep.os.id)
    .bind(&rep.os.version_id)
    .bind(&rep.os.codename)
    .bind(&rep.os.pretty_name)
    .bind(&k.running_release)
    .bind(pkg.map(|p| &p.name))
    .bind(pkg.map(|p| &p.version))
    .bind(pkg.and_then(|p| p.source.as_ref()))
    .bind(pkg.and_then(|p| p.source_version.as_ref()))
    .bind(&k.newest_installed_release)
    .bind(newest.map(|p| &p.version))
    .bind(k.reboot_needed_kernel)
    .bind(rep.reboot_required_file)
    .bind(rep.updates.as_ref().map(|u| u.pending))
    .bind(rep.updates.as_ref().map(|u| u.security))
    .bind(rep.uptime_seconds)
    .bind(rep.proxmox.is_some())
    .bind(rep.proxmox.as_ref().map(|p| &p.version))
    .bind(&rep.agent_version)
    .bind(rep.updates.as_ref().is_some_and(|u| u.items.is_some()))
    .bind(rep.updates.as_ref().and_then(|u| u.remove))
    .bind(rep.apt_lists_updated_unix.map(|t| t as f64))
    .bind(need_packages)
    .execute(&mut *tx)
    .await?;
    store_updates(
        &mut tx,
        host_id,
        rep.updates.as_ref().and_then(|u| u.items.as_deref()),
        now,
    )
    .await?;

    if let Some(all_pkgs) = &rep.packages {
        // Multiarch hosts list one name once per architecture (the agent omits it, and the key is (host_id, name)).
        // ON CONFLICT cannot touch a row twice (SQLSTATE 21000), so exactly one entry per name is kept; the rule
        // never lets a vulnerable version disappear (see `merge_duplicate_packages`).
        let pkgs = merge_duplicate_packages(all_pkgs);
        let col = |f: fn(&PackageIn) -> Option<&str>| {
            pkgs.iter()
                .map(|p| f(p).map(str::to_owned))
                .collect::<Vec<_>>()
        };
        sqlx::query(
            "INSERT INTO host_packages (host_id, name, version, arch, source_name, source_version, first_seen, last_seen) \
             SELECT $1, n, v, a, s, sv, $7, $7 FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) \
               AS t(n, v, a, s, sv) \
             ON CONFLICT (host_id, name) DO UPDATE SET version = EXCLUDED.version, arch = EXCLUDED.arch, \
               source_name = EXCLUDED.source_name, source_version = EXCLUDED.source_version, \
               first_seen = COALESCE(host_packages.first_seen, EXCLUDED.first_seen), last_seen = EXCLUDED.last_seen",
        )
        .bind(host_id)
        .bind(pkgs.iter().map(|p| p.name.clone()).collect::<Vec<_>>())
        .bind(pkgs.iter().map(|p| p.version.clone()).collect::<Vec<_>>())
        .bind(col(|p| p.arch.as_deref()))
        .bind(col(|p| p.source.as_deref()))
        .bind(col(|p| p.source_version.as_deref()))
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM host_packages WHERE host_id = $1 AND last_seen < $2")
            .bind(host_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE hosts SET packages_hash = $2, packages_count = $3, packages_truncated = $4, \
             packages_updated_at = $5 WHERE id = $1",
        )
        .bind(host_id)
        .bind(&rep.packages_hash)
        .bind(rep.packages_count.unwrap_or(all_pkgs.len() as i32))
        .bind(rep.packages_truncated)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    let stale_after = crate::schedule::stale_after(&st.pool, st.cfg.stale_after_hours).await;
    let status = hostops::recompute_host(&mut tx, host_id, stale_after, now).await?;
    sqlx::query(
        "INSERT INTO reports (host_id, received_at, running_kernel, updates_pending, updates_security, reboot_needed, status, raw) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(host_id)
    .bind(now)
    .bind(&k.running_release)
    .bind(rep.updates.as_ref().map(|u| u.pending))
    .bind(rep.updates.as_ref().map(|u| u.security))
    .bind(reboot_needed)
    .bind(status.as_str())
    .bind(&raw)
    .execute(&mut *tx)
    .await?;
    crate::live::notify(&mut tx, "report_received", Some(host_id), None).await;
    tx.commit().await?;
    // Kernel kann sich geändert haben: CVE-Bewertung neu berechnen. Ein Fehler hier lässt den Report nicht scheitern.
    if let Err(e) = crate::cve::reeval::evaluate_host(&st.pool, host_id, stale_after).await {
        tracing::error!(host = host_id, error = %e, "CVE-Bewertung nach Report fehlgeschlagen");
    }
    if need_packages {
        return Ok(Json(serde_json::json!({ "need_packages": true })).into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Ausstehende Updates des Hosts auf den Stand des Reports bringen (erste Sichtung bleibt erhalten, Verschwundenes
/// entfällt). Ohne Liste (älterer Agent) gibt es keine Zeilen.
async fn store_updates(
    tx: &mut sqlx::PgConnection,
    host_id: i64,
    items: Option<&[UpdateItemIn]>,
    now: chrono::DateTime<Utc>,
) -> ApiResult<()> {
    let Some(items) = items else {
        sqlx::query("DELETE FROM host_updates WHERE host_id = $1")
            .bind(host_id)
            .execute(&mut *tx)
            .await?;
        return Ok(());
    };
    // Ein Name steht höchstens einmal in der Liste (sonst Fehler 21000 beim Upsert): der erste Eintrag gilt.
    let mut seen = std::collections::HashSet::new();
    let items: Vec<&UpdateItemIn> = items
        .iter()
        .filter(|i| seen.insert(i.name.as_str()))
        .collect();
    sqlx::query(
        "INSERT INTO host_updates (host_id, name, kind, installed, candidate, origin, security, first_seen, last_seen) \
         SELECT $1, n, k, i, c, o, s, $8, $8 \
         FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::bool[]) AS t(n, k, i, c, o, s) \
         ON CONFLICT (host_id, name) DO UPDATE SET kind = EXCLUDED.kind, installed = EXCLUDED.installed, \
           candidate = EXCLUDED.candidate, origin = EXCLUDED.origin, security = EXCLUDED.security, \
           last_seen = EXCLUDED.last_seen",
    )
    .bind(host_id)
    .bind(items.iter().map(|i| i.name.clone()).collect::<Vec<_>>())
    .bind(items.iter().map(|i| i.kind().to_owned()).collect::<Vec<_>>())
    .bind(items.iter().map(|i| i.from.clone()).collect::<Vec<_>>())
    .bind(items.iter().map(|i| i.to.clone()).collect::<Vec<_>>())
    .bind(items.iter().map(|i| i.origin.clone()).collect::<Vec<_>>())
    .bind(items.iter().map(|i| i.security).collect::<Vec<_>>())
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM host_updates WHERE host_id = $1 AND last_seen < $2")
        .bind(host_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    fn p(name: &str, version: &str) -> PackageIn {
        PackageIn {
            name: name.into(),
            version: version.into(),
            arch: None,
            source: None,
            source_version: None,
        }
    }
    fn merged(v: &[PackageIn]) -> Vec<(String, String)> {
        merge_duplicate_packages(v)
            .into_iter()
            .map(|x| (x.name.clone(), x.version.clone()))
            .collect()
    }
    fn one(v: &[PackageIn]) -> String {
        let m = merged(v);
        assert_eq!(m.len(), 1);
        m[0].1.clone()
    }

    #[test]
    fn same_version_twice_stays_one_entry() {
        assert_eq!(one(&[p("libc6", "2.36-9"), p("libc6", "2.36-9")]), "2.36-9");
    }

    #[test]
    fn lower_version_wins_in_any_order() {
        let (lo, hi) = (p("libc6", "2.36-9"), p("libc6", "2.36-10"));
        assert_eq!(one(&[lo.clone(), hi.clone()]), "2.36-9");
        assert_eq!(one(&[hi, lo]), "2.36-9");
    }

    #[test]
    fn epoch_and_tilde_follow_dpkg_rules_not_text() {
        // 1:2.0 is NEWER than 2.0 (epoch), so 2.0 is the lower one.
        assert_eq!(one(&[p("x", "1:2.0"), p("x", "2.0")]), "2.0");
        assert_eq!(one(&[p("x", "2.0"), p("x", "1:2.0")]), "2.0");
        // 1.0~rc1 sorts BEFORE 1.0.
        assert_eq!(one(&[p("x", "1.0"), p("x", "1.0~rc1")]), "1.0~rc1");
        assert_eq!(one(&[p("x", "1.0~rc1"), p("x", "1.0")]), "1.0~rc1");
        // 10 > 9 numerically although "10" < "9" as text.
        assert_eq!(one(&[p("x", "10"), p("x", "9")]), "9");
    }

    #[test]
    fn three_entries_keep_the_lowest_and_other_names_stay() {
        let v = [p("a", "3.0"), p("b", "1.0"), p("a", "1.0"), p("a", "2.0")];
        let m = merged(&v);
        assert_eq!(
            m,
            vec![("a".into(), "1.0".into()), ("b".into(), "1.0".into())]
        );
        let mut r: Vec<PackageIn> = v.iter().cloned().rev().collect();
        assert_eq!(merged(&r), m);
        r.rotate_left(1);
        assert_eq!(merged(&r), m);
    }

    #[test]
    fn unparsable_and_empty_versions_never_hide_behind_a_fixed_one() {
        // An empty or malformed version cannot be compared: it is kept, so the host ends up "unknown", not "fixed".
        assert_eq!(one(&[p("x", "1.0"), p("x", "")]), "");
        assert_eq!(one(&[p("x", ""), p("x", "1.0")]), "");
        assert_eq!(one(&[p("x", "1.0"), p("x", "!!")]), "!!");
        // Two unparsable ones: deterministic by text.
        assert_eq!(one(&[p("x", "!!"), p("x", "##")]), "!!");
        assert_eq!(one(&[p("x", "##"), p("x", "!!")]), "!!");
    }

    #[test]
    fn very_long_versions_are_compared_without_panic() {
        let long = format!("1.{}", "9".repeat(4000));
        let longer = format!("1.{}", "9".repeat(4001));
        let r = one(&[p("x", &longer), p("x", &long)]);
        assert!(r == long || r == longer);
    }

    #[test]
    fn ties_with_different_source_are_deterministic() {
        let mut a = p("x", "1.0");
        a.source = Some("src-b".into());
        let mut b = p("x", "1.0");
        b.source = Some("src-a".into());
        let m1 = merge_duplicate_packages(&[a.clone(), b.clone()])[0]
            .source
            .clone();
        let m2 = merge_duplicate_packages(&[b, a])[0].source.clone();
        assert_eq!(m1, m2);
    }
}
