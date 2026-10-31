use crate::error::{ApiError, ApiResult};
use crate::extract::ClientIp;
use crate::hostops;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde::Deserialize;

pub const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_PACKAGES: usize = 30_000;

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
}

#[derive(Deserialize)]
struct ProxmoxIn {
    version: String,
}

#[derive(Deserialize)]
struct PackageIn {
    name: String,
    version: String,
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
    if r.schema_version != 1 {
        return Err(bad("nicht unterstützte schema_version"));
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
        {
            return Err(bad("ungültige Update-Zähler"));
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
            check_opt(&p.source, 128, NAME_CHARS, "Quellpaket")?;
            check_opt(&p.source_version, 128, VERSION_CHARS, "Quellversion")?;
        }
    }
    Ok(())
}

/// POST /api/v1/report: Authentifizierung per Bearer-Token (nur Hash in der DB), dann Validierung.
pub async fn post_report(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let host_id = super::agent::authenticate_host(&st, &ip, &headers, "report", 300).await?;

    let mut raw: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| bad("kein gültiges JSON"))?;
    let rep: ReportIn = serde_json::from_value(raw.clone())
        .map_err(|e| ApiError::BadRequest(format!("ungültiger Report: {e}")))?;
    validate(&rep)?;
    // Die Paketliste gehört nicht in die Historie.
    if let Some(o) = raw.as_object_mut() {
        o.remove("packages");
    }

    let now = Utc::now();
    let k = &rep.kernel;
    let (pkg, newest) = (
        k.running_package.as_ref(),
        k.newest_installed_package.as_ref(),
    );
    let reboot_needed = rep.reboot_required_file || k.reboot_needed_kernel == Some(true);
    let mut tx = st.pool.begin().await?;
    sqlx::query(
        "UPDATE hosts SET last_report_at = $2, hostname = $3, os_id = $4, os_version = $5, os_codename = $6, \
         pretty_name = $7, running_kernel = $8, kernel_package = $9, kernel_package_version = $10, \
         kernel_source = $11, kernel_source_version = $12, newest_kernel = $13, newest_kernel_version = $14, \
         reboot_needed_kernel = $15, reboot_required_file = $16, updates_pending = $17, updates_security = $18, \
         uptime_seconds = $19, is_proxmox = $20, proxmox_version = $21, agent_version = $22, last_checkin_at = $2, \
         report_requested_at = NULL, report_dispatched_at = NULL WHERE id = $1",
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
    .execute(&mut *tx)
    .await?;

    if let Some(pkgs) = &rep.packages {
        let col = |f: fn(&PackageIn) -> Option<&str>| {
            pkgs.iter()
                .map(|p| f(p).map(str::to_owned))
                .collect::<Vec<_>>()
        };
        sqlx::query(
            "INSERT INTO host_packages (host_id, name, version, source_name, source_version, last_seen) \
             SELECT $1, n, v, s, sv, $6 FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[]) AS t(n, v, s, sv) \
             ON CONFLICT (host_id, name) DO UPDATE SET version = EXCLUDED.version, \
               source_name = EXCLUDED.source_name, source_version = EXCLUDED.source_version, last_seen = EXCLUDED.last_seen",
        )
        .bind(host_id)
        .bind(pkgs.iter().map(|p| p.name.clone()).collect::<Vec<_>>())
        .bind(pkgs.iter().map(|p| p.version.clone()).collect::<Vec<_>>())
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
    Ok(StatusCode::NO_CONTENT)
}
