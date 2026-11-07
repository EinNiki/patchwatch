// Spiegel der JSON-Antworten der Rust-API (server/src/routes/*).

export type HostStatus =
  | "pending"
  | "stale"
  | "cve_unknown"
  | "cve_vulnerable"
  | "security_updates"
  | "reboot_required"
  | "updates_pending"
  | "ok";

export type CveStatus =
  | "fixed"
  | "fixed_installed_reboot_required"
  | "vulnerable"
  | "fix_pending"
  | "not_affected"
  | "unknown";

export interface Host {
  /** Begründung für „CVE-Lage unbekannt“ wegen unvollständiger/veralteter/fehlerhafter Quelle. */
  cve_source_issue?: string | null;
  id: number;
  name: string;
  hostname: string | null;
  os_id: string | null;
  os_version: string | null;
  os_codename: string | null;
  pretty_name: string | null;
  running_kernel: string | null;
  kernel_package: string | null;
  kernel_package_version: string | null;
  newest_kernel: string | null;
  newest_kernel_version: string | null;
  reboot_needed_kernel: boolean | null;
  reboot_required_file: boolean | null;
  reboot_needed: boolean;
  updates_pending: number | null;
  updates_security: number | null;
  uptime_seconds: number | null;
  is_proxmox: boolean;
  proxmox_version: string | null;
  status: HostStatus;
  status_changed_at: string | null;
  last_report_at: string | null;
  created_at: string;
  agent_version: string | null;
  last_checkin_at: string | null;
  report_requested_at: string | null;
  cve_vulnerable: number;
  cve_fix_pending: number;
  cve_unknown: number;
  cve_reboot: number;
  cve_fixed: number;
}

export interface HistoryRow {
  id: number;
  received_at: string;
  running_kernel: string | null;
  updates_pending: number | null;
  updates_security: number | null;
  reboot_needed: boolean;
  status: HostStatus;
}

export interface SourceEntry {
  source: string;
  release: string;
  package: string;
  status: string;
  fix_version: string | null;
}

export interface HostCve {
  cve_id: string;
  status: CveStatus;
  reason: string;
  computed_at: string;
  sources: SourceEntry[];
  description: string | null;
  priority: string | null;
  watched: boolean;
  reviewed_at: string | null;
  reviewed_by: string | null;
  /** Priorität als Stufe 0–10 (0 = unbekannt). */
  level: number;
  /** Fix-Version und Name der zuständigen Quelle. */
  fix_version: string | null;
  source: string | null;
  /** Seit wann die CVE öffentlich bekannt ist. */
  published_at: string | null;
}

export interface CveGroup {
  /** `null`: Eintrag ohne Fix-Version. */
  fix_version: string | null;
  count: number;
}

export interface HostCveGroupsResponse {
  groups: CveGroup[];
  total: number;
}

export interface HostCvesResponse {
  items: HostCve[];
  /** Treffer für den aktuellen Filter (ohne Seitenbegrenzung). */
  total: number;
  /** Zähler je Zustand für den ganzen Host (unabhängig von Filter und Suche). */
  counts: Record<CveStatus, number>;
  /** Offene CVEs, für die eine Quelle bereits eine Fix-Version kennt (im Archiv, nicht installiert). */
  open_with_fix: number;
  /** Warum die Bewertung eingeschränkt ist (Quelle unvollständig/veraltet), sonst null. */
  issue: string | null;
  host: {
    is_proxmox: boolean;
    running_kernel: string | null;
    running_kernel_version: string | null;
    newest_kernel: string | null;
    newest_kernel_version: string | null;
    reboot_needed: boolean;
  };
}

export interface Cve {
  id: string;
  description: string | null;
  priority: string | null;
  /** Priorität als Stufe 0–10 (0 = unbekannt). */
  level: number;
  published_at: string | null;
  /** Letzte Änderung laut Quelle; `null` = keine Quelle liefert ein Datum (nie der Importzeitpunkt). */
  updated_at: string | null;
  /** Zuletzt mit einer Quelle abgeglichen. */
  last_synced_at: string | null;
  watched: boolean;
  note: string | null;
  /** In der CISA-KEV-Liste (aktiv ausgenutzt). */
  exploited: boolean;
  hosts_vulnerable: number;
  hosts_fix_pending: number;
  /** Fix installiert, läuft erst nach dem Neustart. */
  hosts_reboot: number;
  hosts_unknown: number;
  /** Namen betroffener Hosts (höchstens 6, nur in der Liste); die Gesamtzahl steht in den `hosts_*`-Zählern. */
  affected_hosts?: string[];
}

/** Ein Chip je (Quelle, Release): ungünstigster Status über alle Pakete. */
export interface Distro {
  source: string;
  release: string;
  status: string;
  package: string;
  fix_version: string | null;
  updated_at: string;
  mine: boolean;
  packages: number;
  /** Debian: Status und Version je Suite (`trixie`, `trixie-security`); null, wenn noch nicht importiert. */
  suites: Record<string, { version: string; status: string }> | null;
}

export interface CveListItem extends Cve {
  distros: Distro[];
  /** Releases, die wegen „nur meine Releases“ nicht in `distros` stehen. */
  hidden_releases: number;
}

export interface CveSourceRow {
  source: string;
  release: string;
  package: string;
  status: string;
  fix_version: string | null;
  updated_at: string;
}

export interface CveDetail {
  cve: Cve;
  sources: CveSourceRow[];
  distros: Distro[];
  links: { source: string; url: string }[];
  last_change_at: string | null;
  last_synced_at: string | null;
  hosts: { id: number; name: string; os_codename: string | null; status: CveStatus; reason: string }[];
}

export interface ChannelView {
  kind: string;
  enabled: boolean;
  from_env: boolean;
  config: Record<string, string>;
  secret_set: boolean;
  events: string[];
  summary_time: string | null;
  timezone: string | null;
  last_error: string | null;
  last_ok_at: string | null;
}

export interface NotificationsResponse {
  secret_storage: boolean;
  events: string[];
  channels: ChannelView[];
}

export type ReportSchedule =
  | { mode: "off" }
  | { mode: "interval"; every_hours: number }
  | { mode: "daily"; at: string; tz: string };

export interface Settings {
  report_retention_days: number;
  report_retention_default_days: number;
  report_retention_min_days: number;
  report_retention_max_days: number;
  stale_after_hours: number;
  stale_after_default_hours: number;
  stale_after_min_hours: number;
  stale_after_max_hours: number;
  feeds: { source: string; label: string; interval_minutes: number; default_minutes: number; bulk_interval_minutes: number | null; bulk_default_minutes: number | null }[];
  feed_interval_min_minutes: number;
  feed_interval_max_minutes: number;
  report_schedule: ReportSchedule & { last_run: string | null; due_now: boolean; next_run: string | null };
  report_every_hours_min: number;
  report_every_hours_max: number;
  checkin_interval_hint: string;
}

export interface Feed {
  /** Stabile ID (nicht der Anzeigename). */
  source: string;
  type: "debian" | "ubuntu" | "osv" | "nvd" | "cisa_kev";
  /** Anzeigename, frei wählbar; immer als Text ausgeben. */
  label: string;
  ecosystem: string | null;
  takes_ecosystem: boolean;
  kind: "builtin" | "managed";
  enabled: boolean;
  /** Alt-Feld: eingeschaltet. */
  configured: boolean;
  enrich_only: boolean;
  takes_secret: boolean;
  takes_base_url: boolean;
  secret_set: boolean;
  base_url: string | null;
  interval_minutes: number;
  state: "ok" | "stale" | "incomplete" | "never" | "disabled";
  healthy: boolean;
  last_attempt_at: string | null;
  last_success_at: string | null;
  stale_since: string | null;
  last_error: string | null;
  last_error_at: string | null;
  consecutive_failures: number;
  /** Fehlläufe in Folge, Zeitpunkt des nächsten Versuchs und der Fehler als verständlicher Text. */
  failed_runs?: number;
  next_attempt_at?: string | null;
  error_text?: string | null;
  /** Nur bei state "incomplete": Fortschritt des Rückstandsabbaus. */
  backfill: { pages_done: number; runs: number; next_offset: number; pages_per_run: number | null; since: string; progress: string; initial?: boolean; position_pages?: number; est_pages?: number | null; target?: string } | null;
  /** Nur Ubuntu im Hybridmodus: Massendaten je Release und stündlicher Abruf. */
  bulk?: FeedBulk | null;
  /** Letzter Lauf und Mediane der letzten zehn (nur Zahlen). */
  run_stats?: FeedRunStats;
}

export interface FeedRunStats {
  last: {
    status: string;
    total_ms: number;
    phases: Partial<Record<"connect" | "download" | "parse" | "store" | "evaluate", number>>;
    requests: number | null;
    retries: number | null;
    wait_ms: number | null;
    page_size: number | null;
    bytes: number;
    statuses: Record<string, number>;
  } | null;
  median_ms: number | null;
  phase_median_ms: Record<string, number>;
  runs: number;
}

export interface FeedBulkRelease {
  release: string;
  state: "ok" | "error" | "stale" | "pending";
  result_text: string;
  imported_at: string | null;
  verified_at: string | null;
  bytes: number | null;
  records: number | null;
  status: number | null;
  retry_after_secs: number | null;
  next_attempt_at: string | null;
  fresh_until: string | null;
}

export interface FeedBulk {
  complete: boolean;
  bulk_interval_minutes: number;
  releases: FeedBulkRelease[];
  hourly: {
    last_run_at: string | null;
    last_ok_at: string | null;
    page_size: number;
    max_page: number | null;
    pages_last: number;
    failures: number;
    status: number | null;
    retry_after_secs: number | null;
    error_text: string | null;
    next_attempt_at: string | null;
    hint: string | null;
  };
}

export interface Me {
  username: string;
  csrf_token: string;
  /** Start-Passwort (erzeugt oder früherer Standardwert): bis zum Wechsel ist nur der Passwortwechsel möglich. */
  must_change_password?: boolean;
  /** Zeitstempel (Sekunden) des eigenen Profilbilds; `null` = Kreis mit Initialen. Dient als Cache-Schlüssel. */
  avatar?: number | null;
}

export interface NewHost {
  id: number;
  name: string;
  token: string;
}

/** Ein offenes Paket-Update aus dem Report des Agents. */
export interface UpdateItem {
  name: string;
  /** Installierte Version; fehlt bei neu hinzukommenden Paketen. */
  from: string | null;
  to: string;
  origin: string;
  security: boolean;
}
