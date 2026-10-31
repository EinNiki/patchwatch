// Spiegel der JSON-Antworten der Rust-API (server/src/routes/*).

export type HostStatus =
  | "pending"
  | "stale"
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
}

export interface Cve {
  id: string;
  description: string | null;
  priority: string | null;
  published_at: string | null;
  updated_at: string;
  watched: boolean;
  note: string | null;
  hosts_vulnerable: number;
  hosts_fix_pending: number;
  hosts_unknown: number;
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
  last_change_at: string;
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
  feeds: { source: string; interval_minutes: number; default_minutes: number }[];
  feed_interval_min_minutes: number;
  feed_interval_max_minutes: number;
  report_schedule: ReportSchedule & { last_run: string | null; due_now: boolean };
  report_every_hours_min: number;
  report_every_hours_max: number;
  checkin_interval_hint: string;
}

export interface Feed {
  source: string;
  configured: boolean;
  interval_minutes: number;
  state: "ok" | "stale" | "never";
  healthy: boolean;
  last_attempt_at: string | null;
  last_success_at: string | null;
  stale_since: string | null;
  last_error: string | null;
  last_error_at: string | null;
  consecutive_failures: number;
}

export interface Me {
  username: string;
  csrf_token: string;
}

export interface NewHost {
  id: number;
  name: string;
  token: string;
}
