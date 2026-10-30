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

export interface Feed {
  source: string;
  configured: boolean;
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
