import type { StatusInfo } from "./status";

export interface SoftwareFinding {
  id: string;
  status: string;
  source: string;
  fix_version: string | null;
  reason: string;
  url: string | null;
}

export interface SoftwareItem {
  id: string;
  host_id: number;
  host_name: string;
  name: string;
  version: string | null;
  ecosystem: string;
  source_name: string | null;
  source_version: string | null;
  last_seen: string;
  stale: boolean;
  candidate: string | null;
  security_update: boolean;
  status: string;
  reason: string;
  findings: SoftwareFinding[];
  inventory_id: number | null;
  context_label: string | null;
  context_kind: string | null;
  identity: string | null;
  purl: string | null;
  location: string | null;
  assessed_at: string | null;
}

export interface SoftwareResponse {
  items: SoftwareItem[];
  total: number;
  limit: number;
  offset: number;
  security_visible: boolean;
  hosts: { id: number; name: string; packages_reported_at: string | null; last_report_at: string | null }[];
}

export function softwareStatus(status: string): StatusInfo {
  if (status === "no_known_findings") return { label: "In OSV keine Treffer", icon: "unknown", tone: "unknown", rank: 2 };
  if (status === "vulnerable") return { label: "Verwundbar", icon: "crit", tone: "crit", rank: 0 };
  if (status === "known_fixed") return { label: "Bekannte Meldungen erledigt", icon: "ok", tone: "ok", rank: 2 };
  if (status === "fixed") return { label: "Fix installiert", icon: "ok", tone: "ok", rank: 2 };
  if (status === "not_affected") return { label: "Nicht betroffen", icon: "ok", tone: "ok", rank: 2 };
  return { label: "Nicht abschließend bewertet", icon: "unknown", tone: "unknown", rank: 1 };
}
