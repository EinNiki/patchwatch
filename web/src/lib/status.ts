import type { CveStatus, HostStatus } from "./types";

export type Tone = "ok" | "warn" | "crit" | "unknown";
export type IconName = "ok" | "warn" | "crit" | "unknown" | "reboot" | "clock" | "pending";

export interface StatusInfo {
  label: string;
  tone: Tone;
  icon: IconName;
  /** Sortierung: kleiner = dringlicher. */
  rank: number;
}

/** Zuordnung gemäß DESIGN.md. Unbekannt ist nie "ok". */
export const HOST_STATUS: Record<HostStatus, StatusInfo> = {
  cve_vulnerable: { label: "Verwundbar (CVE)", tone: "crit", icon: "crit", rank: 0 },
  security_updates: { label: "Sicherheitsupdates offen", tone: "crit", icon: "crit", rank: 1 },
  cve_unknown: { label: "CVE-Lage unbekannt", tone: "unknown", icon: "unknown", rank: 1.5 },
  stale: { label: "Meldet sich nicht", tone: "unknown", icon: "clock", rank: 2 },
  reboot_required: { label: "Neustart nötig", tone: "warn", icon: "reboot", rank: 3 },
  updates_pending: { label: "Updates offen", tone: "warn", icon: "warn", rank: 4 },
  pending: { label: "Noch keine Daten", tone: "unknown", icon: "pending", rank: 5 },
  ok: { label: "Aktuell", tone: "ok", icon: "ok", rank: 6 },
};

export const CVE_STATUS: Record<CveStatus, StatusInfo> = {
  vulnerable: { label: "Verwundbar", tone: "crit", icon: "crit", rank: 0 },
  fixed_installed_reboot_required: { label: "Gefixt installiert, Neustart nötig", tone: "warn", icon: "reboot", rank: 1 },
  fix_pending: { label: "Fix angekündigt", tone: "warn", icon: "warn", rank: 2 },
  unknown: { label: "Unbekannt", tone: "unknown", icon: "unknown", rank: 3 },
  fixed: { label: "Behoben", tone: "ok", icon: "ok", rank: 4 },
  not_affected: { label: "Nicht betroffen", tone: "ok", icon: "ok", rank: 5 },
};

export const TONE_CLASS: Record<Tone, string> = {
  ok: "bg-ok-soft text-ok",
  warn: "bg-warn-soft text-warn",
  crit: "bg-crit-soft text-crit",
  unknown: "bg-unknown-soft text-unknown",
};

export const HOST_STATUS_ORDER = Object.keys(HOST_STATUS) as HostStatus[];
