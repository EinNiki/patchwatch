// Reine Logik der CVE-Liste (URL-Parameter, Zähler); ohne React, damit sie mit node:test prüfbar ist.
import type { CveListItem } from "./types.ts";

export type CveSort = "hosts" | "latest" | "level" | "updated";
const SORTS: readonly string[] = ["hosts", "latest", "level", "updated"];

/** `?sort=`: ohne Angabe (oder bei Unsinn) gilt „betroffene Hosts zuerst“. */
export function parseSort(v: string | null): CveSort {
  return v !== null && SORTS.includes(v) ? (v as CveSort) : "hosts";
}

/** `?affects=`: „Meine Hosts“ ist der Standard, nur `all` zeigt alles. */
export function parseAffectsAll(v: string | null): boolean {
  return v === "all";
}

/** Anzahl der Hosts, die diese CVE betrifft: verwundbar, Fix angekündigt oder Neustart nötig („unbekannt“ zählt nicht). */
export function affectedHosts(c: Pick<CveListItem, "hosts_vulnerable" | "hosts_fix_pending" | "hosts_reboot">): number {
  return c.hosts_vulnerable + c.hosts_fix_pending + c.hosts_reboot;
}

/** „3 CVEs betreffen deine Hosts“ bzw. „1 CVE betrifft deine Hosts“. */
export function affectingLabel(n: number): string {
  return n === 1 ? "1 CVE betrifft deine Hosts" : `${n.toLocaleString("de-DE")} CVEs betreffen deine Hosts`;
}

/** Tooltip der Spalte „Aktualisiert“: Quelldatum und, getrennt davon, der letzte Abgleich (beide Europe/Berlin). */
export function updatedTitle(updatedAt: string | null, syncedAt: string | null, abs: (iso: string | null) => string): string {
  const src = updatedAt ? `Laut Quelle geändert: ${abs(updatedAt)}` : "Änderungsdatum: unbekannt (keine Quelle liefert eines)";
  return syncedAt ? `${src}\nZuletzt abgeglichen: ${abs(syncedAt)}` : src;
}
