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

export interface ListStats {
  /** CVEs der Liste, die mindestens einen Host betreffen. */
  affecting: number;
  /** Davon Level hoch oder kritisch (ab 8). */
  high: number;
  /** Davon mit Fix im Archiv (eine Quelle nennt für ein Release deiner Hosts eine Fix-Version). */
  withFix: number;
  /** Davon ohne Fix. */
  withoutFix: number;
}

/** Hat die CVE für ein Release auf den eigenen Hosts schon eine Fix-Version im Archiv? */
export function hasArchiveFix(c: Pick<CveListItem, "distros">): boolean {
  return c.distros.some((d) => d.mine && d.fix_version !== null && d.fix_version !== "");
}

/** Kennzahlen aus den geladenen Zeilen (keine eigene Abfrage); sie stimmen mit der Tabelle überein. */
export function listStats(rows: readonly CveListItem[]): ListStats {
  const aff = rows.filter((c) => affectedHosts(c) > 0);
  const withFix = aff.filter(hasArchiveFix).length;
  return { affecting: aff.length, high: aff.filter((c) => c.level >= 8).length, withFix, withoutFix: aff.length - withFix };
}

/** Namen für die Chips: höchstens `max`, der Rest als Zahl für „+N“ (aus den Zählern, nicht aus der Namensliste). */
export function hostChips(c: Pick<CveListItem, "hosts_vulnerable" | "hosts_fix_pending" | "hosts_reboot" | "affected_hosts">, max = 4): { names: string[]; more: number } {
  const names = (c.affected_hosts ?? []).slice(0, max);
  return { names, more: Math.max(0, affectedHosts(c) - names.length) };
}

/** Zustand der betroffenen Hosts einer CVE aus den Zählern der Zeile; `null`, wenn die Zeile mehrere Zustände mischt. */
export function hostState(c: Pick<CveListItem, "hosts_vulnerable" | "hosts_fix_pending" | "hosts_reboot">): { icon: "crit" | "warn" | "reboot"; tone: string; text: string } | null {
  const kinds = [c.hosts_vulnerable > 0, c.hosts_fix_pending > 0, c.hosts_reboot > 0].filter(Boolean).length;
  if (kinds !== 1) return null;
  if (c.hosts_vulnerable > 0) return { icon: "crit", tone: "text-crit", text: "verwundbar, Fix noch nicht installiert" };
  if (c.hosts_fix_pending > 0) return { icon: "warn", tone: "text-warn", text: "Fix angekündigt, noch nicht installiert" };
  return { icon: "reboot", tone: "text-warn", text: "Fix installiert, Neustart nötig" };
}

/** Kopfzeile: „5 betreffen deine Hosts · 5.723 insgesamt“ (bzw. „1 betrifft deine Hosts“). */
export function affectingShort(n: number): string {
  return n === 1 ? "1 betrifft deine Hosts" : `${n.toLocaleString("de-DE")} betreffen deine Hosts`;
}

/** Kennzahlen als Textstücke; Werte von 0 entfallen, bei lauter Nullen bleibt die Liste leer. */
export function statParts(s: { high: number; withFix: number; withoutFix: number }): string[] {
  const out: string[] = [];
  if (s.high > 0) out.push(`davon hoch/kritisch ${s.high.toLocaleString("de-DE")}`);
  if (s.withFix > 0) out.push(`${s.withFix.toLocaleString("de-DE")} mit Fix im Archiv`);
  if (s.withoutFix > 0) out.push(`${s.withoutFix.toLocaleString("de-DE")} ohne Fix`);
  return out;
}

/** Anzahl der Einstellungen im Filterfenster, die vom Standard abweichen (Suche und Watchlist-Stern zählen nicht mit). */
export function filterDeviations(f: { affectsAll: boolean; distro: string; debianFix: string; ubuntuFix: string }): number {
  return [f.affectsAll, f.distro !== "", f.debianFix !== "", f.ubuntuFix !== ""].filter(Boolean).length;
}
