// Reine Logik der Host-Ansicht (Satz, Balken, Kacheln, Banner); keine React-Importe, damit sie mit node:test prüfbar ist.
import type { Feed, HostCve } from "./types.ts";

export interface StateCounts {
  open: number;
  reboot: number;
  fixed: number;
  notAffected: number;
  unknown: number;
}

export type Tile = "open" | "reboot" | "fixed" | "not_affected" | "unknown";

/** Zähler aus der API-Antwort; `fix_pending` zählt zu "offen" (ein nur angekündigter Fix lässt den Host verwundbar). */
export function stateCounts(c: { vulnerable: number; fix_pending: number; fixed_installed_reboot_required: number; fixed: number; not_affected: number; unknown: number }): StateCounts {
  return { open: c.vulnerable + c.fix_pending, reboot: c.fixed_installed_reboot_required, fixed: c.fixed, notAffected: c.not_affected, unknown: c.unknown };
}

const n = (v: number) => String(v);
const cves = (v: number) => (v === 1 ? "1 CVE" : `${v} CVEs`);

/** Ein Satz als Entscheidungshilfe; richtet sich nach dem Zustand (kein Neustart nötig, alles gefixt, nur offen). */
export function summarySentence(c: StateCounts, opts: { newest: string | null; proxmox: boolean; restricted: boolean }): string {
  if (opts.proxmox) {
    return `Keine belastbare Quelle für Proxmox-Kernel: ${cves(c.unknown)} unbekannt, manuell prüfen.`;
  }
  const maybe = opts.restricted ? " (kann unvollständig sein)" : "";
  if (c.reboot > 0) {
    const target = opts.newest ? ` auf ${opts.newest}` : "";
    const rest = c.open > 0 ? `sind noch ${cves(c.open)} offen${maybe}` : opts.restricted ? "sind keine offenen CVEs bekannt (Quelle unvollständig)" : "sind keine CVEs offen";
    return `Nach dem Neustart${target} ${rest}, ${n(c.reboot)} ${c.reboot === 1 ? "wird" : "werden"} behoben.`;
  }
  if (c.open > 0) return `${cves(c.open)} offen${maybe}, kein Fix installiert.`;
  return opts.restricted ? "Keine offenen CVEs bekannt, aber die Quelle ist unvollständig." : "Keine offenen CVEs.";
}

export interface Segment {
  tile: Tile;
  count: number;
  /** Anteil in Prozent; jedes nicht leere Segment ist mindestens 1 % breit, damit es sichtbar bleibt. */
  pct: number;
}

/** Gestapelter Balken aus allen Zuständen; Summe der Breiten ist 100. */
export function barSegments(c: StateCounts): Segment[] {
  const parts: [Tile, number][] = [
    ["open", c.open],
    ["reboot", c.reboot],
    ["fixed", c.fixed],
    ["not_affected", c.notAffected],
    ["unknown", c.unknown],
  ];
  const total = parts.reduce((s, p) => s + p[1], 0);
  if (total === 0) return [];
  const raw = parts.filter((p) => p[1] > 0).map(([tile, count]) => ({ tile, count, pct: Math.max(1, (count / total) * 100) }));
  const sum = raw.reduce((s, p) => s + p.pct, 0);
  return raw.map((p) => ({ ...p, pct: (p.pct / sum) * 100 }));
}

/** Zeile zum Kernel: läuft, neuester installiert, Neustart nötig. */
export function kernelLine(running: string | null, newest: string | null, reboot: boolean): string {
  return `Läuft ${running ?? "–"} · Neuester installiert ${newest ?? "–"}${reboot ? " · Neustart nötig" : ""}`;
}

/** Status in Worten für die Offen-Tabelle (Icon kommt von der Komponente, nie nur Farbe). */
export function openStatusWord(c: Pick<HostCve, "status" | "fix_version">): string {
  if (c.status === "fix_pending") return "Fix angekündigt";
  return c.fix_version ? "Fix im Archiv" : "Kein Fix";
}

export interface FeedNotice {
  /** Banner-Text oder null, wenn die zuständige Quelle nutzbar ist. */
  text: string | null;
  /** Offen-Zahl kann unvollständig sein. */
  restricted: boolean;
}

const hhmm = (iso: string) => new Date(iso).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });

/** Banner nur, wenn die für den Host zuständige Quelle eingeschränkt ist (nicht bei beliebigen anderen Feeds). */
export function feedNotice(feeds: Feed[] | undefined, osId: string | null, codename: string | null, issue: string | null): FeedNotice {
  const feed = feeds?.find((f) => f.enabled && f.type === osId) ?? null;
  const restrictedFeed = feed !== null && feed.state !== "ok" && feed.state !== "disabled";
  if (!restrictedFeed && !issue) return { text: null, restricted: false };
  const name = feed?.label ?? (osId === "ubuntu" ? "Ubuntu" : osId === "debian" ? "Debian" : "Quelle");
  const since = feed?.stale_since ?? feed?.last_error_at ?? feed?.backfill?.since ?? null;
  const why = !feed
    ? "Quelle nicht nutzbar"
    : feed.state === "incomplete"
      ? "Abruf läuft noch"
      : feed.state === "never"
        ? "noch nie abgerufen"
        : feed.consecutive_failures > 0 || feed.last_error
          ? "API überlastet"
          : "veraltet";
  const when = since ? `, seit ${hhmm(since)}` : "";
  const bulkOk = Boolean(codename && feed?.bulk?.releases.some((r) => r.release === codename && r.state === "ok"));
  const tail = bulkOk
    ? "Gefixt-Angaben stammen aus den Massendaten und sind belastbar. "
    : "Auch Gefixt-Angaben können fehlen oder veraltet sein. ";
  return {
    text: `${name}: Offene Fälle nicht vollständig geladen (${why}${when}). ${tail}Die Zahl „Offen“ kann unvollständig sein.`,
    restricted: true,
  };
}

/** Level (0–10) in Worten; Mindeststufen für den Filter stehen in `LEVEL_FILTERS`. */
export function levelWord(level: number): string {
  if (level >= 10) return "Kritisch";
  if (level >= 8) return "Hoch";
  if (level >= 5) return "Mittel";
  if (level >= 3) return "Niedrig";
  return level > 0 ? "Minimal" : "Unbekannt";
}

export const LEVEL_FILTERS: { min: number; label: string }[] = [
  { min: 0, label: "Alle Level" },
  { min: 8, label: "Hoch und kritisch" },
  { min: 5, label: "Mittel und höher" },
];

/** Gruppenüberschrift: "Behoben in 7.0.0-42.42: 1.204 CVEs". */
export function groupTitle(fix: string | null, count: number): string {
  const num = count.toLocaleString("de-DE");
  return `${fix ? `Behoben in ${fix}` : "Ohne Fix-Version"}: ${num} ${count === 1 ? "CVE" : "CVEs"}`;
}

/** Kurzbeschreibung: der immer gleiche Kernel-Vorspann der Quellen trägt keine Information und verdrängt den Kern der Zeile. */
export function shortText(text: string | null): string {
  if (!text) return "";
  return text.replace(/^In the Linux kernel, the following vulnerability has been resolved:\s*/i, "").trim() || text;
}
