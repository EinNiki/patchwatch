// Reine Logik der Host-Ansicht (Satz, Balken, Kacheln, Banner); keine React-Importe, damit sie mit node:test prüfbar ist.
import { clockTime as hhmm } from "./format.ts";
import type { Feed, HostCve, UpdateItem } from "./types.ts";

export interface StateCounts {
  open: number;
  reboot: number;
  fixed: number;
  unknown: number;
}

export type Tile = "open" | "reboot" | "fixed" | "unknown";

/** Erlaubte Werte von `?cve=`. "Nicht betroffen" gibt es in der Host-Ansicht nicht mehr (die API liefert es weiter). */
const TILES: readonly string[] = ["open", "reboot", "fixed", "unknown"];
/** Unbekannte oder entfernte Werte (auch "not_affected", "constructor") ergeben null = Standardansicht. */
export function parseCveFilter(v: string | null): Tile | null {
  return v !== null && TILES.includes(v) ? (v as Tile) : null;
}

/** Zähler aus der API-Antwort (`not_affected` wird hier bewusst nicht übernommen); `fix_pending` zählt zu "offen" (ein nur angekündigter Fix lässt den Host verwundbar). */
export function stateCounts(c: { vulnerable: number; fix_pending: number; fixed_installed_reboot_required: number; fixed: number; not_affected: number; unknown: number }): StateCounts {
  return { open: c.vulnerable + c.fix_pending, reboot: c.fixed_installed_reboot_required, fixed: c.fixed, unknown: c.unknown };
}

const n = (v: number) => String(v);
const cves = (v: number) => (v === 1 ? "1 CVE" : `${v} CVEs`);

/** Ein Satz als Entscheidungshilfe; richtet sich nach dem Zustand (kein Neustart nötig, alles gefixt, nur offen). */
export function summarySentence(c: StateCounts, opts: { newest: string | null; proxmox: boolean; restricted: boolean }): string {
  if (opts.proxmox) {
    return `Keine belastbare Quelle für Proxmox-Kernel: ${cves(c.unknown)} manuell zu prüfen.`;
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

/** Was die Quellen zum Fix sagen: veröffentlicht (Tracker führt eine Fix-Version), nur angekündigt (Tracker: „Fix in Arbeit“) oder nichts. */
export type FixKind = "released" | "announced" | "none";

export interface FixInfo {
  kind: FixKind;
  /** Fix-Version (bei „announced“: die voraussichtliche). */
  version: string | null;
  /** Quelle, die die Aussage macht (z. B. „ubuntu“). */
  source: string | null;
}

/**
 * Herkunft der Aussage: `sources` sind die Einträge der Tracker. „Veröffentlicht“ nur, wenn ein Eintrag eine Fix-Version
 * OHNE Status „fix_pending“ trägt. Gibt es nur angekündigte Einträge, ist der Fix nicht bestätigt, auch wenn apt auf dem
 * Host die Version schon anbietet (das ist eine zweite, zeitversetzte Quelle). Ohne `sources` gilt `fix_version` als veröffentlicht.
 */
export function fixInfo(c: Pick<HostCve, "status" | "fix_version" | "sources">): FixInfo {
  const list = c.sources ?? [];
  if (list.length === 0) return { kind: c.fix_version ? (c.status === "fix_pending" ? "announced" : "released") : "none", version: c.fix_version, source: null };
  const released = list.find((e) => e.fix_version && e.status !== "fix_pending");
  if (released) return { kind: "released", version: released.fix_version, source: released.source };
  const announced = list.find((e) => e.status === "fix_pending") ?? (c.status === "fix_pending" ? list[0] : undefined);
  if (announced) return { kind: "announced", version: announced.fix_version ?? c.fix_version, source: announced.source };
  return { kind: "none", version: null, source: null };
}

/** Status in Worten für die Offen-Tabelle (Icon kommt von der Komponente, nie nur Farbe). */
export function openStatusWord(c: Pick<HostCve, "status" | "fix_version"> & { sources?: HostCve["sources"] }): string {
  const k = fixInfo({ ...c, sources: c.sources ?? [] }).kind;
  if (c.status === "fix_pending" || k === "announced") return "Fix angekündigt";
  return k === "released" ? "Fix im Archiv" : "Kein Fix";
}

/** Kernel-Pakete des Hosts, für die apt genau die Fix-Version als Update anbietet (zweite Quelle neben dem Tracker). */
export function aptCandidate(items: readonly UpdateItem[] | null | undefined, version: string | null): UpdateItem | null {
  if (!version || !items) return null;
  return items.find((u) => /^linux(-|$)/.test(u.name) && u.to === version) ?? null;
}

const TRACKER: Record<string, string> = { ubuntu: "Ubuntus Tracker", debian: "Debians Tracker" };

/**
 * Text zu einem nur angekündigten Fix: beide Aussagen mit Herkunft, ehrlich zeitversetzt. `updates`: Paketliste des letzten
 * Reports (`null` = Agent schickt keine, `undefined` = noch nicht geladen).
 */
export function announcedText(info: FixInfo, updates: readonly UpdateItem[] | null | undefined): { lines: string[]; aptAvailable: boolean } {
  const v = info.version;
  const who = (info.source && TRACKER[info.source]) ?? "Der Tracker";
  const lines = [`${who} führt die CVE noch als „Fix in Arbeit“${v ? ` (voraussichtlich in ${v})` : ""}.`];
  const apt = aptCandidate(updates, v);
  if (apt) lines.push(`Auf diesem Host ist ${v} laut apt verfügbar (${apt.origin}).`);
  else if (v && updates) lines.push(`Laut den zuletzt gemeldeten Daten bietet apt auf diesem Host ${v} noch nicht an.`);
  lines.push("Beide Angaben können zeitversetzt sein. Als bestätigt gilt der Fix erst, wenn der Tracker ihn als veröffentlicht führt.");
  return { lines, aptAvailable: apt !== null };
}

export interface FeedNotice {
  /** Banner-Text oder null, wenn die zuständige Quelle nutzbar ist. */
  text: string | null;
  /** Offen-Zahl kann unvollständig sein. */
  restricted: boolean;
}


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
