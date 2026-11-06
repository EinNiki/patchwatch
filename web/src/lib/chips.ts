// Reine Logik der CVE-Chips (ohne JSX, damit sie mit `npm test` geprüft werden kann).
import type { IconName, Tone } from "./status.ts";
import { absTime } from "./format.ts";
import type { Distro } from "./types.ts";

const DISTRO_NAME: Record<string, string> = { debian: "Debian", ubuntu: "Ubuntu", osv: "OSV" };
export const distroName = (source: string): string => DISTRO_NAME[source] ?? source;

export const STATUS: Record<string, { word: string; tone: Tone; icon: IconName; muted?: boolean }> = {
  fixed: { word: "gefixt", tone: "ok", icon: "ok" },
  not_affected: { word: "nicht betroffen", tone: "ok", icon: "ok", muted: true },
  fix_pending: { word: "verwundbar, Fix in Arbeit", tone: "crit", icon: "crit" },
  vulnerable: { word: "verwundbar", tone: "crit", icon: "crit" },
  unknown: { word: "unbekannt", tone: "unknown", icon: "unknown" },
};

/** Suite-Angaben eines Debian-Chips: Archiv und Security getrennt, wenn sie sich unterscheiden. */
export interface SuitePart {
  /** `Security`, `Archiv` oder leer (beide gleich). */
  label: string;
  status: string;
  version: string | null;
}

/** Debian-Releases ohne Security-Suite (Testing/Unstable). */
const NO_SECURITY = new Set(["sid", "forky", "unstable", "testing", "experimental"]);

/**
 * Teile des Debian-Chips: je Suite Status und Version. Sind beide Suiten gleich, steht eine Angabe; fehlt die
 * Security-Suite in den Daten, steht „Security: unbekannt“ (nie stillschweigend die Archivangabe). `null` für andere Quellen.
 */
export function suiteParts(d: Distro): SuitePart[] | null {
  if (d.source !== "debian" || NO_SECURITY.has(d.release)) return null;
  const arc = d.suites?.[d.release];
  const sec = d.suites?.[`${d.release}-security`];
  const ver = (x: { version: string; status: string }) => (x.status === "fixed" ? (d.fix_version ?? x.version) : x.status === "not_affected" ? null : x.version);
  if (!sec) {
    const parts: SuitePart[] = [{ label: "Security", status: "unbekannt", version: null }];
    if (arc) parts.push({ label: "Archiv", status: arc.status, version: ver(arc) });
    return parts;
  }
  if (!arc || arc.status === sec.status) return [{ label: "", status: sec.status, version: ver(sec) }];
  return [
    { label: "Security", status: sec.status, version: ver(sec) },
    { label: "Archiv", status: arc.status, version: ver(arc) },
  ];
}

/** Tooltip eines Chips (Klartext; ohne Umfangs-Wörter, die Umfangs-Kennzeichnung ist der gestrichelte Rand). */
export function chipTitle(d: Distro, allScope: boolean): string {
  const s = STATUS[d.status] ?? STATUS.unknown!;
  const parts = suiteParts(d);
  const detail = parts
    ? parts.map((p) => `${p.label ? p.label + " " : ""}${SUITE_WORD[p.status] ?? p.status}${p.version ? ` ${p.version}` : ""}`).join(", ")
    : `${s.word}${d.fix_version ? ` ab ${d.fix_version}` : ""}`;
  const outside = !allScope && !d.mine;
  return `${distroName(d.source)} ${d.release}: ${detail} (Paket ${d.package}${d.packages > 1 ? ` und ${d.packages - 1} weitere` : ""}, Stand ${absTime(d.updated_at)})${
    outside ? ". Läuft auf keinem deiner Hosts" : ""
  }`;
}

export const SUITE_WORD: Record<string, string> = { fixed: "gefixt", vulnerable: "verwundbar", not_affected: "nicht betroffen", unknown: "unbekannt" };
