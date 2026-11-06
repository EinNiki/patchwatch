import { absTime } from "@/lib/format";
import type { StatusInfo } from "@/lib/status";
import type { Feed } from "@/lib/types";

export const FEED_OK: StatusInfo = { label: "CVE-Feeds aktuell", tone: "ok", icon: "ok", rank: 0 };

/**
 * Gesamtzustand der CVE-Feeds. Ein Feed ist nur "aktuell", wenn der letzte Abruf erfolgreich war;
 * veraltete oder nie abgerufene Feeds sind nie grün (DESIGN.md).
 */
export function feedSummary(feeds: Feed[] | undefined): { info: StatusInfo; label: string; ok: boolean } | null {
  if (!feeds) return null;
  const active = feeds.filter((f) => f.enabled);
  if (active.length === 0) {
    return { info: { label: "", tone: "unknown", icon: "unknown", rank: 0 }, label: feeds.length ? "Alle CVE-Quellen abgeschaltet" : "Keine CVE-Quelle konfiguriert", ok: false };
  }
  const disabled = feeds.filter((f) => !f.enabled);
  const stale = active.filter((f) => f.state === "stale");
  const never = active.filter((f) => f.state === "never");
  const incomplete = active.filter((f) => f.state === "incomplete");
  if (incomplete.length > 0 && stale.length === 0) {
    const f = incomplete[0]!;
    return { info: { label: "", tone: "warn", icon: "clock", rank: 0 }, label: `CVE-Feed ${f.label} unvollständig: ${f.backfill?.progress ?? "Abruf läuft noch"}`, ok: false };
  }
  if (stale.length > 0) {
    const f = stale[0]!;
    const since = f.stale_since ? ` seit ${absTime(f.stale_since)}` : "";
    return { info: { label: "", tone: "warn", icon: "clock", rank: 0 }, label: `CVE-Feed ${f.label} veraltet${since}`, ok: false };
  }
  if (never.length > 0) {
    return { info: { label: "", tone: "unknown", icon: "unknown", rank: 0 }, label: `CVE-Feed ${never[0]!.label} noch nie abgerufen`, ok: false };
  }
  // Eine abgeschaltete Quelle ist nie grün: die Daten dieser Quelle fehlen in der Bewertung.
  if (disabled.length > 0) {
    return { info: { label: "", tone: "unknown", icon: "unknown", rank: 0 }, label: `CVE-Quelle ${disabled[0]!.label} abgeschaltet`, ok: false };
  }
  return { info: FEED_OK, label: FEED_OK.label, ok: true };
}
