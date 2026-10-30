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
  const active = feeds.filter((f) => f.configured);
  if (active.length === 0) {
    return { info: { label: "", tone: "unknown", icon: "unknown", rank: 0 }, label: "Keine CVE-Quelle konfiguriert", ok: false };
  }
  const stale = active.filter((f) => f.state === "stale");
  const never = active.filter((f) => f.state === "never");
  if (stale.length > 0) {
    const f = stale[0]!;
    const since = f.stale_since ? ` seit ${absTime(f.stale_since)}` : "";
    return { info: { label: "", tone: "warn", icon: "clock", rank: 0 }, label: `CVE-Feed ${f.source} veraltet${since}`, ok: false };
  }
  if (never.length > 0) {
    return { info: { label: "", tone: "unknown", icon: "unknown", rank: 0 }, label: `CVE-Feed ${never[0]!.source} noch nie abgerufen`, ok: false };
  }
  return { info: FEED_OK, label: FEED_OK.label, ok: true };
}
