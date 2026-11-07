const rtf = new Intl.RelativeTimeFormat("de", { numeric: "auto" });

/** Alle Zeiten erscheinen in dieser Zeitzone, unabhängig von Server (UTC) und Browser. */
export const TIME_ZONE = "Europe/Berlin";

const ymd = new Intl.DateTimeFormat("en-CA", { timeZone: TIME_ZONE, year: "numeric", month: "2-digit", day: "2-digit" });
/** Fortlaufende Tagesnummer des Berliner Kalendertags (Sommerzeitwechsel haben 23 oder 25 Stunden, der Tag zählt trotzdem 1). */
function berlinDay(ms: number): number {
  const [y, m, d] = ymd.format(ms).split("-").map(Number) as [number, number, number];
  return Math.round(Date.UTC(y, m - 1, d) / 86_400_000);
}

/** Relative Zeit auf Deutsch ("vor 3 Std."); der absolute Wert gehört in `title`/`dateTime`. Tage zählen als Berliner Kalendertage. */
export function relTime(iso: string | null, now = Date.now()): string {
  if (!iso) return "nie";
  const then = new Date(iso).getTime();
  const diff = (then - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 60) return "gerade eben";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  return rtf.format(berlinDay(then) - berlinDay(now), "day");
}

const dtf = new Intl.DateTimeFormat("de-DE", { dateStyle: "medium", timeStyle: "short", timeZone: TIME_ZONE });

/** Absolute Zeit in Europe/Berlin, z. B. "06.11.2026, 22:27". */
export function absTime(iso: string | null): string {
  return iso ? dtf.format(new Date(iso)) : "–";
}

const clock = new Intl.DateTimeFormat("de-DE", { hour: "2-digit", minute: "2-digit", timeZone: TIME_ZONE });
/** Uhrzeit in Europe/Berlin, z. B. "22:27". */
export function clockTime(iso: string): string {
  return clock.format(new Date(iso));
}

const dayMonth = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit", timeZone: TIME_ZONE });
/** Kurzes Datum mit Uhrzeit in Europe/Berlin, z. B. "06.11. 22:27". */
export function shortDateTime(ms: number): string {
  return `${dayMonth.format(ms)} ${clock.format(ms)}`;
}

/** Bootzeit = Reportzeit minus gemeldete Uptime (ms); `null`, wenn eine der Angaben fehlt oder unsinnig ist. */
export function bootTime(lastReportAt: string | null, uptimeSeconds: number | null): number | null {
  if (!lastReportAt || uptimeSeconds == null || !Number.isFinite(uptimeSeconds) || uptimeSeconds < 0) return null;
  const t = new Date(lastReportAt).getTime();
  return Number.isNaN(t) ? null : t - uptimeSeconds * 1000;
}

/** Aktuelle Uptime in Sekunden, aus der Bootzeit abgeleitet (nicht der beim Report gemeldete Wert). */
export function liveUptimeSeconds(lastReportAt: string | null, uptimeSeconds: number | null, now = Date.now()): number | null {
  const boot = bootTime(lastReportAt, uptimeSeconds);
  return boot === null ? null : Math.max(0, Math.floor((now - boot) / 1000));
}

/** "gestartet 06.11. 22:27" oder `null`. */
export function bootLabel(lastReportAt: string | null, uptimeSeconds: number | null): string | null {
  const boot = bootTime(lastReportAt, uptimeSeconds);
  return boot === null ? null : `gestartet ${shortDateTime(boot)}`;
}

export function uptime(seconds: number | null): string {
  if (seconds == null) return "–";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d} Tg. ${h} Std.`;
  if (h > 0) return `${h} Std. ${m} Min.`;
  return `${m} Min.`;
}

/** Kernel-Release ohne Variante, z. B. "6.8.0-31-generic" -> "6.8.0-31". */
export function kernelBase(release: string | null): string {
  if (!release) return "–";
  const m = /^(\d+\.\d+\.\d+(?:-\d+)?)/.exec(release);
  return m?.[1] ?? release;
}
