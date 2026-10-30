const rtf = new Intl.RelativeTimeFormat("de", { numeric: "auto" });

/** Relative Zeit auf Deutsch ("vor 3 Std."); der absolute Wert gehört in `title`/`dateTime`. */
export function relTime(iso: string | null, now = Date.now()): string {
  if (!iso) return "nie";
  const diff = (new Date(iso).getTime() - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 60) return "gerade eben";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  return rtf.format(Math.round(diff / 86400), "day");
}

const dtf = new Intl.DateTimeFormat("de-DE", { dateStyle: "medium", timeStyle: "short" });

export function absTime(iso: string | null): string {
  return iso ? dtf.format(new Date(iso)) : "–";
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
