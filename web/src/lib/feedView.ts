// Darstellung der Tabelle "CVE-Quellen": Fehlerzeile, Fehler-Chip und die neutralen Details (reine Logik, ohne React).

import { absTime } from "./format.ts";
import type { Feed, FeedBulk } from "./types.ts";
import type { StatusInfo } from "./status.ts";

/** Der Server hängt ", nächster Versuch in 12 Minuten" an Fehlertexte; der Zeitpunkt steht in der eigenen Spalte. */
export function stripNextAttempt(text: string): string {
  return text.replace(/,\s*nächster Versuch.*$/i, "").trim();
}

/** Fehlerzeile im Klartext (z. B. "Ubuntu meldet 503"), nie der Antwort-Inhalt; `null`, wenn es keinen Fehler gibt. */
export function errorLine(f: Pick<Feed, "last_error" | "error_text" | "failed_runs" | "consecutive_failures">): string | null {
  if (!f.last_error) return null;
  const text = stripNextAttempt(f.error_text ?? f.last_error);
  const n = f.failed_runs ?? f.consecutive_failures;
  return n > 1 ? `${text} (${n}× in Folge)` : text;
}

/** Chip für Quellen mit Fehler: ab drei Fehlläufen in Folge Fehler, davor Warnung (die Quelle versucht es weiter). */
export function errorChip(f: Pick<Feed, "last_error" | "failed_runs" | "consecutive_failures">): StatusInfo | null {
  if (!f.last_error) return null;
  const n = f.failed_runs ?? f.consecutive_failures;
  return n >= 3 ? { label: "Abruf fehlgeschlagen", tone: "crit", icon: "crit", rank: 0 } : { label: "Abruf gestört", tone: "warn", icon: "warn", rank: 1 };
}

export interface DetailLine {
  key: string;
  tone: "muted" | "warn";
  /** Release (wird als Code dargestellt), davor dem Text. */
  release?: string;
  text: string;
}

function size(bytes: number | null): string {
  if (bytes === null) return "";
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function join(parts: (string | false | null | undefined)[]): string {
  return parts.filter((p): p is string => typeof p === "string" && p !== "").join(" · ");
}

/** Importstand je Release und stündlicher Abruf als neutrale Zeilen. Der nächste Versuch steht nur in seiner Spalte. */
export function bulkLines(bulk: FeedBulk): DetailLine[] {
  const out: DetailLine[] = bulk.releases.map((r) => ({
    key: `rel-${r.release}`,
    tone: r.state === "ok" ? "muted" : "warn",
    release: r.release,
    text: join([
      stripNextAttempt(r.result_text),
      r.verified_at && `geprüft ${absTime(r.verified_at)}`,
      r.imported_at && `Import ${absTime(r.imported_at)}`,
      r.bytes !== null && size(r.bytes),
      r.status !== null && `Status ${r.status}`,
      r.retry_after_secs ? `Retry-After ${r.retry_after_secs} s` : "",
    ]),
  }));
  const h = bulk.hourly;
  out.push({
    key: "hourly",
    tone: h.failures > 0 ? "warn" : "muted",
    text: join([
      `Stündlicher Abruf: ${h.last_ok_at ? `zuletzt erfolgreich ${absTime(h.last_ok_at)}` : "noch nicht erfolgreich"}`,
      `Seitengröße ${h.page_size || "Standard"}${h.max_page ? ` (Maximum ${h.max_page})` : ""}`,
      h.status !== null && `Status ${h.status}`,
      h.retry_after_secs ? `Retry-After ${h.retry_after_secs} s` : "",
    ]),
  });
  if (h.error_text) out.push({ key: "hourly-err", tone: "warn", text: stripNextAttempt(h.error_text) });
  if (h.hint) out.push({ key: "hint", tone: "warn", text: h.hint });
  if (!bulk.complete) out.push({ key: "incomplete", tone: "warn", text: "Nicht vollständig: nicht für jedes relevante Release liegt ein gültiger, frischer Import vor." });
  return out;
}

/** Alle Detailzeilen einer Quelle; leer, wenn es nichts Neutrales zu zeigen gibt (dann bleibt die Zelle leer). */
export function detailLines(f: Pick<Feed, "backfill" | "bulk">): DetailLine[] {
  const out: DetailLine[] = [];
  if (f.backfill) out.push({ key: "backfill", tone: "warn", text: f.backfill.progress });
  if (f.bulk) out.push(...bulkLines(f.bulk));
  return out;
}

/** So viele Zeilen sind ohne Aufklappen sichtbar. */
export const VISIBLE_DETAIL_LINES = 2;
