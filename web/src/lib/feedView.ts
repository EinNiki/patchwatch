// Darstellung der Tabelle "CVE-Quellen": Fehlerzeile, Fehler-Chip und die neutralen Details (reine Logik, ohne React).

import { absTime } from "./format.ts";
import type { Feed, FeedBulk, FeedRunStats } from "./types.ts";
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

/** Dauer für Menschen: "0,4 s", "48 s", "2 Min. 5 s". */
export function duration(ms: number): string {
  const s = ms / 1000;
  if (s < 10) return `${s.toFixed(1).replace(/\.0$/, "").replace(".", ",")} s`;
  if (s < 120) return `${Math.round(s)} s`;
  const m = Math.floor(s / 60);
  return `${m} Min. ${Math.round(s - m * 60)} s`;
}

/** "0 B", "12 KB", "4,7 MB", "1,2 GB"; ab 100 MB ohne Nachkommastelle. */
export function byteSize(bytes: number): string {
  if (bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  const m = bytes / 1024 / 1024;
  if (m >= 1024) return `${(m / 1024).toFixed(1).replace(".", ",")} GB`;
  return m >= 100 || Number.isInteger(m) ? `${Math.round(m)} MB` : `${m.toFixed(1).replace(".", ",")} MB`;
}

const num = (n: number): string => n.toLocaleString("de-DE");

const PHASE_SHORT: [keyof NonNullable<FeedRunStats["last"]>["phases"], string][] = [
  ["connect", "Verbinden"],
  ["download", "Herunterladen"],
  ["parse", "Auswerten"],
  ["store", "Speichern"],
  ["evaluate", "Hosts bewerten"],
];

/** "Letzter Lauf: 48 s (Herunterladen 41 s · Auswerten 5 s · Speichern 2 s · 10 Seiten · 14,2 MB)"; Median in der Zeile darunter. */
export function runStatLines(stats: FeedRunStats | undefined, pages: boolean): DetailLine[] {
  const last = stats?.last;
  if (!stats || !last) return [];
  const parts: string[] = [];
  for (const [k, label] of PHASE_SHORT) {
    const ms = last.phases[k];
    if (ms !== undefined && ms >= 1000) parts.push(`${label} ${duration(ms)}`);
  }
  if (last.requests) parts.push(pages ? `${last.requests} ${last.requests === 1 ? "Seite" : "Seiten"}` : `${last.requests} ${last.requests === 1 ? "Anfrage" : "Anfragen"}`);
  if (last.page_size) parts.push(`Seitengröße ${last.page_size}`);
  if (last.retries) parts.push(`${last.retries} ${last.retries === 1 ? "Wiederholung" : "Wiederholungen"}`);
  if (last.wait_ms && last.wait_ms >= 1000) parts.push(`${duration(last.wait_ms)} Wartezeit`);
  const bad = last.status === "failed";
  const out: DetailLine[] = [{ key: "last-run", tone: bad ? "warn" : "muted", text: `Letzter Lauf${bad ? " (fehlgeschlagen)" : ""}: ${duration(last.total_ms)}${parts.length ? ` (${parts.join(" · ")})` : ""}` }];
  if (stats.median_ms !== null && stats.runs > 0) out.push({ key: "median", tone: "muted", text: `Median der letzten ${stats.runs} ${stats.runs === 1 ? "Laufs" : "Läufe"}: ${duration(stats.median_ms)}` });
  out.push(...transferLines(stats));
  return out;
}

/**
 * Übertragung, Datenbank und Platte je Lauf klar getrennt, dazu die Summe der letzten 24 Stunden.
 * Nur Zahlen; "Temporär auf Platte" ist immer 0 B, weil Downloads gestreamt werden und nie als Datei landen.
 */
export function transferLines(stats: FeedRunStats): DetailLine[] {
  const last = stats.last;
  if (!last) return [];
  const out: DetailLine[] = [];
  const unpacked = last.bytes_unpacked ?? 0;
  const wire = last.bytes_wire;
  if (wire === 0 && unpacked === 0 && (last.statuses["304"] ?? 0) > 0) {
    out.push({ key: "transfer", tone: "muted", text: "Unverändert (304), 0 B übertragen" });
  } else if (wire != null) {
    out.push({ key: "transfer", tone: "muted", text: `Übertragen ${byteSize(wire)} (entpackt ${byteSize(unpacked)})` });
  } else if (unpacked > 0) {
    out.push({ key: "transfer", tone: "muted", text: `Übertragen: nicht messbar (entpackt ${byteSize(unpacked)})` });
  }
  if (last.rows_written != null) {
    out.push({ key: "stored", tone: "muted", text: last.rows_written === 0 ? "Gespeichert in der Datenbank: keine Zeile geändert" : `Gespeichert in der Datenbank: +${num(last.rows_written)} ${last.rows_written === 1 ? "Zeile" : "Zeilen"} geändert` });
  }
  out.push({ key: "disk", tone: "muted", text: "Temporär auf Platte: 0 B" });
  const d = stats.day;
  if (d && d.runs > 0) {
    const bits = [`${d.runs} ${d.runs === 1 ? "Lauf" : "Läufe"}`];
    if (d.not_modified > 0) bits.push(`${d.not_modified}× unverändert (304)`);
    bits.push(`übertragen ${byteSize(d.bytes_wire)}${d.unmeasured > 0 ? ` (+ ${d.unmeasured} nicht messbar)` : ""}`);
    bits.push(`entpackt ${byteSize(d.bytes_unpacked)}`);
    bits.push(`${d.rows_written > 0 ? "+" : ""}${num(d.rows_written)} Zeilen`);
    out.push({ key: "day", tone: "muted", text: `Letzte 24 Stunden: ${bits.join(" · ")}` });
  }
  return out;
}

/** Alle Detailzeilen einer Quelle; leer, wenn es nichts Neutrales zu zeigen gibt (dann bleibt die Zelle leer). */
export function detailLines(f: Pick<Feed, "backfill" | "bulk"> & { run_stats?: FeedRunStats; type?: Feed["type"] }): DetailLine[] {
  const out: DetailLine[] = runStatLines(f.run_stats, f.type === "ubuntu");
  if (f.backfill) out.push({ key: "backfill", tone: "warn", text: f.backfill.progress });
  if (f.bulk) out.push(...bulkLines(f.bulk));
  return out;
}

/** So viele Zeilen sind ohne Aufklappen sichtbar. */
export const VISIBLE_DETAIL_LINES = 2;
