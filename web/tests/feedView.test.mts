import assert from "node:assert/strict";
import { test } from "node:test";
import { duration, runStatLines, detailLines, errorChip, errorLine, stripNextAttempt, VISIBLE_DETAIL_LINES } from "../src/lib/feedView.ts";
import type { Feed, FeedBulk } from "../src/lib/types.ts";

const bulk = (o: Partial<FeedBulk> = {}): FeedBulk => ({
  complete: true,
  bulk_interval_minutes: 1440,
  releases: [{ release: "resolute", state: "ok", result_text: "importiert", imported_at: "2026-11-07T14:36:00Z", verified_at: "2026-11-07T14:36:00Z", bytes: 4_700_000, records: 10, status: null, retry_after_secs: null, next_attempt_at: null, fresh_until: null }],
  hourly: { last_run_at: null, last_ok_at: "2026-11-07T20:57:00Z", page_size: 10, max_page: null, pages_last: 1, failures: 0, status: null, retry_after_secs: null, error_text: null, next_attempt_at: "2026-11-07T21:56:00Z", hint: null },
  ...o,
}) as FeedBulk;

test("the next attempt is stripped from error text (it has its own column)", () => {
  assert.equal(stripNextAttempt("Ubuntu meldet 503, nächster Versuch in 12 Minuten"), "Ubuntu meldet 503");
  assert.equal(stripNextAttempt("Ubuntu meldet 503, nächster Versuch gleich"), "Ubuntu meldet 503");
  assert.equal(stripNextAttempt("Ubuntu meldet 503"), "Ubuntu meldet 503");
});

test("error line only exists with an error and names the status in plain text", () => {
  const ok = { last_error: null, error_text: null, failed_runs: 0, consecutive_failures: 0 };
  assert.equal(errorLine(ok), null);
  assert.equal(errorChip(ok), null);
  const bad = { last_error: "HTTP 503", error_text: "Ubuntu meldet 503, nächster Versuch in 3 Minuten", failed_runs: 2, consecutive_failures: 2 };
  assert.equal(errorLine(bad), "Ubuntu meldet 503 (2× in Folge)");
  assert.equal(errorChip(bad)!.tone, "warn");
  assert.equal(errorChip({ ...bad, failed_runs: 3 })!.tone, "crit");
  assert.ok(!errorLine(bad)!.includes("Versuch"), "kein zweiter 'Nächster Versuch'");
});

test("details: neutral release and hourly lines, no next-attempt text, no placeholders", () => {
  const lines = detailLines({ backfill: null, bulk: bulk() });
  assert.equal(lines.length, 2);
  assert.equal(lines[0]!.release, "resolute");
  assert.ok(lines.every((l) => l.tone === "muted"));
  assert.ok(lines.every((l) => !/nächster Versuch/i.test(l.text) && l.text.trim() !== "–" && !l.text.includes("· ·")));
  assert.ok(lines.length <= VISIBLE_DETAIL_LINES, "ohne Fehler passt alles in die zwei sichtbaren Zeilen");
});

test("debian without extras has no details at all (empty cell)", () => {
  assert.deepEqual(detailLines({ backfill: null, bulk: null } as Pick<Feed, "backfill" | "bulk">), []);
});

test("problems in details are marked as warnings", () => {
  const lines = detailLines({ backfill: null, bulk: bulk({ complete: false, hourly: { ...bulk().hourly, failures: 3, error_text: "Ubuntu meldet 503, nächster Versuch in 5 Minuten" } }) });
  assert.ok(lines.length > VISIBLE_DETAIL_LINES);
  assert.ok(lines.some((l) => l.key === "hourly-err" && l.tone === "warn" && !/Versuch/.test(l.text)));
  assert.ok(lines.some((l) => l.key === "incomplete"));
});

const stats = (o = {}) => ({
  last: { status: "ok", total_ms: 48_000, phases: { connect: 300, download: 41_000, parse: 5000, store: 2000 }, requests: 10, retries: 0, wait_ms: 0, page_size: 10, bytes: 14_900_000, statuses: { "200": 10 }, ...o },
  median_ms: 52_000, phase_median_ms: { download: 40_000 }, runs: 10,
});

test("durations read naturally", () => {
  assert.equal(duration(400), "0,4 s");
  assert.equal(duration(48_000), "48 s");
  assert.equal(duration(125_000), "2 Min. 5 s");
});

test("last run line lists phases, pages and size; median follows", () => {
  const l = runStatLines(stats() as never, true);
  assert.equal(l[0]!.text, "Letzter Lauf: 48 s (Herunterladen 41 s · Auswerten 5 s · Speichern 2 s · 10 Seiten · Seitengröße 10 · 14,2 MB)");
  assert.equal(l[1]!.text, "Median der letzten 10 Läufe: 52 s");
  assert.deepEqual(runStatLines(undefined, true), []);
  assert.deepEqual(runStatLines({ last: null, median_ms: null, phase_median_ms: {}, runs: 0 }, true), []);
});

test("a failed last run is marked and waits and retries are shown", () => {
  const l = runStatLines(stats({ status: "failed", retries: 2, wait_ms: 15_000 }) as never, false);
  assert.equal(l[0]!.tone, "warn");
  assert.match(l[0]!.text, /fehlgeschlagen.*10 Anfragen.*2 Wiederholungen.*15 s Wartezeit/);
});
