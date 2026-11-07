import assert from "node:assert/strict";
import { test } from "node:test";
import { detailLines, errorChip, errorLine, stripNextAttempt, VISIBLE_DETAIL_LINES } from "../src/lib/feedView.ts";
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
