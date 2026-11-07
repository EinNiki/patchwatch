import assert from "node:assert/strict";
import { test } from "node:test";
import { applyLive, isHung, isSlow, phaseElapsedMs, latestBySource, progress, runText, runningSince, stepStates, summary, type FeedRun } from "../src/lib/feedRuns.ts";

const run = (o: Partial<FeedRun> = {}): FeedRun => ({
  id: 1, source: "debian", trigger: "manual", started_by: "admin", status: "running", phase: "download",
  created_at: "2026-11-07T10:00:00Z", started_at: null, finished_at: null, bytes: 0, items: null, hosts: null, error: null, phases: {}, ...o,
});

test("running: earlier steps done, current active, later pending", () => {
  assert.deepEqual(stepStates(run({ phase: "parse" })), ["done", "done", "active", "pending", "pending", "pending"]);
});

test("failure marks the phase where it happened, later steps stay pending", () => {
  assert.deepEqual(stepStates(run({ status: "failed", phase: "download" })), ["done", "failed", "pending", "pending", "pending", "pending"]);
});

test("success: all done; 304: middle steps skipped", () => {
  assert.ok(stepStates(run({ status: "ok", phase: "done" })).every((s) => s === "done"));
  assert.deepEqual(stepStates(run({ status: "not_modified", phase: "done" })), ["done", "skipped", "skipped", "skipped", "skipped", "done"]);
});

test("progress is monotonic over phases and 1 when finished", () => {
  assert.equal(progress(run({ status: "queued", phase: "connect" })), 0);
  assert.ok(progress(run({ phase: "parse" })) > progress(run({ phase: "download" })));
  assert.equal(progress(run({ status: "ok", phase: "done" })), 1);
});

test("live events update a known run but never go backwards or touch finished runs", () => {
  const a = applyLive([run({ phase: "parse", bytes: 500 })], { run_id: 1, phase: "download", bytes: 100 })!;
  assert.equal(a[0]!.phase, "parse");
  assert.equal(a[0]!.bytes, 500);
  const b = applyLive([run({ status: "ok", phase: "done" })], { run_id: 1, status: "running", phase: "connect" })!;
  assert.equal(b[0]!.status, "ok");
  assert.equal(applyLive([run()], { run_id: 99 }), null);
});

test("latestBySource picks the highest id; summary mentions counts and unchanged", () => {
  assert.equal(latestBySource([run({ id: 2 }), run({ id: 5 }), run({ id: 3 })]).get("debian")!.id, 5);
  assert.match(summary("Debian", run({ status: "ok", phase: "done", items: 12, hosts: 3, phases: { connect: 500, store: 1500 } })), /12 Einträge · 3 Hosts.*2\.0 s/);
  assert.match(summary("Debian", run({ status: "not_modified" })), /unverändert/);
});

test("a running run shows how long it runs; a hung, aborted one says so (different texts)", () => {
  const start = Date.parse("2026-11-07T10:00:00Z");
  const running = run({ status: "running", phase: "connect", started_at: "2026-11-07T10:00:00Z" });
  assert.equal(runningSince(running, start + 30_000), "seit 30 Sekunden");
  assert.equal(runningSince(running, start + 1000), "seit 1 Sekunde");
  assert.equal(runningSince(running, start + 150_000), "seit 2 Minuten");
  assert.equal(runText(running, start + 30_000), "Verbinden, 30 s · läuft seit 30 Sekunden");
  const hung = run({ status: "failed", phase: "connect", error: "Zeitüberschreitung beim Verbinden", finished_at: "2026-11-07T10:02:30Z" });
  assert.ok(isHung(hung));
  assert.equal(runText(hung, start), "Lauf hängt, abgebrochen (bei „Verbinden“)");
  assert.ok(!runText(hung, start).includes("läuft"));
  // Ein gewöhnlicher Fehlschlag ist kein hängender Lauf.
  const failed = run({ status: "failed", phase: "download", error: "HTTP 503" });
  assert.ok(!isHung(failed));
  assert.equal(runText(failed), "Fehlgeschlagen bei „Herunterladen“");
});

test("after a restart the orphaned run is interrupted: nothing active, no spinner step", () => {
  const orphan = run({ status: "interrupted", phase: "download", error: "Der Lauf wurde unterbrochen (Server beendet oder neu gestartet)." });
  assert.ok(!stepStates(orphan).includes("active"));
  assert.equal(stepStates(orphan)[1], "failed");
  assert.match(runText(orphan), /Unterbrochen/);
  assert.ok(!runText(orphan).includes("läuft"));
  // Ein verspätetes Live-Ereignis macht ihn nicht wieder lebendig.
  const out = applyLive([orphan], { run_id: 1, status: "running", phase: "parse" });
  assert.equal(out![0]!.status, "interrupted");
});

test("phase change is reflected in the step states and the text", () => {
  const a = run({ status: "running", phase: "connect" });
  const out = applyLive([a], { run_id: 1, status: "running", phase: "download", bytes: 2048 })!;
  assert.equal(out[0]!.phase, "download");
  assert.deepEqual(stepStates(out[0]!).slice(0, 2), ["done", "active"]);
  assert.match(runText(out[0]!), /Herunterladen/);
});

test("phase time counts from the finished phases; slow means more than 3x the median", () => {
  const start = Date.parse("2026-11-07T10:00:00Z");
  const r = run({ status: "running", phase: "download", started_at: "2026-11-07T10:00:00Z", phases: { connect: 1000 } });
  assert.equal(phaseElapsedMs(r, start + 22_000), 21_000);
  assert.equal(runText(r, start + 22_000), "Herunterladen, 21 s · läuft seit 22 Sekunden");
  const med = { download: 5000 };
  assert.equal(isSlow(r, start + 22_000, med), true, "21 s > 3 × 5 s");
  assert.equal(isSlow(r, start + 12_000, med), false, "11 s ist weniger als 15 s");
  assert.equal(isSlow(r, start + 22_000, { download: 8000 }), false, "21 s < 24 s");
  assert.equal(isSlow(r, start + 22_000, undefined), false, "ohne Vergleichswert keine Warnung");
  assert.equal(isSlow({ ...r, status: "failed" }, start + 22_000, med), false);
  assert.equal(isSlow({ ...r, phase: "parse" }, start + 22_000, { download: 5000 }), false, "nur die Phase mit Median zählt");
});
