import assert from "node:assert/strict";
import { test } from "node:test";
import { applyLive, latestBySource, progress, stepStates, summary, type FeedRun } from "../src/lib/feedRuns.ts";

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
