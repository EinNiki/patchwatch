import assert from "node:assert/strict";
import { test } from "node:test";
import { DURATIONS, MAX_VISIBLE, MERGE_WINDOW_MS, createToastStore, visible } from "../src/lib/toastStore.ts";
import { describeApiError, writeFailure } from "../src/lib/apiErrors.ts";

function clock() {
  let t = 1_000_000;
  return { now: () => t, tick: (ms: number) => void (t += ms) };
}

test("durations per variant: 4 s / 4 s / 8 s, errors stay", () => {
  assert.deepEqual(DURATIONS, { success: 4000, info: 4000, warning: 8000, error: null });
  const s = createToastStore();
  s.push("success", "a");
  s.push("warning", "b");
  s.push("error", "c");
  assert.deepEqual(s.getState().items.map((i) => i.duration), [4000, 8000, null]);
});

test("explicit duration overrides the default (also null = persistent)", () => {
  const s = createToastStore();
  s.push("error", "x", { duration: 8000 });
  s.push("info", "y", { duration: null });
  assert.deepEqual(s.getState().items.map((i) => i.duration), [8000, null]);
});

test("same message within 5 s is merged into a counter and restarts the timer", () => {
  const c = clock();
  const s = createToastStore(c.now);
  const id = s.push("error", "Speichern fehlgeschlagen");
  const first = s.getState().items[0]!.stamp;
  c.tick(MERGE_WINDOW_MS - 1);
  assert.equal(s.push("error", "Speichern fehlgeschlagen"), id);
  c.tick(1000);
  s.push("error", "Speichern fehlgeschlagen");
  const [item] = s.getState().items;
  assert.equal(s.getState().items.length, 1);
  assert.equal(item!.count, 3);
  assert.ok(item!.stamp > first);
});

test("not merged after the window, with another variant, title or text", () => {
  const c = clock();
  const s = createToastStore(c.now);
  s.push("info", "a");
  c.tick(MERGE_WINDOW_MS + 1);
  s.push("info", "a");
  s.push("success", "a");
  s.push("info", "a", { title: "T" });
  s.push("info", "b");
  assert.equal(s.getState().items.length, 5);
});

test("at most four are visible, the rest waits and moves up when one closes", () => {
  const s = createToastStore();
  const ids = ["1", "2", "3", "4", "5", "6"].map((m) => s.push("info", m));
  assert.deepEqual(visible(s.getState().items).map((i) => i.message), ["1", "2", "3", "4"]);
  assert.equal(MAX_VISIBLE, 4);
  s.dismiss(ids[0]!);
  assert.deepEqual(visible(s.getState().items).map((i) => i.message), ["2", "3", "4", "5"]);
});

test("dismiss of unknown id and clear do not notify needlessly", () => {
  const s = createToastStore();
  let n = 0;
  s.subscribe(() => void n++);
  s.dismiss(42);
  s.clear();
  assert.equal(n, 0);
  s.push("info", "x");
  s.clear();
  assert.equal(n, 2);
  assert.equal(s.getState().items.length, 0);
});

test("action and title are kept", () => {
  const s = createToastStore();
  let hit = 0;
  s.push("warning", "m", { title: "T", action: { label: "Rückgängig", onClick: () => void hit++ } });
  const it = s.getState().items[0]!;
  it.action!.onClick();
  assert.equal(it.title, "T");
  assert.equal(it.action!.label, "Rückgängig");
  assert.equal(hit, 1);
});

test("API errors are translated into German", () => {
  assert.equal(describeApiError(0), "Server nicht erreichbar.");
  assert.equal(describeApiError(403), "Dafür fehlt die Berechtigung.");
  assert.equal(describeApiError(404), "Nicht gefunden.");
  assert.equal(describeApiError(429, "too many", 12), "Zu viele Anfragen. Erneut möglich in 12 Sek.");
  assert.equal(describeApiError(400, "Intervall zu klein"), "Intervall zu klein");
  assert.match(describeApiError(500, "boom: secret detail"), /^Serverfehler \(HTTP 500\)/);
  assert.ok(!describeApiError(500, "boom: secret detail").includes("secret"));
  assert.equal(writeFailure("Token konnte nicht erneuert werden", 404), "Token konnte nicht erneuert werden: Nicht gefunden.");
  assert.equal(writeFailure(undefined, 403), "Dafür fehlt die Berechtigung.");
});
