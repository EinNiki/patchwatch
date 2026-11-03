// Fund (niedrig): Anfragen, die beim Abmelden noch laufen, dürfen den Cache danach nicht füllen.
// Lauf: npm test (Node 22, Typen werden entfernt, kein weiteres Framework nötig).
import assert from "node:assert/strict";
import { test } from "node:test";
import { cacheGeneration, cacheGet, cacheSet, cacheSetIfCurrent, clearApiCache } from "../src/lib/apiCache.ts";

test("Antwort einer Anfrage aus der beendeten Sitzung füllt den Cache nicht", () => {
  clearApiCache();
  const gen = cacheGeneration(); // Anfrage startet
  clearApiCache(); // Logout, bevor die Antwort da ist
  assert.equal(cacheSetIfCurrent("/hosts", [{ name: "geheim" }], gen), false);
  assert.equal(cacheGet("/hosts"), undefined);
});

test("auch ein Logout bei leerem Cache beendet die Sitzung (Zähler steigt immer)", () => {
  clearApiCache();
  const before = cacheGeneration();
  clearApiCache();
  assert.equal(cacheGeneration(), before + 1);
});

test("Antwort der aktuellen Sitzung wird gespeichert", () => {
  clearApiCache();
  const gen = cacheGeneration();
  assert.equal(cacheSetIfCurrent("/hosts", [1], gen), true);
  assert.deepEqual(cacheGet("/hosts"), [1]);
});

test("Leeren entfernt vorhandene Daten", () => {
  cacheSet("/x", 1);
  clearApiCache();
  assert.equal(cacheGet("/x"), undefined);
});
