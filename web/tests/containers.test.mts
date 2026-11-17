import { test } from "node:test";
import assert from "node:assert/strict";
import { countOutdated, dockerNotice, matchesFilter, verdictGroup, verdictView } from "../src/lib/containers.ts";
import type { ContainerItem, ContainerVerdict } from "../src/lib/types.ts";

const kinds: ContainerVerdict[] = [
  { status: "current" },
  { status: "update_available", platform_confirmed: true },
  { status: "newer_version", patch: "1.2.9", minor: "1.3.0", major: "2.0.1" },
  { status: "pinned" },
  { status: "unsupported" },
  { status: "pending" },
  { status: "deferred" },
  { status: "incomparable" },
  { status: "incomplete" },
  { status: "no_local_digest" },
  { status: "error", text: "Registry nicht erreichbar" },
];

test("Jede Bewertung hat Chip mit Symbol und Text; Unbekanntes ist nie „aktuell“ und nie rot", () => {
  for (const v of kinds) {
    const { info } = verdictView(v);
    assert.ok(info.label.length > 0 && info.icon, v.status);
    if (v.status !== "current") assert.notEqual(info.tone, "ok", v.status);
    assert.notEqual(info.tone, "crit", `${v.status}: Container-Hinweise sind nie rot`);
  }
});

test("Nicht prüfbar nennt den Grund, nie geraten", () => {
  for (const s of ["unsupported", "pending", "deferred", "incomparable", "incomplete", "no_local_digest"] as const) {
    const { info, detail } = verdictView({ status: s });
    assert.ok(info.tone === "unknown", s);
    assert.ok(detail && detail.length > 10, s);
  }
});

test("Neuere Version nennt die höchste Version und alle Stufen", () => {
  const v = verdictView({ status: "newer_version", patch: "1.2.9", minor: null, major: "2.0.1" });
  assert.equal(v.info.label, "Neuere Version 2.0.1");
  assert.equal(v.detail, "Patch 1.2.9 · Major 2.0.1");
});

test("Digest-Abweichung ohne Plattformbestätigung wird so benannt", () => {
  assert.match(verdictView({ status: "update_available", platform_confirmed: false }).detail ?? "", /nicht bestätigt/);
  assert.equal(verdictView({ status: "update_available", platform_confirmed: true }).detail, null);
});

test("Filter: Updates sind neues Image und neue Version, sonst genau die Gruppe", () => {
  const get = (f: Parameters<typeof matchesFilter>[1]) => kinds.filter((v) => matchesFilter(v, f)).map((v) => v.status);
  assert.deepEqual(get("updates"), ["update_available", "newer_version"]);
  assert.deepEqual(get("current"), ["current"]);
  assert.deepEqual(get("pinned"), ["pinned"]);
  assert.deepEqual(get("error"), ["error"]);
  assert.equal(get("unchecked").length, 6);
  assert.equal(get("all").length, kinds.length);
  assert.equal(verdictGroup({ status: "newer_version", patch: null, minor: null, major: "3.0.0" }), "version");
});

test("Hinweise zu Docker: aus, nicht erreichbar mit Grund, ok ohne Hinweis", () => {
  assert.match(dockerNotice(null)!.title, /nicht aktiviert/);
  assert.equal(dockerNotice({ state: "ok", reason: null, checked_at: null }), null);
  assert.match(dockerNotice({ state: "unavailable", reason: "no_permission", checked_at: null })!.text, /Socket-Proxy/);
  assert.match(dockerNotice({ state: "unavailable", reason: "unbekannt", checked_at: null })!.text, /nicht lesen/);
});

test("Zähler der veralteten Container", () => {
  const c = (verdict: ContainerVerdict) => ({ verdict }) as ContainerItem;
  assert.equal(countOutdated([c(kinds[0]!), c(kinds[1]!), c(kinds[2]!), c(kinds[3]!)]), 2);
});
