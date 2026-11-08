// CVE-Liste: URL-Parameter und Zähler. Muss ohne src/lib/cveList.ts fehlschlagen.
import assert from "node:assert/strict";
import { test } from "node:test";
import { affectedHosts, affectingLabel, hostChips, hostState, listStats, parseAffectsAll, parseSort } from "../src/lib/cveList.ts";
import type { CveListItem } from "../src/lib/types.ts";

test("Standard ist „betroffene Hosts zuerst“, Unsinn fällt darauf zurück", () => {
  assert.equal(parseSort(null), "hosts");
  for (const bad of ["", "constructor", "level;drop", "café😀", "HOSTS"]) assert.equal(parseSort(bad), "hosts", bad);
  for (const ok of ["hosts", "latest", "level", "updated"]) assert.equal(parseSort(ok), ok);
});
test("Filter „Betrifft“: Standard Meine Hosts, nur all schaltet um", () => {
  assert.equal(parseAffectsAll(null), false);
  assert.equal(parseAffectsAll("mine"), false);
  assert.equal(parseAffectsAll("all"), true);
  assert.equal(parseAffectsAll("ALL"), false);
});
test("betroffene Hosts: verwundbar, Fix angekündigt und Neustart zählen, unbekannt nicht", () => {
  assert.equal(affectedHosts({ hosts_vulnerable: 1, hosts_fix_pending: 2, hosts_reboot: 3 }), 6);
  assert.equal(affectedHosts({ hosts_vulnerable: 0, hosts_fix_pending: 0, hosts_reboot: 0 }), 0);
});
test("Zeile über der Liste", () => {
  assert.equal(affectingLabel(1), "1 CVE betrifft deine Hosts");
  assert.equal(affectingLabel(0), "0 CVEs betreffen deine Hosts");
  assert.equal(affectingLabel(1204), "1.204 CVEs betreffen deine Hosts");
});
test("Tooltip „Aktualisiert“: Quelldatum und Abgleich getrennt, ohne Datum „unbekannt“", async () => {
  const { updatedTitle } = await import("../src/lib/cveList.ts");
  const abs = (iso: string | null) => `<${iso}>`;
  assert.equal(updatedTitle("A", "B", abs), "Laut Quelle geändert: <A>\nZuletzt abgeglichen: <B>");
  assert.match(updatedTitle(null, "B", abs), /unbekannt.*\nZuletzt abgeglichen: <B>/);
  assert.ok(!updatedTitle(null, null, abs).includes("abgeglichen"));
});

const row = (o: Partial<CveListItem>): CveListItem => ({
  id: "CVE-2026-1", description: null, priority: null, level: 5, published_at: null, updated_at: null, last_synced_at: null, watched: false, note: null,
  exploited: false, hosts_vulnerable: 0, hosts_fix_pending: 0, hosts_reboot: 0, hosts_unknown: 0, distros: [], hidden_releases: 0, ...o,
});
const dist = (fix: string | null, mine = true) => ({ source: "debian", release: "trixie", status: "x", package: "linux", fix_version: fix, updated_at: "", mine });

test("Kennzahlen zählen nur CVEs, die Hosts betreffen, und stimmen mit der Liste überein", () => {
  const rows = [
    row({ id: "a", hosts_vulnerable: 1, level: 9, distros: [dist("6.1-1")] }),
    row({ id: "b", hosts_fix_pending: 2, level: 4, distros: [dist(null)] }),
    row({ id: "c", hosts_reboot: 1, level: 8, distros: [dist("6.1-2", false)] }),
    row({ id: "d", hosts_unknown: 3, level: 10, distros: [dist("1")] }),
  ];
  assert.deepEqual(listStats(rows), { affecting: 3, high: 2, withFix: 1, withoutFix: 2 });
  assert.deepEqual(listStats([]), { affecting: 0, high: 0, withFix: 0, withoutFix: 0 });
});

test("Host-Chips: höchstens max Namen, Rest aus den Zählern als „+N“", () => {
  const c = row({ hosts_vulnerable: 7, affected_hosts: ["a", "b", "c", "d", "e", "f"] });
  assert.deepEqual(hostChips(c, 4), { names: ["a", "b", "c", "d"], more: 3 });
  assert.deepEqual(hostChips(row({ hosts_vulnerable: 1, affected_hosts: ["a"] })), { names: ["a"], more: 0 });
  assert.deepEqual(hostChips(row({ hosts_vulnerable: 2 })), { names: [], more: 2 });
});

test("host state icon comes from the row counters; mixed rows have no single state", () => {
  const z = { hosts_vulnerable: 0, hosts_fix_pending: 0, hosts_reboot: 0 };
  assert.equal(hostState({ ...z, hosts_vulnerable: 2 })?.text, "verwundbar, Fix noch nicht installiert");
  assert.equal(hostState({ ...z, hosts_fix_pending: 1 })?.icon, "warn");
  assert.equal(hostState({ ...z, hosts_reboot: 1 })?.icon, "reboot");
  assert.equal(hostState({ ...z, hosts_vulnerable: 1, hosts_reboot: 1 }), null);
  assert.equal(hostState(z), null);
});
