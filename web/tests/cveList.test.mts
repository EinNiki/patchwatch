// CVE-Liste: URL-Parameter und Zähler. Muss ohne src/lib/cveList.ts fehlschlagen.
import assert from "node:assert/strict";
import { test } from "node:test";
import { affectedHosts, affectingLabel, parseAffectsAll, parseSort } from "../src/lib/cveList.ts";

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
