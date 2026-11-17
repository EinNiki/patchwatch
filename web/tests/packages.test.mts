import { test } from "node:test";
import assert from "node:assert/strict";
import { filterQuery, listNotice, listsAge, parsePackageFilter } from "../src/lib/packages.ts";

const NOW = Date.parse("2026-11-17T12:00:00Z");
const host = { installed: 10, packages_count: 10, truncated: false, packages_updated_at: null, apt_lists_updated_at: null, updates_listed: true, updates: 0, security: 0, new: 0, remove: null };

test("Filter aus dem Link: unbekannte Werte ergeben „nur mit Update“", () => {
  assert.equal(parsePackageFilter("security"), "security");
  assert.equal(parsePackageFilter("all"), "all");
  for (const bad of [null, "", "constructor", "SECURITY", "x&y"]) assert.equal(parsePackageFilter(bad), "updates");
});

test("Filter wird zu festen Abfrageteilen", () => {
  assert.equal(filterQuery("updates"), "&update=1");
  assert.equal(filterQuery("security"), "&security=1");
  assert.equal(filterQuery("all"), "");
});

test("Alter der Paketlisten: unbekannt ist nie „aktuell“, ab 7 Tagen Warnung", () => {
  assert.deepEqual(listsAge(null, NOW), { text: "unbekannt", stale: false });
  assert.deepEqual(listsAge("2026-11-17T01:00:00Z", NOW), { text: "heute aktualisiert", stale: false });
  assert.deepEqual(listsAge("2026-11-16T01:00:00Z", NOW), { text: "vor 1 Tag", stale: false });
  assert.deepEqual(listsAge("2026-11-11T11:00:00Z", NOW), { text: "vor 6 Tagen", stale: false });
  assert.deepEqual(listsAge("2026-11-10T11:00:00Z", NOW), { text: "vor 7 Tagen", stale: true });
});

test("Hinweise bei abgeschnittener oder fehlender Liste", () => {
  assert.equal(listNotice(host), null);
  assert.match(listNotice({ ...host, truncated: true, installed: 20000 })!, /20\.000 Pakete begrenzt/);
  assert.match(listNotice({ ...host, updates_listed: false })!, /Update-Liste/);
});
