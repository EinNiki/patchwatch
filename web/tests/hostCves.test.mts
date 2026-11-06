// Host-Ansicht: Satz, Balken, Kernel-Zeile, Banner. Muss ohne die Logik in src/lib/hostCves.ts fehlschlagen.
import assert from "node:assert/strict";
import { test } from "node:test";
import { barSegments, feedNotice, kernelLine, openStatusWord, stateCounts, summarySentence } from "../src/lib/hostCves.ts";
import type { Feed } from "../src/lib/types.ts";

const c = (open: number, reboot: number, fixed = 0, notAffected = 0, unknown = 0) => ({ open, reboot, fixed, notAffected, unknown });
const base = { newest: "7.0.0-42.42", proxmox: false, restricted: false };

test("Satz: Neustart nötig, offen bleiben", () => {
  assert.equal(summarySentence(c(81, 2894, 2824, 139), base), "Nach dem Neustart auf 7.0.0-42.42 sind noch 81 CVEs offen, 2894 werden behoben.");
});
test("Satz: kein Neustart nötig", () => {
  assert.equal(summarySentence(c(81, 0), base), "81 CVEs offen, kein Fix installiert.");
});
test("Satz: alles gefixt, nie 'alles gut' bei eingeschränkter Quelle", () => {
  assert.equal(summarySentence(c(0, 0, 5), base), "Keine offenen CVEs.");
  const r = summarySentence(c(0, 0, 5), { ...base, restricted: true });
  assert.ok(!/^Keine offenen CVEs\.$/.test(r) && r.includes("unvollständig"));
});
test("Satz: Neustart behebt alles, Einzahl, eingeschränkt", () => {
  assert.equal(summarySentence(c(0, 1), base), "Nach dem Neustart auf 7.0.0-42.42 sind keine CVEs offen, 1 wird behoben.");
  assert.ok(summarySentence(c(3, 5), { ...base, restricted: true }).includes("kann unvollständig sein"));
});
test("Satz: Proxmox ist nie grün", () => {
  const s = summarySentence(c(0, 0, 0, 0, 7), { ...base, proxmox: true });
  assert.ok(s.includes("manuell prüfen") && !s.includes("Keine offenen"));
});
test("fix_pending zählt zu offen, Eintrag ohne Fix-Version nie als 'Fix installiert'", () => {
  const k = stateCounts({ vulnerable: 2, fix_pending: 3, fixed_installed_reboot_required: 4, fixed: 1, not_affected: 0, unknown: 0 });
  assert.deepEqual(k, c(5, 4, 1));
  assert.equal(openStatusWord({ status: "vulnerable", fix_version: null }), "Kein Fix");
  assert.equal(openStatusWord({ status: "fix_pending", fix_version: "1" }), "Fix angekündigt");
  assert.equal(openStatusWord({ status: "vulnerable", fix_version: "1" }), "Fix im Archiv");
});
test("Balken: Summe 100, kleine Segmente sichtbar, leer ohne Daten", () => {
  const b = barSegments(c(81, 2894, 2824, 139));
  assert.equal(Math.round(b.reduce((s, x) => s + x.pct, 0)), 100);
  assert.ok(b.every((x) => x.pct >= 0.9));
  assert.deepEqual(b.map((x) => x.tile), ["open", "reboot", "fixed", "not_affected"]);
  assert.deepEqual(barSegments(c(0, 0)), []);
});
test("Kernel-Zeile", () => {
  assert.equal(kernelLine("7.0.0-38.38", "7.0.0-42.42", true), "Läuft 7.0.0-38.38 · Neuester installiert 7.0.0-42.42 · Neustart nötig");
  assert.equal(kernelLine(null, null, false), "Läuft – · Neuester installiert –");
});
const feed = (o: Partial<Feed>): Feed => ({ type: "ubuntu", label: "Ubuntu", enabled: true, state: "ok", consecutive_failures: 0, last_error: null, last_error_at: null, stale_since: null, backfill: null, bulk: null, ...o }) as Feed;
test("Banner nur bei eingeschränkter zuständiger Quelle, ohne alten Text", () => {
  assert.equal(feedNotice([feed({})], "ubuntu", "resolute", null).text, null);
  assert.equal(feedNotice([feed({ type: "debian", state: "stale" })], "ubuntu", "resolute", null).text, null, "fremde Quelle zählt nicht");
  const bulk = { releases: [{ release: "resolute", state: "ok" }] } as Feed["bulk"];
  const n = feedNotice([feed({ state: "stale", consecutive_failures: 3, stale_since: "2026-11-06T21:08:00Z", bulk })], "ubuntu", "resolute", null);
  assert.ok(n.restricted && n.text);
  assert.match(n.text!, /^Ubuntu: Offene Fälle nicht vollständig geladen \(API überlastet, seit \d\d:\d\d\)\. Gefixt-Angaben stammen aus den Massendaten und sind belastbar\. Die Zahl „Offen“ kann unvollständig sein\.$/);
  assert.ok(!n.text!.includes("Rückstand"));
  const nb = feedNotice([feed({ state: "stale" })], "ubuntu", "resolute", null);
  assert.ok(!nb.text!.includes("belastbar"), "ohne Massendaten keine Belastbarkeits-Zusage");
});
test("Level in Worten und Gruppentitel", async () => {
  const { levelWord, groupTitle } = await import("../src/lib/hostCves.ts");
  assert.deepEqual([10, 8, 5, 3, 1, 0].map(levelWord), ["Kritisch", "Hoch", "Mittel", "Niedrig", "Minimal", "Unbekannt"]);
  assert.equal(groupTitle("7.0.0-42.42", 1204), "Behoben in 7.0.0-42.42: 1.204 CVEs");
  assert.equal(groupTitle(null, 1), "Ohne Fix-Version: 1 CVE");
});
test("Kurzbeschreibung entfernt den Kernel-Vorspann", async () => {
  const { shortText } = await import("../src/lib/hostCves.ts");
  assert.equal(shortText("In the Linux kernel, the following vulnerability has been resolved: wifi: fix x"), "wifi: fix x");
  assert.equal(shortText("In the Linux kernel, the following vulnerability has been resolved:"), "In the Linux kernel, the following vulnerability has been resolved:");
  assert.equal(shortText(null), "");
});
