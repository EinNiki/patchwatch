// Host-Ansicht: Satz, Balken, Kernel-Zeile, Banner. Muss ohne die Logik in src/lib/hostCves.ts fehlschlagen.
import assert from "node:assert/strict";
import { test } from "node:test";
import { aptCandidate, announcedText, fixInfo, barSegments, feedNotice, kernelLine, openStatusWord, parseCveFilter, stateCounts, summarySentence } from "../src/lib/hostCves.ts";
import type { Feed } from "../src/lib/types.ts";

const c = (open: number, reboot: number, fixed = 0, unknown = 0) => ({ open, reboot, fixed, unknown });
const base = { newest: "7.0.0-42.42", proxmox: false, restricted: false };

test("Satz: Neustart nötig, offen bleiben", () => {
  assert.equal(summarySentence(c(81, 2894, 2824), base), "Nach dem Neustart auf 7.0.0-42.42 sind noch 81 CVEs offen, 2894 werden behoben.");
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
  const s = summarySentence(c(0, 0, 0, 7), { ...base, proxmox: true });
  assert.ok(s.includes("manuell zu prüfen") && !s.includes("Keine offenen"));
});
test("fix_pending zählt zu offen, Eintrag ohne Fix-Version nie als 'Fix installiert'", () => {
  const k = stateCounts({ vulnerable: 2, fix_pending: 3, fixed_installed_reboot_required: 4, fixed: 1, not_affected: 99, unknown: 0 });
  assert.deepEqual(k, c(5, 4, 1));
  assert.equal(openStatusWord({ status: "vulnerable", fix_version: null }), "Kein Fix");
  assert.equal(openStatusWord({ status: "fix_pending", fix_version: "1" }), "Fix angekündigt");
  assert.equal(openStatusWord({ status: "vulnerable", fix_version: "1" }), "Fix im Archiv");
});
test("Balken: Summe 100, kleine Segmente sichtbar, leer ohne Daten", () => {
  const b = barSegments(c(81, 2894, 2824));
  assert.equal(Math.round(b.reduce((s, x) => s + x.pct, 0)), 100);
  assert.ok(b.every((x) => x.pct >= 0.9));
  assert.deepEqual(b.map((x) => x.tile), ["open", "reboot", "fixed"]);
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

test("Nicht betroffen: nicht im Balken, nicht im Zähler (Daten bleiben in der API)", () => {
  const k = stateCounts({ vulnerable: 1, fix_pending: 0, fixed_installed_reboot_required: 0, fixed: 2, not_affected: 500, unknown: 3 });
  assert.deepEqual(k, c(1, 0, 2, 3));
  const b = barSegments(k);
  assert.deepEqual(b.map((x) => x.tile), ["open", "fixed", "unknown"]);
  assert.equal(Math.round(b.reduce((s, x) => s + x.pct, 0)), 100);
  assert.ok(!summarySentence(k, base).toLowerCase().includes("nicht betroffen"));
});
test("alte URL ?cve=not_affected und Fremdwerte führen auf die Standardansicht", () => {
  for (const bad of ["not_affected", "constructor", "__proto__", "", "OPEN", "<script>", "café😀"]) assert.equal(parseCveFilter(bad), null, bad);
  assert.equal(parseCveFilter(null), null);
  for (const ok of ["open", "reboot", "fixed", "unknown"]) assert.equal(parseCveFilter(ok), ok);
});

const src = (status: string, fix: string | null = null) => ({ source: "ubuntu", release: "resolute", package: "linux", status, fix_version: fix });
const cve = (status: string, sources: ReturnType<typeof src>[], fix: string | null) => ({ status, sources, fix_version: fix }) as never;

test("fix kinds: only a tracker entry with a version and no pending status counts as released", () => {
  assert.deepEqual(fixInfo(cve("vulnerable", [src("released", "7.0.0-43.43")], "7.0.0-43.43")), { kind: "released", version: "7.0.0-43.43", source: "ubuntu" });
  assert.deepEqual(fixInfo(cve("vulnerable", [src("fix_pending", "7.0.0-43.43")], "7.0.0-43.43")), { kind: "announced", version: "7.0.0-43.43", source: "ubuntu" });
  assert.equal(fixInfo(cve("vulnerable", [src("needed")], null)).kind, "none");
  // Veröffentlicht schlägt angekündigt, wenn mehrere Einträge vorliegen.
  assert.equal(fixInfo(cve("vulnerable", [src("fix_pending", "7.0.0-44.44"), src("released", "7.0.0-43.43")], "7.0.0-44.44")).kind, "released");
});

test("an announced fix is never called 'Fix im Archiv' in the list", () => {
  assert.equal(openStatusWord({ status: "vulnerable", fix_version: "7.0.0-43.43", sources: [src("fix_pending", "7.0.0-43.43")] }), "Fix angekündigt");
  assert.equal(openStatusWord({ status: "vulnerable", fix_version: "7.0.0-43.43", sources: [src("released", "7.0.0-43.43")] }), "Fix im Archiv");
});

test("apt candidate: the kernel package whose update equals the fix version", () => {
  const items = [
    { name: "base-files", from: "1", to: "2", origin: "Ubuntu:26.04/resolute-updates", security: false },
    { name: "linux-generic", from: "7.0.0-42.42", to: "7.0.0-43.43", origin: "Ubuntu:26.04/resolute-updates", security: true },
  ];
  assert.equal(aptCandidate(items, "7.0.0-43.43")?.name, "linux-generic");
  assert.equal(aptCandidate(items, "7.0.0-44.44"), null);
  assert.equal(aptCandidate(null, "7.0.0-43.43"), null);
  assert.equal(aptCandidate(items, null), null);
});

test("announced text states both sources and that they may differ in time, without confirming the fix", () => {
  const info = fixInfo(cve("vulnerable", [src("fix_pending", "7.0.0-43.43")], "7.0.0-43.43"));
  const items = [{ name: "linux-generic", from: "7.0.0-42.42", to: "7.0.0-43.43", origin: "resolute-updates", security: true }];
  const t = announcedText(info, items);
  assert.equal(t.aptAvailable, true);
  assert.equal(t.lines[0], "Ubuntus Tracker führt die CVE noch als „Fix in Arbeit“ (voraussichtlich in 7.0.0-43.43).");
  assert.equal(t.lines[1], "Auf diesem Host ist 7.0.0-43.43 laut apt verfügbar (resolute-updates).");
  assert.match(t.lines[2]!, /zeitversetzt/);
  assert.ok(!t.lines.join(" ").includes("Fix im Archiv"));
  // apt kennt die Version (noch) nicht: das steht da, ohne den Fix zu bestätigen.
  const none = announcedText(info, []);
  assert.equal(none.aptAvailable, false);
  assert.match(none.lines[1]!, /noch nicht an/);
  // Paketliste noch nicht geladen oder Agent liefert keine: keine Aussage zu apt.
  assert.equal(announcedText(info, undefined).lines.length, 2);
  assert.equal(announcedText(info, null).lines.length, 2);
});
