// Chips der CVE-Liste: keine Umfangswörter ("zählt"), Debian-Suiten getrennt, "Security: unbekannt" statt stiller Archivangabe.
import assert from "node:assert/strict";
import { test } from "node:test";
import { chipTitle, suiteParts } from "../src/lib/chips.ts";
import type { Distro } from "../src/lib/types.ts";

const base: Distro = { source: "debian", release: "trixie", status: "fixed", package: "linux", fix_version: "6.12.113-1", updated_at: "2026-11-06T10:00:00Z", mine: true, packages: 1, suites: null };
const suites = (arc: [string, string] | null, sec: [string, string] | null): Distro["suites"] => ({
  ...(arc ? { trixie: { version: arc[0], status: arc[1] } } : {}),
  ...(sec ? { "trixie-security": { version: sec[0], status: sec[1] } } : {}),
});

test("Archiv verwundbar, Security gefixt: beide Angaben mit Version", () => {
  const d = { ...base, suites: suites(["6.12.107-1", "vulnerable"], ["6.12.115-2", "fixed"]) };
  assert.deepEqual(suiteParts(d), [
    { label: "Security", status: "fixed", version: "6.12.113-1" },
    { label: "Archiv", status: "vulnerable", version: "6.12.107-1" },
  ]);
});

test("beide gleich: eine Angabe; beide offen: eine Angabe", () => {
  assert.equal(suiteParts({ ...base, suites: suites(["6.12.113-1", "fixed"], ["6.12.113-1", "fixed"]) })!.length, 1);
  const open = suiteParts({ ...base, status: "vulnerable", fix_version: null, suites: suites(["1-1", "vulnerable"], ["1-2", "vulnerable"]) })!;
  assert.deepEqual(open, [{ label: "", status: "vulnerable", version: "1-2" }]);
});

test("nur Archiv oder keine Suiten: 'Security: unbekannt', nie stillschweigend die Archivangabe", () => {
  const onlyArc = suiteParts({ ...base, suites: suites(["6.12.107-1", "vulnerable"], null) })!;
  assert.equal(onlyArc[0]!.label, "Security");
  assert.equal(onlyArc[0]!.status, "unbekannt");
  assert.equal(suiteParts(base)![0]!.status, "unbekannt");
});

test("nur Security: eine Angabe ohne erfundenes Archiv", () => {
  const p = suiteParts({ ...base, suites: suites(null, ["6.12.115-2", "fixed"]) })!;
  assert.deepEqual(p, [{ label: "", status: "fixed", version: "6.12.113-1" }]);
});

test("sid/forky und Ubuntu haben keine Security-Suite", () => {
  assert.equal(suiteParts({ ...base, release: "sid" }), null);
  assert.equal(suiteParts({ ...base, source: "ubuntu", release: "noble" }), null);
});

test("kein Chip-Text enthält 'zählt' oder 'zählen' (alle Chiptypen, innerhalb und außerhalb des Umfangs)", () => {
  const cases: Distro[] = [
    base,
    { ...base, mine: false },
    { ...base, source: "ubuntu", release: "noble", status: "vulnerable", fix_version: null },
    { ...base, source: "osv", release: "x", status: "unknown" },
    { ...base, suites: suites(["a-1", "vulnerable"], ["a-2", "fixed"]), mine: false },
    { ...base, release: "bookworm", status: "vulnerable", fix_version: null, mine: false },
  ];
  for (const d of cases) for (const all of [false, true]) assert.doesNotMatch(chipTitle(d, all), /zähl/i);
});

test("außerhalb des Umfangs nennt der Tooltip den Grund, im Umfang nicht", () => {
  assert.match(chipTitle({ ...base, mine: false }, false), /Läuft auf keinem deiner Hosts/);
  assert.doesNotMatch(chipTitle({ ...base, mine: false }, true), /keinem deiner Hosts/);
  assert.doesNotMatch(chipTitle(base, false), /keinem deiner Hosts/);
});

test("Sonderzeichen im Release-Namen brechen nichts", () => {
  assert.doesNotThrow(() => chipTitle({ ...base, release: "café 🔥 <b>", package: "ünï" }, false));
});
