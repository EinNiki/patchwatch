// Der Umfang ("Meine Releases" / "Alle Releases") ist kein Bedienelement mehr: weder Feld noch Link noch URL-Parameter.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const page = readFileSync(new URL("../src/app/(app)/cves/page.tsx", import.meta.url), "utf8");

test("CVE-Seite hat kein Umfangsfeld und liest releases/scope nicht aus der URL", () => {
  assert.doesNotMatch(page, /Umfang|Alle Releases|Meine Releases/);
  assert.doesNotMatch(page, /params\.get\("(releases|scope|umfang)"\)/);
  assert.doesNotMatch(page, /set\("releases"/);
});

test("Legende nennt den festen Bezug auf die Hosts", () => {
  assert.match(page, /Filter berücksichtigen nur Releases deiner Hosts\./);
});
