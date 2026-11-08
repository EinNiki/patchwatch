// Sichtbare Begriffe: "Report" und "Check-in" tauchen in der Oberfläche nicht mehr auf (intern bleiben sie).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ACTIVE_LABEL, ACTIVE_TIP, DATA_LABEL, DATA_TIP, FETCH_ACTION } from "../src/lib/terms.ts";

const read = (p: string) => readFileSync(new URL(`../src/${p}`, import.meta.url), "utf8");

test("Beschriftungen und Erklärtexte", () => {
  assert.equal(DATA_LABEL, "Daten zuletzt");
  assert.equal(ACTIVE_LABEL, "Agent zuletzt aktiv");
  assert.equal(FETCH_ACTION, "Daten jetzt abrufen");
  assert.match(DATA_TIP, /vollständige Daten gemeldet \(Kernel, Pakete, Updates\)\. Das passiert einmal täglich/);
  assert.match(ACTIVE_TIP, /überträgt keine Daten\.$/);
});

test("Oberflächen-Quellen nutzen die alten Begriffe nicht mehr als sichtbaren Text", () => {
  const old = /Letzter Report|Letzter Check-in|Noch kein Report|Noch keine Reports|Jetzt aktualisieren|jetzt aktualisieren|Alle aktualisieren|Reports anfordern|Report-Historie/;
  for (const f of ["app/(app)/agents/page.tsx", "app/(app)/page.tsx", "app/(app)/hosts/[id]/page.tsx", "app/(app)/settings/page.tsx", "components/HostDetails.tsx", "lib/status.ts", "lib/hostCves.ts"]) {
    assert.doesNotMatch(read(f), old, f);
  }
});
