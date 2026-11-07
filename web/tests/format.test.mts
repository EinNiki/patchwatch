// Zeit- und Uptime-Anzeige: Europe/Berlin unabhängig von der Prozess-Zeitzone, Sommerzeit, Bootzeit aus Report und Uptime.
import assert from "node:assert/strict";
import { test } from "node:test";
import { absTime, bootLabel, bootTime, clockTime, liveUptimeSeconds, relTime, shortDateTime, uptime } from "../src/lib/format.ts";

test("absolute Zeit in Europe/Berlin (Winter UTC+1, Sommer UTC+2)", () => {
  assert.match(absTime("2026-11-06T22:30:00Z"), /06\.11\.2026, 23:30/, "Winterzeit");
  assert.match(absTime("2026-07-01T10:00:00Z"), /01\.07\.2026, 12:00/, "Sommerzeit");
  assert.equal(clockTime("2026-11-06T21:08:00Z"), "22:08");
  assert.equal(absTime(null), "–");
});
test("Sommerzeitwechsel: 29.03.2026 02:00 -> 03:00, 25.10.2026 03:00 -> 02:00", () => {
  assert.equal(clockTime("2026-03-29T00:59:00Z"), "01:59");
  assert.equal(clockTime("2026-03-29T01:00:00Z"), "03:00", "02:xx existiert an diesem Tag nicht");
  assert.equal(clockTime("2026-10-25T00:59:00Z"), "02:59");
  assert.equal(clockTime("2026-10-25T01:00:00Z"), "02:00", "02:xx kommt zweimal vor (UTC+2, dann UTC+1)");
  assert.equal(clockTime("2026-10-25T02:00:00Z"), "03:00");
});
test("relative Tage zählen Berliner Kalendertage, auch über den Zeitwechsel", () => {
  const now = Date.parse("2026-03-29T12:00:00Z"); // 14:00 Sommerzeit
  // 36,5 Stunden früher, aber gestern (28.03. 00:30): früher "vorgestern" durch Runden.
  assert.equal(relTime("2026-03-27T23:30:00Z", now), "gestern");
  assert.equal(relTime("2026-03-27T10:00:00Z", now), "vorgestern");
  assert.equal(relTime("2026-03-29T11:30:00Z", now), "vor 30 Minuten");
  assert.equal(relTime("2026-03-29T11:59:40Z", now), "gerade eben");
  // 00:30 Berlin am selben Kalendertag: Stunden, nicht Tage.
  assert.equal(relTime("2026-03-28T23:30:00Z", now), "vor 12 Stunden");
  assert.equal(relTime(null), "nie");
});
test("Bootzeit = Reportzeit minus Uptime; Beispiel: Report vor 10 Minuten", () => {
  const now = Date.parse("2026-11-06T21:47:00Z");
  const report = "2026-11-06T21:37:00Z"; // vor 10 Minuten
  const uptimeAtReport = 600; // 10 Minuten
  assert.equal(new Date(bootTime(report, uptimeAtReport)!).toISOString(), "2026-11-06T21:27:00.000Z");
  assert.equal(bootLabel(report, uptimeAtReport), "gestartet 06.11. 22:27");
  // aktuelle Uptime = 10 Min. beim Report + 10 Min. seither, nicht der gemeldete Wert
  assert.equal(liveUptimeSeconds(report, uptimeAtReport, now), 1200);
  assert.equal(uptime(liveUptimeSeconds(report, uptimeAtReport, now)), "20 Min.");
  // eine Stunde später ohne neuen Report läuft die Anzeige weiter
  assert.equal(uptime(liveUptimeSeconds(report, uptimeAtReport, now + 3_600_000)), "1 Std. 20 Min.");
});
test("Neustart des Hosts: der nächste Report setzt die Anzeige zurück", () => {
  const before = liveUptimeSeconds("2026-11-06T10:00:00Z", 5 * 86400, Date.parse("2026-11-06T10:05:00Z"));
  assert.equal(uptime(before), "5 Tg. 0 Std.");
  const after = liveUptimeSeconds("2026-11-06T10:10:00Z", 90, Date.parse("2026-11-06T10:10:30Z"));
  assert.equal(uptime(after), "2 Min.", "Host neu gestartet: 90 s beim Report + 30 s");
});
test("fehlende oder unsinnige Angaben: keine Uhrzeit erfinden", () => {
  for (const [r, u] of [[null, 5], ["2026-11-06T10:00:00Z", null], ["2026-11-06T10:00:00Z", -1], ["kaputt", 5], ["2026-11-06T10:00:00Z", Number.NaN]] as const) {
    assert.equal(bootTime(r, u), null);
    assert.equal(bootLabel(r, u), null);
    assert.equal(liveUptimeSeconds(r, u), null);
  }
  assert.equal(uptime(null), "–");
  // Uhr des Browsers geht vor: nie negativ
  assert.equal(liveUptimeSeconds("2026-11-06T10:00:00Z", 10, Date.parse("2026-11-06T09:00:00Z")), 0);
});
test("Prozess-Zeitzone ist egal", () => {
  assert.equal(shortDateTime(Date.parse("2026-11-06T21:27:00Z")), "06.11. 22:27");
});
