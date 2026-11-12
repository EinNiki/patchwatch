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
test("relative Tage über den Zeitwechsel im Oktober (25-Stunden-Tag) und „vor n Tagen“", () => {
  // 25.10.2026 hat 25 Stunden. 26 h zurück ist zwei Berliner Kalendertage früher, nicht „gestern“ (gerundete 24-h-Tage).
  assert.equal(relTime("2026-10-25T22:30:00Z", Date.parse("2026-10-27T00:30:00Z")), "vorgestern");
  // 24,5 h zurück am 25-Stunden-Tag selbst: derselbe Kalendertag, also „heute“.
  assert.equal(relTime("2026-10-24T22:00:00Z", Date.parse("2026-10-25T22:30:00Z")), "heute");
  // Mehrere Tage über beide Wechsel: zählt Kalendertage.
  assert.equal(relTime("2026-10-24T21:30:00Z", Date.parse("2026-10-27T12:00:00Z")), "vor 3 Tagen");
  assert.equal(relTime("2026-03-28T10:00:00Z", Date.parse("2026-03-31T10:00:00Z")), "vor 3 Tagen");
  assert.equal(relTime("2026-03-28T22:30:00Z", Date.parse("2026-03-30T10:00:00Z")), "vorgestern");
});
test("Bootzeit nach Neustart: verschiebt sich nur um die Sendedauer, Anzeige in Minuten (N8)", () => {
  // Zwei Reports desselben Laufs, Uptime jeweils beim Sammeln gelesen; der zweite kommt 3 s später an als gesammelt.
  const boot1 = bootTime("2026-11-06T12:00:10Z", 3_600)!;
  const boot2 = bootTime("2026-11-07T12:00:13Z", 3_600 + 86_400)!;
  assert.equal(boot2 - boot1, 3_000, "Drift = Zeit zwischen Lesen der Uptime und Empfang");
  assert.equal(bootLabel("2026-11-06T12:00:10Z", 3_600), bootLabel("2026-11-07T12:00:13Z", 3_600 + 86_400));
  // An einer Minutengrenze springt die Anzeige um eine Minute (bekannt, niedrig): Boot 12:00:58 -> 12:01:01 (Berlin).
  assert.equal(bootLabel("2026-11-06T12:00:58Z", 3_600), "gestartet 06.11. 12:00");
  assert.equal(bootLabel("2026-11-07T12:01:01Z", 3_600 + 86_400), "gestartet 06.11. 12:01");
  // Nach einem Neustart gilt die neue Uptime sofort, nie negativ.
  assert.equal(bootLabel("2026-11-08T08:00:00Z", 120), "gestartet 08.11. 08:58");
  assert.equal(bootTime("2026-11-08T08:00:00Z", -5), null);
});
