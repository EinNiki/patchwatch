// E2E: Entfernen in der Ansicht "nur Watchlist" (Rückgängig, verzögertes Ausblenden, Persistenz) gegen den laufenden Stack.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> node scripts/e2e-watchlist.mjs
// Legt über Docker-Postgres PW_PG_NAME (Standard `pw-night-pg`) zwei Test-Einträge in der Watchlist an und räumt sie wieder auf.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const sql = (q) => execFileSync("docker", ["exec", process.env.PW_PG_NAME ?? "pw-night-pg", "psql", "-U", "patchwatch", "-d", "patchwatch", "-tAc", q]).toString().trim();
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";

const ids = sql("select id from cves order by id desc limit 2").split("\n");
sql(`delete from cve_watchlist where cve_id in ('${ids.join("','")}')`);
sql(`insert into cve_watchlist (cve_id) values ('${ids[0]}'), ('${ids[1]}')`);
const watched = (id) => sql(`select count(*) from cve_watchlist where cve_id='${id}'`) === "1";

async function run(reducedMotion) {
  const b = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
  const page = await (await b.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: reducedMotion ? "reduce" : "no-preference" })).newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const tag = reducedMotion ? "[reduced-motion] " : "";
  const row = (id) => page.getByRole("row").filter({ hasText: id });
  const star = (id) => row(id).getByRole("button", { name: /beobachten/i });

  await page.goto(`${base}/cves?watchlist=1`);
  await row(ids[0]).waitFor();
  await page.evaluate(() => (window.__noReload = true));

  // Zwei Zeilen gleichzeitig entfernen: je Zeile ein Timer.
  await star(ids[0]).click();
  await page.waitForTimeout(1500);
  await star(ids[1]).click();
  ok(await row(ids[0]).getByText("Entfernt.").isVisible(), `${tag}Hinweis "Entfernt. Rückgängig" in der Zeile`);
  ok((await star(ids[0]).getAttribute("aria-label")) === "Beobachten", `${tag}Stern sofort leer`);
  ok(!watched(ids[0]) && !watched(ids[1]), `${tag}Server hat sofort gespeichert`);
  ok((await page.locator('[role="status"]').allTextContents()).join(" ").includes(`${ids[1]} von der Watchlist entfernt, Rückgängig möglich`), `${tag}aria-live-Ansage`);

  // Zeile 0 nach ~4 s (ab Klick) weg, Zeile 1 noch da (eigener Timer).
  await row(ids[0]).waitFor({ state: "detached", timeout: 5000 });
  ok(await row(ids[1]).isVisible(), `${tag}zweite Zeile hat einen eigenen Timer und bleibt noch`);
  ok(await page.evaluate(() => window.__noReload === true), `${tag}ohne Neuladen verschwunden`);

  // Rückgängig an Zeile 1 bringt die Markierung zurück und bleibt.
  await row(ids[1]).getByRole("button", { name: "Rückgängig" }).click();
  await page.waitForTimeout(5000);
  ok(await row(ids[1]).isVisible() && watched(ids[1]), `${tag}Rückgängig behält die Zeile und speichert`);
  ok((await star(ids[1]).getAttribute("aria-label")) === "Nicht mehr beobachten", `${tag}Stern wieder gefüllt`);

  // Erneut entfernen, dann Filter wechseln: ausstehendes Ausblenden endet sofort.
  await star(ids[1]).click();
  const box = page.getByRole("button", { name: "Nur Watchlist" });
  await box.click();
  await page.waitForURL((u) => !u.searchParams.has("watchlist"));
  await box.click();
  await page.waitForURL((u) => u.searchParams.get("watchlist") === "1");
  ok((await row(ids[1]).count()) === 0, `${tag}Filterwechsel schließt das Ausblenden sofort ab`);

  // Neuladen zeigt den gespeicherten Stand.
  await page.reload();
  await page.getByRole("table").or(page.getByText(/Keine|Noch keine/)).first().waitFor();
  ok((await row(ids[0]).count()) === 0 && (await row(ids[1]).count()) === 0, `${tag}nach Neuladen sind beide weg`);

  // Ohne Filter verschwindet nichts.
  sql(`insert into cve_watchlist (cve_id) values ('${ids[0]}') on conflict do nothing`);
  await page.goto(`${base}/cves?q=${ids[0]}`);
  await row(ids[0]).waitFor();
  await star(ids[0]).click();
  await page.waitForTimeout(4600);
  ok(await row(ids[0]).isVisible(), `${tag}ohne Watchlist-Filter bleibt die Zeile`);
  await b.close();
  sql(`insert into cve_watchlist (cve_id) values ('${ids[0]}'), ('${ids[1]}') on conflict do nothing`);
}

try {
  await run(false);
  await run(true);
} finally {
  sql(`delete from cve_watchlist where cve_id in ('${ids.join("','")}')`);
}
