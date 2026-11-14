// E2E: Spalte „CVE“ der Hostliste – zwei Einträge je Reihe, Reihenfolge nach Wichtigkeit, Einträge mit 0 entfallen, „+N“ bei mehr als
// vier Einträgen (mit Popover), Zeilenhöhe ≤ 64 px, Klick führt gefiltert zur Host-Seite, kein Überlauf, axe. Die Hostliste wird nachgestellt.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=… node scripts/e2e-hostlist-cve.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axe = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log("PAGEERR", e.message.slice(0, 300)));
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const real = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const mk = (i, name, o) => ({ ...real[0], id: 9000 + i, name, hostname: name, is_proxmox: false, status: "cve_vulnerable", cve_vulnerable: 0, cve_fix_pending: 0, cve_reboot: 0, cve_unknown: 0, cve_fixed: 0, cve_source_issue: null, ...o });
  const HOSTS = [
    mk(1, "demo-vier", { cve_vulnerable: 29, cve_reboot: 134, cve_unknown: 2, cve_fixed: 5718 }),
    mk(2, "demo-nur-gefixt", { cve_fixed: 100, status: "ok" }),
    mk(3, "demo-fuenf", { cve_vulnerable: 5, cve_fix_pending: 3, cve_reboot: 2, cve_unknown: 1, cve_fixed: 7 }),
  ];
  await page.route(/\/api\/v1\/hosts$/, (r) => (r.request().method() === "GET" ? r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(HOSTS) }) : r.continue()));
  const cell = (name) => page.locator("tbody tr", { hasText: name }).first().locator("td").nth(4);

  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    for (const w of [1024, 1280, 1440, 1920, 2560]) {
      const tag = `${w}px ${scheme}`;
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(`${base}/`);
      await page.locator("tbody tr", { hasText: "demo-vier" }).first().waitFor({ timeout: 8000 }).catch(async (e) => { console.log(page.url(), (await page.locator("body").innerText()).slice(0, 400)); throw e; });
      // Spalte CVE ist ab 768 px die fünfte Zelle (Host, Distribution, [Gemeldet], [Updates], CVE …); Index über den Kopf bestimmen.
      const idx = await page.evaluate(() => [...document.querySelectorAll("table.tbl thead th")].filter((h) => h.getBoundingClientRect().width > 0).findIndex((h) => h.textContent.trim().startsWith("CVE")));
      const c = (name) => page.locator("tbody tr", { hasText: name }).first().locator("td").filter({ visible: true }).nth(idx);
      // Vier Einträge: 2 × 2, Reihenfolge, keine „+N“.
      const four = c("demo-vier");
      const texts = (await four.locator("a").allInnerTexts()).map((t) => t.replace(/\s+/g, " ").trim());
      ok(JSON.stringify(texts) === JSON.stringify(["29 offen", "134 Neustart", "5.718 gefixt"]), `${tag}: Reihenfolge offen, Neustart, gefixt (kein „unbekannt“) (${texts})`);
      const b = await four.locator("a").evaluateAll((l) => l.map((a) => { const r = a.getBoundingClientRect(); return [r.x, r.y, r.width]; }));
      ok(Math.abs(b[0][1] - b[1][1]) <= 1 && Math.abs(b[2][1] - b[3][1]) <= 1 && b[2][1] > b[0][1] + 8, `${tag}: zwei Einträge je Reihe`);
      ok(Math.abs(b[1][0] - b[3][0]) <= 1 && Math.abs(b[0][0] - b[2][0]) <= 1, `${tag}: zweite Spalte beginnt an derselben Stelle`);
      ok((await four.getByRole("button", { name: /weitere/ }).count()) === 0, `${tag}: bei vier Einträgen kein „+N“`);
      if (w >= 1280) {
        const rh = await page.locator("tbody tr", { hasText: "demo-vier" }).first().evaluate((r) => r.getBoundingClientRect().height);
        ok(rh <= 64.5, `${tag}: Zeilenhöhe ≤ 64 px (${Math.round(rh)})`);
      }
      // Einträge mit 0 fehlen.
      const only = (await c("demo-nur-gefixt").locator("a").allInnerTexts()).map((t) => t.replace(/\s+/g, " ").trim());
      ok(JSON.stringify(only) === JSON.stringify(["100 gefixt"]), `${tag}: Einträge mit 0 entfallen (${only})`);
      // „unbekannt“ wird nie als Eintrag gezeigt: fünf Zähler des Servers ergeben vier Einträge, kein „+N“.
      const five = c("demo-fuenf");
      ok((await five.locator("a").count()) === 4, `${tag}: vier Einträge, kein „unbekannt“`);
      ok((await five.getByRole("button", { name: /weitere Angaben/ }).count()) === 0, `${tag}: kein „+N“`);
      if (w === 1440) {
        await page.evaluate(axe);
        const v = await page.evaluate(() => globalThis.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag22aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}:${x.nodes[0]?.target}`)));
        ok(v.filter((x) => !/^(region|landmark|page-has)/.test(x)).length === 0, `${tag}: axe ${v.join(", ")}`);
      }
      // Überlauf und Überlappung.
      const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      ok(over <= 0, `${tag}: kein Seitenüberlauf (${over})`);
      const inCell = await four.evaluate((td) => { const r = td.getBoundingClientRect(); return [...td.querySelectorAll("a")].every((a) => { const x = a.getBoundingClientRect(); return x.left >= r.left - 1 && x.right <= r.right + 1; }); });
      ok(inCell, `${tag}: Einträge liegen in der Zelle`);
      const right = await page.evaluate(() => { const t = document.querySelector("table.tbl"); const ths = [...t.querySelectorAll("thead th")].filter((h) => h.getBoundingClientRect().width > 0); return Math.abs(ths[ths.length - 1].getBoundingClientRect().right - (innerWidth - 24)); });
      ok(right <= 1.5, `${tag}: Tabelle reicht bis zum Rand (${right.toFixed(1)})`);
    }
  }
  // Klick auf einen Eintrag führt gefiltert zur Host-Seite.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}/`);
  await page.locator("tbody tr", { hasText: "demo-vier" }).first().waitFor();
  const idx2 = await page.evaluate(() => [...document.querySelectorAll("table.tbl thead th")].filter((h) => h.getBoundingClientRect().width > 0).findIndex((h) => h.textContent.trim().startsWith("CVE")));
  await page.locator("tbody tr", { hasText: "demo-vier" }).first().locator("td").filter({ visible: true }).nth(idx2).getByRole("link", { name: /Neustart/ }).click();
  await page.waitForURL(/\/hosts\/9001\?cve=reboot/);
  ok(/cve=reboot/.test(page.url()), "Klick auf „Neustart“ führt mit Filter zur Host-Seite");
} finally {
  await browser.close();
}
