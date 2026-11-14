// E2E: Host-Seite – vier gleich große CVE-Kacheln (Raster 4 / 2×2 / 1 Spalte), keine abgeschnittenen Texte, Mindestbreite 200 px unter 1280 px, Spalte „Host-Details“
// am Inhaltsrand, kein Seitenüberlauf, kein „sudo reboot“, axe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=… node scripts/e2e-hostcards.mjs
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
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const hosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  // Bevorzugt ein Host mit Neustart (Textzeile „Neustart nötig“), sonst der erste.
  const host = hosts.find((h) => h.reboot_needed) ?? hosts[0];
  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    for (const w of [390, 768, 1024, 1280, 1440, 1920, 2560]) {
      const tag = `${w}px ${scheme}`;
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(`${base}/hosts/${host.id}`);
      const tiles = page.locator('[role="group"][aria-label^="CVE"] > button[aria-pressed]');
      await tiles.first().waitFor();
      await page.waitForFunction(() => ![...document.querySelectorAll('[role="group"][aria-label^="CVE"] > button[aria-pressed]')].some((b) => b.textContent.includes("…")));
      await page.waitForTimeout(300);
      ok((await tiles.count()) === 3, `${tag}: drei Kacheln (Offen, Neustart nötig, Gefixt), keine „Unbekannt“-Kachel`);
      const m = await tiles.evaluateAll((l) => l.map((b) => { const r = b.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, cut: [b, ...b.querySelectorAll("*")].some((e) => e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflow !== "visible"), right: r.right, text: b.textContent }; }));
      ok(m.every((t) => !t.cut), `${tag}: kein abgeschnittener Text in den Kacheln`);
      const perRow = w >= 1280 ? 4 : w >= 640 ? 2 : 1;
      const rows = new Map();
      for (const t of m) rows.set(Math.round(t.y), [...(rows.get(Math.round(t.y)) ?? []), t]);
      ok([...rows.values()].every((r, i, a) => r.length === perRow || (i === a.length - 1 && r.length <= perRow)), `${tag}: ${perRow} Kachel(n) je Reihe (${[...rows.values()].map((r) => r.length)})`);
      ok(Math.max(...m.map((t) => t.w)) - Math.min(...m.map((t) => t.w)) <= 1, `${tag}: gleich breit (${m.map((t) => Math.round(t.w))})`);
      for (const r of rows.values()) ok(Math.max(...r.map((t) => t.h)) - Math.min(...r.map((t) => t.h)) <= 1, `${tag}: gleich hoch je Reihe`);
      ok(m.every((t) => t.right <= w), `${tag}: Kacheln im Fenster`);
      // Mindestbreite 200 px unter 1280 px: Raster in einen schmalen Container zwingen; die Spalten dürfen nicht unter 200 px schrumpfen.
      if (w < 1280) {
        const narrow = await page.evaluate(() => {
          const g = document.querySelector('[role="group"][aria-label^="CVE"]');
          const old = g.style.width;
          g.style.width = "300px";
          const ws = [...g.children].map((c) => c.getBoundingClientRect().width);
          g.style.width = old;
          return Math.min(...ws);
        });
        ok(narrow >= 199.5, `${tag}: Kacheln nie schmaler als 200 px (${Math.round(narrow)})`);
      }
      ok(!m.some((t) => /nbekannt/.test(t.text)), `${tag}: keine Kachel „Unbekannt“`);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      ok(over <= 0, `${tag}: kein Seitenüberlauf (${over})`);
      ok((await page.getByText("sudo reboot").count()) === 0 && (await page.locator('[aria-label*="sudo reboot"],[title*="sudo reboot"]').count()) === 0, `${tag}: kein „sudo reboot“ im DOM`);
      if (w >= 1280) {
        const a = await page.locator('aside[aria-labelledby="facts"]').boundingBox();
        const main = await page.evaluate(() => { const m = document.querySelector("main"); const r = m.getBoundingClientRect(); return r.right - 24; });
        ok(a && a.x + a.width <= main + 1 && a.x + a.width >= main - 2, `${tag}: Host-Details enden am Inhaltsrand (${Math.round(a?.x + a?.width)} / ${Math.round(main)})`);
      } else {
        ok((await page.locator('aside[aria-labelledby="facts"]').isVisible()) === false, `${tag}: Details nicht als Seitenspalte`);
        ok((await page.locator("summary", { hasText: "Host-Details" }).first().isVisible()), `${tag}: Details aufklappbar unter den Kacheln`);
      }
      if ([390, 1024, 1440].includes(w)) {
        await page.evaluate(axe);
        const v = await page.evaluate(() => globalThis.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag22aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}:${x.nodes[0]?.target}`)));
        ok(v.filter((x) => !/^(region|landmark|page-has)/.test(x)).length === 0, `${tag}: axe ${v.join(", ")}`);
      }
    }
  }
} finally {
  await browser.close();
}
