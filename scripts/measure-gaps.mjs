// Misst den sichtbaren Abstand zwischen dem Inhalt benachbarter Spalten (rechter Rand des gefüllten Inhalts der Spalte bis
// linker Rand des Inhalts der nächsten) je Zeile; Ergebnis: Median je Spaltenpaar. Nur Lesezugriffe.
//   node scripts/measure-gaps.mjs [Pfad=/] [Breiten=1440,1920]
//   PW_SCHEDULE=1: /settings wird mit einem Server-Zeitplan gemockt (lange „Aktualisierung“-Zelle auf /agents).
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { measure } from "./lib/gaps.mjs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const path = process.argv[2] ?? "/";
const widths = (process.argv[3] ?? "1440,1920").split(",").map(Number);
// CSS-Selektor der Tabelle (Standard: erste); die CVE-Seite hat zwei Tabellen (Quellen, CVE-Liste).
const sel = process.argv[4] ?? "table.tbl";

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  if (process.env.PW_SCHEDULE) {
    const st = await page.evaluate(() => fetch("/api/v1/settings").then((r) => r.json()));
    const sched = { ...st.report_schedule, mode: "interval", every_hours: 6, next_run: new Date(Date.now() + 3 * 3600e3).toISOString() };
    await page.route(/\/api\/v1\/settings$/, (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...st, report_schedule: sched }) }));
  }
  for (const w of widths) {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${base}${path}`);
    await page.locator(`${sel} tbody tr`).first().waitFor();
    await page.waitForTimeout(500);
    const r = await page.evaluate(measure, sel);
    console.log(`--- ${path} ${w}px (Überlauf ${r.overflow}) Spaltenbreiten: ${r.cols.join(" | ")}`);
    for (const p of r.pairs) console.log(`${String(p.gap).padStart(4)} px  (Kopf ${String(p.headGap).padStart(4)})  ${p.pair}`);
  }
} finally {
  await browser.close();
}
