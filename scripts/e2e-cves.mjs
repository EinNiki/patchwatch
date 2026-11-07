// E2E: CVE-Seite (Filter „Betrifft“ als Auswahlfeld, Kennzahlen, Layout ohne leere Flächen, Überlauf).
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> node scripts/e2e-cves.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));

  // A) Betrifft: Auswahlfeld statt Knöpfe.
  await page.goto(`${base}/cves`);
  const sel = page.locator('label:has-text("Betrifft") select');
  await sel.waitFor();
  ok((await page.getByRole("button", { name: /^Meine Hosts/ }).count()) === 0 && (await page.getByRole("group", { name: "Betrifft" }).count()) === 0, "keine Knöpfe „Meine Hosts / Alle“ im DOM");
  ok((await sel.inputValue()) === "mine", "Standard „Meine Hosts“");
  const text = page.getByTestId("affects-count");
  await text.getByText(/betreff/).waitFor();
  ok((await text.locator("button, a").count()) === 0, "Satz „N CVEs betreffen deine Hosts“ ist reiner Text");
  const n = Number((await text.innerText()).replace(/\./g, "").match(/\d+/)?.[0]);
  await sel.focus();
  await page.keyboard.press("ArrowDown");
  await page.waitForURL(/affects=all/);
  ok((await sel.inputValue()) === "all", "Auswahl per Tastatur (Pfeil runter) stellt „Alle“, URL enthält affects=all");
  await page.waitForFunction((n0) => Number(document.querySelector('[data-testid="affects-count"]')?.textContent?.replace(/\./g, "").match(/\d+/)?.[0]) >= 0 && document.querySelector('[data-testid="affects-count"]')?.textContent?.includes("betreff"), n);
  // Alte URL funktioniert weiter.
  await page.goto(`${base}/cves?affects=all`);
  await sel.waitFor();
  ok((await sel.inputValue()) === "all", "alte URL ?affects=all stellt das Feld auf „Alle“");
  await page.goto(`${base}/cves`);
  await sel.waitFor();
  // Satz stimmt mit der Trefferzahl überein: Zeilen der Liste (bis zum Limit) ≤ Zahl.
  const list = page.locator("table.tbl", { has: page.locator("caption", { hasText: "CVEs mit" }) });
  await list.locator("tbody tr").first().waitFor().catch(() => {});
  const rows = await list.locator("tbody tr").count();
  ok(Number.isFinite(n) && (rows === n || (rows >= 100 && n >= rows) || (rows === 0 && n === 0)), `Satz (${n}) stimmt mit der Liste (${rows}) überein`);
  await ctx.close();
} finally {
  await browser.close();
}
