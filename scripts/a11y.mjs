// axe-core gegen die laufende Web-UI (hell/dunkel, Desktop/mobil). Exit-Code 1 bei Verstößen.
//
//   PW_MODULE=/pfad/zu/node_modules/playwright PW_CHROME=/pfad/zu/chrome AXE_JS=/pfad/zu/axe.min.js \
//   PW_PASSWORD=… node scripts/a11y.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

const base = (process.env.PW_BASE ?? "http://127.0.0.1:3100").replace(/\/$/, "");
const password = process.env.PW_PASSWORD ?? (console.error("PW_PASSWORD setzen"), process.exit(1));
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE ?? "playwright");
const axe = readFileSync(process.env.AXE_JS ?? "node_modules/axe-core/axe.min.js", "utf8");

const PAGES = [
  "/", "/hosts/host:web-01", "/hosts/host:db-01", "/hosts/host:pve-01", "/cves", "/cves/CVE-2024-1086", "/agents", "/notifications",
  "/notifications/ntfy", "/notifications/matrix", "/notifications/discord", "/notifications/browser", "/settings",
];
const viewports = { desktop: { width: 1440, height: 900 }, mobile: { width: 390, height: 844 } };
const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
let total = 0;

async function scan(page, label) {
  await page.evaluate(axe);
  const r = await page.evaluate(() => globalThis.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] }));
  for (const v of r.violations) {
    total += v.nodes.length;
    console.log(`✗ ${label}: ${v.id} (${v.impact}) – ${v.help}`);
    for (const n of v.nodes.slice(0, 3)) console.log(`    ${n.target.join(" ")}\n    ${n.failureSummary?.split("\n").slice(0, 2).join(" ")}`);
  }
  if (r.violations.length === 0) console.log(`✓ ${label}`);
}

for (const scheme of ["light", "dark"]) {
  for (const [vpName, viewport] of Object.entries(viewports)) {
    const ctx = await browser.newContext({ viewport, colorScheme: scheme, reducedMotion: "reduce" });
    const page = await ctx.newPage();
    await page.goto(`${base}/login`);
    await scanLogin(page, `login ${vpName}/${scheme}`);
    await page.getByLabel("Benutzername").fill(process.env.PW_USER ?? "admin");
    await page.getByLabel("Passwort").fill(password);
    await page.getByRole("button", { name: "Anmelden" }).click();
    await page.waitForURL((u) => !u.pathname.startsWith("/login"));
    const ids = Object.fromEntries(await page.evaluate(async () => (await (await fetch("/api/v1/hosts")).json()).map((h) => [h.name, h.id])));
    for (const p of PAGES) {
      await page.goto(base + p.replace(/host:([\w.-]+)/, (_, n) => ids[n]));
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(500);
      await scan(page, `${p} ${vpName}/${scheme}`);
    }
    // Zustände mit Dialog bzw. Menü
    await page.goto(`${base}/agents`);
    await page.getByRole("button", { name: "Agent hinzufügen" }).first().click();
    await scan(page, `/agents (Dialog) ${vpName}/${scheme}`);
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Agent web-01 löschen" }).click();
    await scan(page, `/agents (Bestätigung) ${vpName}/${scheme}`);
    await page.keyboard.press("Escape");
    if (vpName === "mobile") {
      await page.getByRole("button", { name: "Menü" }).click();
      await scan(page, `Menü offen ${scheme}`);
    }
    await ctx.close();
  }
}
async function scanLogin(page, label) {
  await page.getByLabel("Benutzername").waitFor();
  // Der Button ist bis zur Hydration deaktiviert; erst danach ist der Zustand stabil.
  await page.getByRole("button", { name: "Anmelden" }).waitFor();
  await page.waitForFunction(() => !document.querySelector("button[type=submit]")?.disabled);
  await scan(page, label);
}
await browser.close();
console.log(total === 0 ? "\naxe: keine Verstöße" : `\naxe: ${total} Verstöße`);
process.exit(total === 0 ? 0 : 1);
