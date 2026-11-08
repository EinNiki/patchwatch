// E2E: CVE-Seite ohne Umfangsfeld. Feld nicht im DOM, alte URLs (releases=all, scope=all) ohne Fehler und wie der feste
// Wert, Chips anderer Releases ändern den Filter nicht, Leer-Zustand mit aktiven Filtern und "Filter zurücksetzen", axe.
// Die CVE-Liste wird per page.route nachgestellt; der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-cves-scope.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const json = (status, body) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

const chip = (release, mine, status = "vulnerable") => ({ source: "ubuntu", release, package: "linux", status, fix_version: null, suites: null, updated_at: null, mine, packages: 1 });
const cve = (id, hidden) => ({ id, description: "Testeintrag", published_at: null, priority: "high", level: "high", watched: false, source_updated_at: null, hosts_affected: 1, hosts: [{ id: 1, name: "web-01", status: "vulnerable" }], distros: [chip("noble", true)], hidden_releases: hidden });
let seenQuery = [];
let list = [cve("CVE-2026-70001", 2)];

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.route(/\/api\/v1\/cves\?/, (r) => { seenQuery.push(new URL(r.request().url()).search); return r.fulfill(json(200, list)); });
  await page.route(/\/api\/v1\/cves\/scope-count\?/, (r) => r.fulfill(json(200, { mine: list.length, all: list.length, affecting: list.length })));
  await page.route(/\/api\/v1\/cves\/CVE-2026-70001$/, (r) => r.fulfill(json(200, { id: "CVE-2026-70001", distros: [chip("noble", true), chip("focal", false), chip("bionic", false, "fixed")] })));

  for (const [w, scheme] of [[1440, "light"], [390, "dark"], [768, "light"], [1920, "dark"]]) {
    const L = `${w}/${scheme}`;
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: w, height: 900 });
    for (const url of ["/cves", "/cves?releases=all", "/cves?scope=all&umfang=alle"]) {
      seenQuery = [];
      errors.length = 0;
      await page.goto(`${base}${url}`);
      await page.getByText("CVE-2026-70001").first().waitFor();
      ok((await page.getByText("Umfang").count()) === 0, `${L} ${url}: kein Text "Umfang"`);
      ok((await page.getByRole("combobox", { name: /Umfang/ }).count()) === 0 && (await page.locator("option", { hasText: /Releases/ }).count()) === 0, `${L} ${url}: kein Auswahlfeld für Releases`);
      ok((await page.getByText("Alle Releases").count()) === 0, `${L} ${url}: kein "Alle Releases"`);
      ok((await page.getByText("Filter berücksichtigen nur Releases deiner Hosts.").count()) === 1, `${L} ${url}: Legende vorhanden`);
      ok(seenQuery.length > 0 && seenQuery.every((q) => !/releases=|scope=|umfang=/.test(q)), `${L} ${url}: Abfrage ohne Umfangsparameter (${seenQuery[0] ?? ""})`);
      ok(errors.length === 0, `${L} ${url}: keine Fehler in der Konsole (${errors[0] ?? "ok"})`);
    }
    // Chips anderer Releases: eingeklappt hinter "+ 2 weitere Releases", ändern Filter und URL nicht.
    await page.goto(`${base}/cves?debian=fixed`);
    const more = page.getByRole("button", { name: /\+ 2 weitere Releases/ });
    await more.waitFor();
    const urlBefore = page.url();
    await more.click();
    await page.getByText("focal").first().waitFor();
    const dashed = await page.getByText("focal").first().evaluate((e) => { let n = e; while (n && getComputedStyle(n).borderStyle !== "dashed") n = n.parentElement; return !!n; });
    ok(dashed, `${L}: Chip eines Releases ohne Host ist gestrichelt abgesetzt`);
    await page.getByText("focal").first().click();
    ok(page.url() === urlBefore, `${L}: Klick auf den Chip ändert URL und Filter nicht`);
    // Leer-Zustand
    list = [];
    await page.goto(`${base}/cves?debian=fixed&ubuntu=open`);
    await page.getByText("Aktive Filter:").waitFor();
    const empty = await page.locator("main").innerText();
    ok(/Aktive Filter: .*Debian.*Ubuntu/.test(empty) && !/Umfang|Alle Releases|Releases ohne Host/.test(empty), `${L}: Leer-Zustand nennt nur die aktiven Filter`);
    ok((await page.getByRole("button", { name: "Filter zurücksetzen" }).count()) === 1, `${L}: "Filter zurücksetzen" vorhanden`);
    await page.getByRole("button", { name: "Filter zurücksetzen" }).click();
    await page.waitForFunction(() => !location.search.includes("debian="));
    ok(!page.url().includes("debian="), `${L}: Zurücksetzen entfernt die Filter`);
    if (shots) { list = [cve("CVE-2026-70001", 2)]; await page.goto(`${base}/cves`); await page.getByText("CVE-2026-70001").first().waitFor(); await page.waitForTimeout(300); await page.screenshot({ path: `${shots}/cves-scope-${w}-${scheme}.png` }); }
    list = [cve("CVE-2026-70001", 2)];
    await page.goto(`${base}/cves`);
    await page.getByText("CVE-2026-70001").first().waitFor();
    await page.evaluate(axeSrc);
    const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
    ok(v.length === 0, `${L}: axe ${v.join(", ") || "keine Verstöße"}`);
  }
} finally {
  await browser.close();
}
