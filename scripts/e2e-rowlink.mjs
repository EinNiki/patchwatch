// E2E: ganze Zeile der Hostliste ist klickbar (Maus, Touch), der Hostname bleibt der echte Link; Ausnahmen, Tastatur, Fokusring,
// Strg-/Mittelklick, Textauswahl, CVE-Zelle mit Filter, Agents-Zeile bleibt unberührt, axe. Nur Lesezugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… node scripts/e2e-rowlink.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
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
  const hosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const host = hosts[0];
  const target = `/hosts/${host.id}`;
  const row = () => page.locator("table.tbl tbody tr", { has: page.getByRole("link", { name: host.name, exact: true }) }).first();
  const open = async () => { await page.goto(`${base}/`); await row().waitFor(); };
  const path = () => new URL(page.url()).pathname;

  await open();
  // Aufbau: nur ein Link zum Host in der Zeile (Name), kein verschachtelter Link, kein role=link auf der Zeile.
  ok((await row().locator(`a[href="${target}"]`).count()) === 1, "genau ein Link zur Host-Seite im Hostnamen");
  ok((await page.locator("a a, tr[role=link], td[role=link]").count()) === 0, "kein verschachtelter Link, kein role=link auf Zeile/Zelle");
  ok((await page.getByRole("link", { name: host.name, exact: true }).count()) === 1, "Screenreader-Name der Zeile: Link heißt wie der Host");
  ok((await row().evaluate((e) => getComputedStyle(e).cursor)) === "pointer", "cursor: pointer auf der Zeile");

  // Klick auf freie Zelle (Updates) navigiert.
  await row().locator("td").nth(3).click({ position: { x: 4, y: 4 } });
  await page.waitForURL(`**${target}`);
  ok(path() === target, "Klick auf freie Zelle führt zur Host-Seite");

  // Klick auf den Hostnamen: genau eine Navigation (ein Verlaufseintrag mehr).
  await open();
  const before = await page.evaluate(() => history.length);
  await page.getByRole("link", { name: host.name, exact: true }).click();
  await page.waitForURL(`**${target}`);
  await page.waitForTimeout(400);
  ok(path() === target && (await page.evaluate(() => history.length)) === before + 1, "Klick auf Hostname: eine Navigation, kein Doppel");

  // Strg-Klick und Mittelklick öffnen einen neuen Tab, die Liste bleibt.
  await open();
  let [tab] = await Promise.all([ctx.waitForEvent("page"), row().locator("td").nth(3).click({ modifiers: ["Control"], position: { x: 4, y: 4 } })]);
  ok(new URL(tab.url()).pathname === target || (await tab.waitForURL(`**${target}`).then(() => true)), "Strg-Klick öffnet neuen Tab mit der Host-Seite");
  ok(path() === "/", "Strg-Klick: Liste bleibt im alten Tab");
  await tab.close();
  [tab] = await Promise.all([ctx.waitForEvent("page"), row().locator("td").nth(3).click({ button: "middle", position: { x: 4, y: 4 } })]);
  await tab.waitForURL(`**${target}`);
  ok(path() === "/", "Mittelklick öffnet neuen Tab, Liste bleibt");
  await tab.close();

  // Textauswahl: Klick navigiert nicht.
  await open();
  const navigated = await row().locator("td").nth(1).evaluate((td) => {
    const r = document.createRange();
    r.selectNodeContents(td);
    const s = getSelection();
    s.removeAllRanges();
    s.addRange(r);
    td.dispatchEvent(new MouseEvent("click", { bubbles: true, button: 0 }));
    return new Promise((res) => setTimeout(() => res(location.pathname !== "/"), 400));
  });
  ok(!navigated, "markierter Text: Klick navigiert nicht");

  // Tastatur: Tab auf den Link, Fokusring um die ganze Zeile, Enter navigiert.
  await open();
  await page.getByRole("link", { name: host.name, exact: true }).focus();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Shift+Tab");
  const ring = await row().evaluate((e) => { const s = getComputedStyle(e); return `${s.outlineStyle} ${s.outlineWidth}`; });
  ok(ring === "solid 2px", `Fokusring um die ganze Zeile (${ring})`);
  await page.keyboard.press("Enter");
  await page.waitForURL(`**${target}`);
  ok(path() === target, "Tastatur: Enter auf dem Link navigiert");

  // CVE-Zelle: freier Bereich führt gefiltert zur Host-Seite.
  await open();
  const cell = row().locator("td[data-href]").first();
  const dh = await cell.getAttribute("data-href");
  const box = await cell.boundingBox();
  await page.mouse.click(box.x + box.width - 3, box.y + box.height - 3);
  await page.waitForURL(`**${target}?cve=*`);
  ok(dh.startsWith(`${target}?cve=`) && page.url().includes(dh), `CVE-Zelle führt mit Filter zur Host-Seite (${dh})`);

  // Bedienelemente in der Zeile (Link in der CVE-Zelle) behalten ihre Aktion: nur eine Navigation.
  await open();
  const cveLink = row().locator("td[data-href] a").first();
  if (await cveLink.count()) {
    const h0 = await page.evaluate(() => history.length);
    const want = await cveLink.getAttribute("href");
    await cveLink.click();
    await page.waitForURL(`**${want}`);
    await page.waitForTimeout(400);
    ok((await page.evaluate(() => history.length)) === h0 + 1, "Link in der CVE-Zelle: eine Navigation, eigenes Ziel");
  }

  // Agents-Tabelle: Zeilen mit eigenen Aktionen sind nicht klickbar, nur der Name ist Link.
  await page.goto(`${base}/agents`);
  await page.locator("table.tbl tbody tr").first().waitFor();
  ok((await page.locator("table.tbl tbody tr[data-rowlink]").count()) === 0, "Agents: Zeilen nicht klickbar");
  await page.locator("table.tbl tbody tr").first().locator("td").nth(2).click({ position: { x: 4, y: 4 } });
  await page.waitForTimeout(300);
  ok(path() === "/agents", "Agents: Klick auf freie Zelle navigiert nicht");

  // Fenster offen: Zeile nicht klickbar (Dialog "Agent hinzufügen" liegt darüber).
  await page.getByRole("button", { name: /Agent hinzufügen/ }).first().click();
  await page.waitForTimeout(300);
  await page.keyboard.press("Escape");

  // axe auf der Hostliste.
  await open();
  await page.evaluate(axeSrc);
  const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
  ok(v.length === 0, `axe ${v.join(", ") || "keine Verstöße"}`);

  // Touch: Tippen auf die Zeile navigiert; keine Hover-Hervorhebung auf Touchgeräten.
  const tctx = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  const tp = await tctx.newPage();
  await tp.goto(`${base}/login`);
  await tp.getByLabel("Benutzername").fill("admin");
  await tp.getByLabel("Passwort").fill(pw);
  await tp.getByRole("button", { name: "Anmelden" }).click();
  await tp.waitForURL((u) => !u.pathname.startsWith("/login"));
  await tp.goto(`${base}/`);
  const trow = tp.locator("table.tbl tbody tr").first();
  await trow.waitFor();
  ok(!(await tp.evaluate(() => matchMedia("(hover: hover)").matches)), "Touchgerät meldet kein Hover (Hover-Stil greift nicht)");
  // Die erste Zeile der Liste ist nach Dringlichkeit sortiert und nicht zwingend `hosts[0]` der API: Ziel aus ihrem Link lesen.
  const touchTarget = await trow.locator("a[href^='/hosts/']").first().getAttribute("href");
  await trow.locator("td").nth(1).tap({ position: { x: 4, y: 4 } });
  await tp.waitForURL((u) => u.pathname === touchTarget);
  ok(new URL(tp.url()).pathname === touchTarget, "Touch: Tippen auf die Zeile führt zur Host-Seite");
  await tctx.close();
} finally {
  await browser.close();
}
