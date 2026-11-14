// E2E: CopyButton/CodeField (nur Symbol, 16 px, Zeilenhöhe, Zwischenablage-Inhalt, Rückfall ohne navigator.clipboard,
// Fehlerfall mit Warn-Toast und markiertem Text, Tastatur, Touch-Trefferfläche, axe, Screenshots).
// Seiten: Agents (Befehl), CVE-Fenster der Host-Seite (per page.route nachgestellte Liste). Keine Schreibzugriffe am Server.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=<axe.min.js> [PW_SHOTS=<Ordner>] node scripts/e2e-copy.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const CMD = "sudo patchwatch-agent-update";
const UPDATE = "sudo apt update && sudo apt upgrade";

const gen = (n) => Array.from({ length: n }, (_, i) => ({
  cve_id: `CVE-2026-${String(10000 + i)}`, status: "vulnerable", reason: "Fix im Archiv", computed_at: "2026-11-01T10:00:00Z",
  sources: [{ source: "debian", release: "trixie", package: "linux", status: "resolved", fix_version: "6.12.5-1" }],
  description: "Beispiel", priority: "medium", watched: false, reviewed_at: null, reviewed_by: null, level: 5, fix_version: "6.12.5-1", source: "debian", published_at: "2026-10-01T00:00:00Z",
}));

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light", hasTouch: true });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"], { origin: base });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const hosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const host = hosts[0];
  await page.route(new RegExp(`/api/v1/hosts/${host.id}/cves\\?(?!limit=1$)`), async (r) => {
    const url = new URL(r.request().url());
    if (url.pathname.endsWith("/groups")) return r.fallback();
    const real = await (await r.fetch()).json();
    return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...real, items: gen(3), total: 3 }) });
  });
  const toasts = () => page.getByRole("region", { name: "Benachrichtigungen" });

  async function structure(scope, label, L) {
    const btn = scope.getByRole("button", { name: label }).first();
    ok(await btn.isVisible(), `${L}: Symbolknopf "${label}" vorhanden`);
    ok((await btn.innerText()).trim() === "", `${L}: kein Text im Knopf (nur Symbol)`);
    ok(await btn.getAttribute("title") === label, `${L}: Tooltip ${label}`);
    const g = await btn.evaluate((el) => {
      const svg = el.querySelector("svg"); const s = svg.getBoundingClientRect(); const b = el.getBoundingClientRect();
      const code = el.parentElement.querySelector("code"); const lh = parseFloat(getComputedStyle(code).lineHeight);
      return { svg: [Math.round(s.width), Math.round(s.height)], sw: svg.getAttribute("stroke-width"), btn: Math.round(b.height), lh, fieldW: el.parentElement.getBoundingClientRect().width, vw: innerWidth, hit: Math.round(parseFloat(getComputedStyle(el, "::before").height) || 0) };
    });
    ok(g.svg[0] === 16 && g.svg[1] === 16 && g.sw === "1.5", `${L}: Symbol 16 px, Linie 1.5 (${g.svg})`);
    ok(g.btn <= 44 && g.btn >= g.lh - 1, `${L}: Knopfhöhe ${g.btn} px passt zur Zeilenhöhe ${g.lh} px`);
    ok(g.fieldW <= g.vw, `${L}: Codefeld passt in den Bildschirm`);
    return btn;
  }

  for (const [w, h, scheme] of [[1440, 900, "light"], [1920, 1000, "dark"], [768, 900, "light"], [390, 800, "dark"]]) {
    const L = `${w}/${scheme}`;
    await page.setViewportSize({ width: w, height: h });
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(`${base}/agents`);
    await page.getByText(CMD).first().waitFor();
    ok((await page.getByRole("button", { name: /^(Befehl|Token) kopieren$/ }).filter({ hasText: /\S/ }).count()) === 0, `${L}: kein Textknopf "Befehl kopieren" im DOM`);
    const btn = await structure(page.locator("main"), "Befehl kopieren", L);
    if (w < 768) {
      const hit = await btn.evaluate((el) => { const r = el.getBoundingClientRect(); return { w: r.width, h: r.height }; });
      ok(hit.w >= 44 && hit.h >= 44, `${L}: Trefferfläche mobil >= 44 px (${hit.w}x${hit.h})`);
    }
    // Klick: Zwischenablage, Haken, Toast.
    await btn.click();
    ok((await page.evaluate(() => navigator.clipboard.readText())) === CMD, `${L}: Zwischenablage enthält den Befehl`);
    ok(await toasts().getByText("In die Zwischenablage kopiert").isVisible(), `${L}: Erfolgs-Toast`);
    ok(await btn.locator("svg path").count() === 1, `${L}: Haken nach dem Klick`);
    await page.waitForTimeout(1800);
    ok(await btn.locator("svg rect").count() === 1, `${L}: Symbol kehrt nach 1,5 s zurück`);
    // Tastatur.
    await page.evaluate(() => navigator.clipboard.writeText("leer"));
    await page.keyboard.press("Shift"); // Tastaturmodus, damit :focus-visible greift
    await btn.focus();
    ok(await btn.evaluate((el) => getComputedStyle(el).outlineStyle !== "none" || getComputedStyle(el).boxShadow !== "none"), `${L}: Fokus sichtbar`);
    await page.keyboard.press("Enter");
    ok((await page.evaluate(() => navigator.clipboard.readText())) === CMD, `${L}: Enter kopiert`);
    await page.waitForTimeout(1800);
    await page.evaluate(() => navigator.clipboard.writeText("leer"));
    await page.keyboard.press("Space");
    ok((await page.evaluate(() => navigator.clipboard.readText())) === CMD, `${L}: Leertaste kopiert`);
    await page.evaluate(axeSrc);
    const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
    ok(v.length === 0, `${L}: axe Agents ${v.join(", ") || "keine Verstöße"}`);
    if (shots) await page.locator("main").screenshot({ path: `${shots}/copy-agents-${w}-${scheme}.png` });

    // CVE-Fenster der Host-Seite.
    await page.goto(`${base}/hosts/${host.id}`);
    const open = page.getByRole("button", { name: "Details zu CVE-2026-10000" }).first();
    await open.waitFor();
    await (w < 768 ? open.tap() : open.click());
    const dlg = page.getByRole("dialog", { name: "CVE-2026-10000" });
    await dlg.waitFor();
    await page.waitForTimeout(400);
    ok((await dlg.getByRole("button", { name: "Befehl kopieren" }).filter({ hasText: /\S/ }).count()) === 0, `${L}: Fenster ohne Textknopf`);
    const dbtn = await structure(dlg, "Befehl kopieren", `${L} Fenster`);
    await dbtn.click();
    ok((await page.evaluate(() => navigator.clipboard.readText())) === UPDATE, `${L}: Fenster kopiert den Update-Befehl`);
    const noteText = await dlg.locator("[role=note]").innerText();
    ok(noteText.includes("Update einspielen:") && noteText.includes("Danach Neustart"), `${L}: Befehl steht im eigenen Feld, nicht mitten im Satz`);
    await page.evaluate(axeSrc);
    const v2 = await page.evaluate(() => axe.run(document.querySelector("dialog[open]"), { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
    ok(v2.length === 0, `${L}: axe Fenster ${v2.join(", ") || "keine Verstöße"}`);
    if (shots) await page.screenshot({ path: `${shots}/copy-dialog-${w}-${scheme}.png` });
    await page.keyboard.press("Escape");
    await dlg.waitFor({ state: "hidden" });
  }

  // Rückfall ohne navigator.clipboard (http://<IP>): execCommand wird aufgezeichnet und bestätigt.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto(`${base}/agents`);
  await page.getByText(CMD).first().waitFor();
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
    window.__legacy = [];
    document.execCommand = (cmd) => { const a = document.activeElement; window.__legacy.push([cmd, a && "value" in a ? a.value : null]); return true; };
  });
  await page.getByRole("button", { name: "Befehl kopieren" }).first().click();
  const legacy = await page.evaluate(() => window.__legacy);
  ok(legacy.length === 1 && legacy[0][0] === "copy" && legacy[0][1] === CMD, `Rückfall: execCommand("copy") mit dem Befehl (${JSON.stringify(legacy)})`);
  ok(await toasts().getByText("In die Zwischenablage kopiert").isVisible(), "Rückfall: Erfolgs-Toast");
  ok((await page.locator("textarea[aria-hidden=true]").count()) === 0, "Rückfall: verstecktes Textfeld wieder entfernt");

  // Fehlerfall: weder API noch execCommand: Warn-Toast und markierter Text im Codefeld.
  await page.evaluate(() => { document.execCommand = () => false; });
  await page.getByRole("button", { name: "Befehl kopieren" }).first().click();
  ok(await toasts().getByText("Kopieren nicht möglich. Text markiert, mit Strg+C kopieren.").isVisible(), "Fehlerfall: Warn-Toast");
  ok((await page.evaluate(() => window.getSelection().toString())) === CMD, "Fehlerfall: Text im Codefeld ist markiert");
  if (shots) await page.locator("main").screenshot({ path: `${shots}/copy-fail.png` });
} finally {
  await browser.close();
}
