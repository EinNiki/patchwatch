// E2E: Toast-System (Zeiten, Zusammenfassen, Pausieren, Obergrenze, Escape, Rollen, reduzierte Bewegung) gegen den laufenden Stack.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> node scripts/e2e-toasts.mjs
// Antworten werden im Browser per page.route nachgestellt; der Server bekommt keine Schreibzugriffe.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function open(browser, opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ...opts });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  return page;
}

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const page = await open(browser);
  await page.goto(`${base}/agents`);
  const region = page.getByRole("region", { name: "Benachrichtigungen" });
  ok((await region.count()) === 1, "Bereich „Benachrichtigungen“ vorhanden");
  const box = await region.boundingBox();
  ok(box !== null && box.y < 120 && box.x + box.width > 1440 - 40, "Bereich liegt oben rechts");

  // 1) Fehler: bleibt stehen (kein Ablauf), Rolle alert, Zusammenfassen ×3 innerhalb von 5 s.
  await page.route("**/api/v1/hosts/request-report", (r) => r.fulfill({ status: 500, contentType: "application/json", body: '{"error":"interner Detailtext"}' }));
  const all = page.getByRole("button", { name: "Alle aktualisieren" });
  for (let i = 0; i < 3; i++) { await all.click(); await sleep(150); }
  const err = region.getByRole("alert");
  ok((await err.count()) === 1, "gleiche Fehlermeldung wird zusammengefasst (1 Toast)");
  ok(/×3/.test(await err.innerText()), "Zähler „×3“");
  ok(!(await err.innerText()).includes("interner Detailtext"), "5xx zeigt keinen Server-Detailtext");
  await sleep(9000);
  ok((await region.getByRole("alert").count()) === 1, "Fehler-Toast bleibt auch nach 9 s");

  // 2) Escape schließt die Meldung, in der der Fokus steht.
  await region.getByRole("button", { name: "Meldung schließen" }).focus();
  await page.keyboard.press("Escape");
  await page.waitForFunction(() => document.querySelectorAll('[role="region"][aria-label="Benachrichtigungen"] li').length === 0);
  ok(true, "Escape schließt den Toast");

  // 4) Höchstens 4 sichtbar, der Rest wartet.
  await page.route("**/api/v1/hosts/*/request-report", (r) => r.fulfill({ status: 500, contentType: "application/json", body: "{}" }));
  const per = page.getByRole("button", { name: /jetzt aktualisieren$/ }).and(page.locator(":enabled"));
  const n = await per.count();
  for (let i = 0; i < n; i++) { await per.nth(i).click(); await sleep(120); }
  const shown = await region.locator("li").count();
  ok(n < 5 ? true : shown === 4, `höchstens 4 sichtbar (Hosts: ${n}, sichtbar: ${shown})`);
  if (n >= 5) ok(/weitere/.test(await region.innerText()), "Hinweis auf wartende Meldungen");
  // Zugänglichkeit: Bereich hat Namen, Schließen-Knöpfe haben Namen
  const names = await region.getByRole("button").evaluateAll((els) => els.map((e) => e.textContent?.trim()));
  ok(names.every((x) => x && x.length > 0), "alle Schaltflächen im Bereich haben einen Namen");

  await page.unroute("**/api/v1/hosts/*/request-report");
  await region.getByRole("button", { name: "Meldung schließen" }).evaluateAll((els) => els.forEach((e) => e.click()));
  // 3) Erfolg: verschwindet nach ~4 s; Hover hält an, danach läuft die Restzeit.
  await page.unroute("**/api/v1/hosts/request-report");
  await page.route("**/api/v1/hosts/request-report", (r) => r.fulfill({ status: 200, contentType: "application/json", body: '{"requested":3,"skipped":0}' }));
  await all.click();
  const st = region.getByRole("status").first();
  await st.waitFor();
  ok(true, "Info/Erfolg hat Rolle status");
  await st.hover();
  await sleep(5500);
  ok((await region.getByRole("status").count()) >= 1, "bei Hover läuft die Zeit nicht ab (5,5 s)");
  await page.mouse.move(5, 500);
  await sleep(4800);
  ok((await region.getByRole("status").count()) === 0, "nach dem Verlassen verschwindet der Toast");

  await page.context().close();

  // 5) Reduzierte Bewegung: keine Übergänge.
  const rm = await open(browser, { reducedMotion: "reduce" });
  await rm.goto(`${base}/agents`);
  await rm.route("**/api/v1/hosts/request-report", (r) => r.fulfill({ status: 500, body: "{}" }));
  await rm.getByRole("button", { name: "Alle aktualisieren" }).click();
  const dur = await rm.locator("li.toast").first().evaluate((e) => getComputedStyle(e).transitionDuration);
  ok(dur.split(",").every((d) => parseFloat(d) <= 0.001), `reduzierte Bewegung: transition-duration ${dur}`);
  await rm.context().close();
} finally {
  await browser.close();
}
