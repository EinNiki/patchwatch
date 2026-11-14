// E2E: Agents-Seite: Spalten, ruhige Zeile statt Spalte „Aktualisierung“, Aktionen in einer Zeile mit „…“-Menü,
// Zeilenhöhe, gleiche Spaltenabstände, volle Breite, kein Überlauf, Tastatur, mobil gestapelt, axe.
// Nur Lesezugriffe gegen den Server (Löschen/Token erneuern werden abgebrochen, nie bestätigt); /settings kommt aus einem Mock.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-agents.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { measure } from "./lib/gaps.mjs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const HEADERS = ["Name", "Hostname laut Agent", "Distribution", "Zuletzt gemeldet", "Zuletzt erreichbar", "Aktionen", "Agent-Version"];

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const settings = await page.evaluate(() => fetch("/api/v1/settings").then((r) => r.json()));
  let schedule = { ...settings.report_schedule, mode: "off", next_run: null };
  await page.route(/\/api\/v1\/settings$/, (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...settings, report_schedule: schedule }) }));

  const table = page.locator("table.tbl").first();
  const load = async () => { await page.goto(`${base}/agents`); await table.locator("tbody tr").first().waitFor(); };

  for (const [w, scheme] of [[1440, "light"], [1920, "dark"]]) {
    const L = `${w}/${scheme}`;
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: w, height: 900 });
    await load();
    const heads = (await table.locator("thead th").allInnerTexts()).map((t) => t.trim()).filter(Boolean);
    ok(JSON.stringify(heads) === JSON.stringify(HEADERS), `${L}: Spalten ${heads.join(" | ")}`);
    ok(!heads.includes("Aktualisierung"), `${L}: keine Spalte „Aktualisierung“`);
    ok((await page.getByTestId("schedule-line").innerText()).trim() === "Der Agent meldet täglich um ca. 12:00 (Uhrzeit des Hosts). Der Server-Zeitplan ist unter Einstellungen → Zeitpläne einstellbar.", `${L}: Zeile über der Tabelle (Modus aus)`);
    ok((await page.getByTestId("schedule-line").getByRole("link", { name: "Einstellungen → Zeitpläne" }).getAttribute("href")) === "/settings#sched-h", `${L}: Link zu Einstellungen → Zeitpläne`);
    const longText = await table.locator("tbody td").evaluateAll((tds) => tds.filter((t) => t.innerText.trim().length > 60).map((t) => t.innerText.trim().slice(0, 40)));
    ok(longText.length === 0, `${L}: kein Fließtext in der Tabelle (${longText.join("; ") || "ok"})`);
    ok((await page.getByText("bittet den Agent, beim nächsten Kontakt").count()) === 0 || !(await page.getByText("bittet den Agent, beim nächsten Kontakt").first().isVisible()), `${L}: lange Erklärung nicht dauerhaft sichtbar`);

    // Aktionen in einer Zeile, Zeilenhöhe, Mitte
    const geo = await page.evaluate(() => [...document.querySelectorAll("table.tbl tbody tr")].map((tr) => {
      const r = tr.getBoundingClientRect();
      const btns = [...tr.querySelectorAll("td.cell-actions button")].filter((b) => b.offsetParent).map((b) => { const q = b.getBoundingClientRect(); return { top: Math.round(q.top), h: Math.round(q.height), mid: q.top + q.height / 2 }; });
      const tds = [...tr.children].filter((c) => c.offsetParent).map((td) => { const q = td.getBoundingClientRect(); return { top: q.top, h: q.height }; });
      return { h: Math.round(r.height), btns, centered: Math.max(...tds.map((t) => Math.abs(t.top + t.h / 2 - (r.top + r.height / 2)))) };
    }));
    ok(geo.every((g) => g.btns.length === 2 && g.btns[0].top === g.btns[1].top || Math.abs(g.btns[0].mid - g.btns[1].mid) <= 1), `${L}: „Daten jetzt abrufen“ und „…“ stehen in einer Zeile`);
    ok(geo.every((g) => g.btns[0].h === 32 && g.btns[1].h === 32), `${L}: Knöpfe 32 px hoch (${geo[0].btns.map((b) => b.h).join("/")})`);
    ok(geo.every((g) => g.h <= 56), `${L}: Zeilenhöhe ≤ 56 px (${geo.map((g) => g.h).join(", ")})`);
    ok(geo.every((g) => g.centered <= 2), `${L}: Zellen vertikal mittig (Abweichung ${Math.max(...geo.map((g) => g.centered)).toFixed(1)} px)`);
    const names = await table.locator("tbody td.cell-actions button").allInnerTexts();
    ok(names.filter((t) => /Token erneuern|Löschen/.test(t)).length === 0, `${L}: Token erneuern/Löschen nicht direkt sichtbar`);

    // Abstände und Breite
    const r = await page.evaluate(measure, "table.tbl");
    const pad = w >= 1600 ? 32 : 24;
    // Abstände ergeben sich seit der Volle-Breite-Verteilung aus Prozentanteilen (e2e-fullwidth prüft den Rand).
    // Die Messfunktion zählt bei Knöpfen nur den Text; der sichtbare Abstand zum Rand des ersten Knopfes ist maßgeblich.
    const btnGap = await page.evaluate(() => { const tr = document.querySelector("table.tbl tbody tr"); const prev = tr.querySelector("td.cell-actions").previousElementSibling; const b = tr.querySelector("td.cell-actions button").getBoundingClientRect(); return Math.round(b.left - (prev.getBoundingClientRect().right - parseFloat(getComputedStyle(prev).paddingRight))); });
    console.log(`INFO ${L}: Abstand zum Knopf ${btnGap}`);
    ok(r.pairs.every((p) => p.gap >= pad - 8), `${L}: kein Abstand unter ${pad - 8} px (${r.pairs.map((p) => p.gap).join(", ")})`);
    ok(r.overflow <= 0, `${L}: kein horizontaler Überlauf`);
    console.log(`INFO ${L}: ${r.pairs.map((p) => `${p.pair.replace(" → ", ">")}=${p.gap}`).join(" ")}`);
    const fill = await page.evaluate(() => {
      const t = document.querySelector("table.tbl").getBoundingClientRect();
      const c = document.querySelector("section[aria-labelledby=agent-update]").getBoundingClientRect();
      const last = [...document.querySelectorAll("table.tbl thead th")].pop().getBoundingClientRect();
      return { dt: Math.abs(t.right - c.right), dl: Math.abs(t.left - c.left), lastRight: last.right, tr: t.right };
    });
    ok(fill.dt <= 1 && fill.dl <= 1, `${L}: Tabelle füllt die Breite des Inhaltsbereichs (Δ rechts ${fill.dt.toFixed(1)} px)`);
    const act = await page.evaluate(() => { const tr = document.querySelector("table.tbl tbody tr"); const td = tr.querySelector("td.cell-actions"); const b = td.querySelector("button"); return b.getBoundingClientRect().left - td.getBoundingClientRect().left; });
    ok(act <= 32 + 1, `${L}: Aktionen linksbündig in ihrer Zelle (Abstand zum Zellrand ${act.toFixed(1)} px)`);
    if (shots) await page.screenshot({ path: `${shots}/agents-${w}-${scheme}.png` });
    await page.evaluate(axeSrc);
    const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((x) => x.violations.map((y) => `${y.id}: ${y.nodes.length}`)));
    ok(v.length === 0, `${L}: axe ${v.join(", ") || "keine Verstöße"}`);
  }

  // Zeitplan-Zeile mit Server-Zeitplan
  schedule = { ...settings.report_schedule, mode: "interval", every_hours: 6, next_run: new Date(Date.now() + 3 * 3600e3).toISOString() };
  await page.setViewportSize({ width: 1440, height: 900 });
  await load();
  const sl = (await page.getByTestId("schedule-line").innerText()).trim();
  ok(/^Server-Zeitplan: alle 6 Std\., nächster Lauf/.test(sl) && /12:00/.test(sl), `Zeile mit Server-Zeitplan: „${sl}“`);
  schedule = { ...settings.report_schedule, mode: "off", next_run: null };

  // Info-Symbol, Hinweis zu älteren Agents
  await load();
  const info = page.getByRole("button", { name: "Erklärung zu „Daten jetzt abrufen“" });
  await info.click();
  ok(await page.getByRole("dialog", { name: "Erklärung zu „Daten jetzt abrufen“" }).getByText(/beim nächsten Kontakt/).isVisible(), "Info-Symbol zeigt die Erklärung");
  await page.keyboard.press("Escape");
  ok(await info.evaluate((e) => document.activeElement === e), "Info: Escape schließt, Fokus zurück");
  const more = page.getByRole("button", { name: "Mehr", exact: true });
  ok((await more.getAttribute("aria-expanded")) === "false", "Hinweis zu älteren Agents: „Mehr“ zu");
  const hintH = await page.getByText("Ältere Agents aktualisierst du").evaluate((e) => Math.round(e.parentElement.getBoundingClientRect().height));
  ok(hintH <= 28, `Hinweis steht in einer Zeile (${hintH} px)`);
  await more.click();
  ok((await page.getByRole("button", { name: "Weniger" }).getAttribute("aria-expanded")) === "true" && (await page.getByText(/--auto-update/).isVisible()), "„Mehr“ klappt Details auf");
  await page.getByRole("button", { name: "Weniger" }).click();

  // „…“-Menü, Bestätigung, Tastatur
  const firstName = (await table.locator("tbody tr").first().locator("td").first().innerText()).trim();
  const menuBtn = page.getByRole("button", { name: `Weitere Aktionen für ${firstName}` });
  await menuBtn.focus();
  await page.keyboard.press("Enter");
  const menu = page.getByRole("dialog", { name: `Weitere Aktionen für ${firstName}` });
  ok(await menu.isVisible(), "Menü öffnet per Enter");
  const items = (await menu.getByRole("button").allInnerTexts()).map((t) => t.trim());
  ok(JSON.stringify(items) === JSON.stringify(["Token erneuern", "Löschen"]), `Menü: ${items.join(", ")}`);
  const del = menu.getByRole("button", { name: `Agent ${firstName} löschen` });
  ok(await del.evaluate((e) => getComputedStyle(e).color) !== (await menu.getByRole("button", { name: /Token erneuern/ }).evaluate((e) => getComputedStyle(e).color)), "Löschen in Fehlerfarbe");
  await page.keyboard.press("Escape");
  ok(!(await menu.isVisible().catch(() => false)) && (await menuBtn.evaluate((e) => document.activeElement === e)), "Escape schließt das Menü, Fokus zurück");
  await menuBtn.click();
  await page.locator("h1").click();
  ok(!(await menu.isVisible().catch(() => false)), "Klick daneben schließt das Menü");
  await menuBtn.click();
  ok(await page.evaluate(() => document.activeElement?.textContent?.trim() === "Token erneuern"), "Fokus springt beim Öffnen auf den ersten Eintrag");
  await page.keyboard.press("Tab");
  ok(await page.evaluate(() => document.activeElement?.textContent?.trim() === "Löschen"), "Tab erreicht „Löschen“ im Menü");
  await page.keyboard.press("Enter");
  const dlg = page.getByRole("alertdialog").or(page.getByRole("dialog", { name: new RegExp(`Agent ${firstName} löschen\\?`) }));
  await dlg.first().waitFor();
  ok((await dlg.first().innerText()).includes(firstName), "Bestätigung nennt den Host");
  const confirmBtn = dlg.first().getByRole("button", { name: `${firstName} löschen` });
  ok(await confirmBtn.isVisible(), "Bestätigungsknopf „… löschen“");
  const col = await confirmBtn.evaluate((e) => getComputedStyle(e).color);
  const crit = await page.evaluate(() => { const s = document.createElement("span"); s.style.color = "var(--crit)"; document.body.appendChild(s); const c = getComputedStyle(s).color; s.remove(); return c; });
  ok(col === crit, `Bestätigung in Fehlerfarbe (${col})`);
  if (shots) await page.screenshot({ path: `${shots}/agents-delete-confirm.png` });
  await dlg.first().getByRole("button", { name: "Abbrechen" }).click();
  ok(await table.locator("tbody tr").first().isVisible(), "Abbrechen löscht nichts");
  await menuBtn.click();
  await menu.getByRole("button", { name: /Token erneuern/ }).click();
  ok(await page.getByText(new RegExp(`Token von ${firstName} erneuern\\?`)).isVisible(), "Token erneuern fragt nach");
  await page.getByRole("button", { name: "Abbrechen" }).click();

  // Mobil
  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: 390, height: 800 });
    await load();
    const L = `390/${scheme}`;
    ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), `${L}: kein Überlauf`);
    ok(await table.locator("thead").evaluate((e) => e.getBoundingClientRect().height <= 1), `${L}: Kopfzeile nur für Screenreader (gestapelt)`);
    const b = await page.evaluate(() => [...document.querySelectorAll("table.tbl tbody tr:first-child td.cell-actions button")].filter((x) => x.offsetParent).map((x) => { const r = x.getBoundingClientRect(); return [Math.round(r.height), Math.round(r.width)]; }));
    ok(b.length === 2 && b.every(([h, w]) => h >= 44 && w >= 44), `${L}: Aktionen ≥ 44 px (${JSON.stringify(b)})`);
    if (shots) await page.screenshot({ path: `${shots}/agents-390-${scheme}.png` });
    await page.evaluate(axeSrc);
    const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((x) => x.violations.map((y) => `${y.id}: ${y.nodes.length}`)));
    ok(v.length === 0, `${L}: axe ${v.join(", ") || "keine Verstöße"}`);
  }
} finally {
  await browser.close();
}
