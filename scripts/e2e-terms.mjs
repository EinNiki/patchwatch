// E2E: Begriffe "Report" und "Check-in" sind in der Oberfläche nicht mehr sichtbar (Hostliste, Host-Seite, Agents-Seite,
// auch nicht in aria-label und title); neue Beschriftungen, Erklärung per Info-Symbol (Maus, Tastatur, Touch), axe.
// Nur Lesezugriffe gegen den laufenden Server.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-terms.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const OLD = /Daten zuletzt|Agent zuletzt aktiv|\bReports?\b|Check-?in|Jetzt aktualisieren|Alle aktualisieren|jetzt aktualisieren/i;

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

  // Sichtbarer Text, aria-label, title und alt aller Elemente (ohne Skripte).
  const scan = () => page.evaluate(() => {
    const out = [document.body.innerText];
    for (const e of document.querySelectorAll("[aria-label],[title]")) { out.push(e.getAttribute("aria-label") ?? "", e.getAttribute("title") ?? ""); }
    return out.join("\n");
  });

  for (const [w, scheme] of [[1440, "light"], [390, "dark"], [768, "light"], [1920, "dark"]]) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: w, height: 900 });
    for (const [name, path] of [["Hostliste", "/"], ["Host", `/hosts/${host.id}`], ["Agents", "/agents"]]) {
      const L = `${w}/${scheme} ${name}`;
      await page.goto(`${base}${path}`);
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(300);
      if (name === "Host" && w < 1280) await page.locator("details summary", { hasText: "Host-Details" }).first().click();
      const text = await scan();
      // Lange Fließtexte sind CVE-Beschreibungen aus den Datenquellen (fremder Text) und gelten nicht als Oberflächentext.
      const hit = text.split("\n").filter((l) => l.length < 160 && OLD.test(l));
      ok(hit.length === 0, `${L}: alte Begriffe nicht sichtbar (${hit[0] ?? "keine"})`);
      if (name === "Hostliste") ok(/Zuletzt gemeldet/.test(text), `${L}: neue Beschriftung`);
      if (name === "Agents") {
        ok(w < 768 || /Zuletzt gemeldet/.test(text) && /Zuletzt erreichbar/.test(text), `${L}: Spalten "Zuletzt gemeldet" und "Zuletzt erreichbar"`);
        ok((await page.getByRole("button", { name: /Daten jetzt abrufen/ }).count()) >= 1 && (await page.getByRole("button", { name: "Alle Daten abrufen" }).count()) === 1, `${L}: Aktion "Daten jetzt abrufen" / "Alle Daten abrufen"`);
      }
      if (name === "Host") {
        const scope = w >= 1280 ? page.locator("aside[aria-labelledby=facts]") : page.locator("details:has(dl)");
        for (const [label, frag, title] of [["Zuletzt gemeldet", "vollständige Daten geschickt", "Zuletzt gemeldet"], ["Zuletzt erreichbar", "keine Daten übertragen", "Zuletzt erreichbar"]]) {
          const btn = scope.getByRole("button", { name: `Erklärung zu „${label}“` });
          ok((await btn.count()) === 1, `${L}: Info-Symbol zu "${label}" mit Aria-Label`);
          ok(((await btn.getAttribute("title")) ?? "").includes(frag), `${L}: Tooltip zu "${label}"`);
          ok((await btn.getAttribute("aria-expanded")) === "false", `${L}: "${label}" zunächst eingeklappt`);
          if (w >= 768) { await btn.focus(); await page.keyboard.press("Enter"); } else await btn.tap().catch(() => btn.click());
          ok((await btn.getAttribute("aria-expanded")) === "true" && (await scope.getByText(frag, { exact: false }).last().isVisible()), `${L}: Erklärung zu "${label}" klappt auf (${w >= 768 ? "Tastatur" : "Touch/Klick"})`);
          const size = await btn.boundingBox();
          if (w < 768) ok(size.width >= 44 && size.height >= 44, `${L}: Trefferfläche mobil >= 44 px (${size.width}x${size.height})`);
        }
        if (shots) await page.screenshot({ path: `${shots}/terms-host-${w}-${scheme}.png` });
      }
      await page.evaluate(axeSrc);
      const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
      ok(v.length === 0, `${L}: axe ${v.join(", ") || "keine Verstöße"}`);
    }
  }
} finally {
  await browser.close();
}
