// E2E: modale Fenster (CVE-Fenster der Host-Seite): Klick auf den Hintergrund schließt, Klick im Fenster und Textauswahl nicht,
// Escape, Fokus kehrt zurück, Scrollsperre wird freigegeben, Hintergrund inert, Bottom-Sheet mobil, Tastatur, Touch, axe.
// Die CVE-Liste wird per page.route nachgestellt; der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=<axe.min.js> [PW_SHOTS=<Ordner>] node scripts/e2e-dialogs.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };

const gen = (n) => Array.from({ length: n }, (_, i) => ({
  cve_id: `CVE-2026-${String(10000 + i)}`, status: "vulnerable", reason: "Fix im Archiv", computed_at: "2026-11-01T10:00:00Z",
  sources: [{ source: "debian", release: "trixie", package: "linux", status: "resolved", fix_version: "6.12.5-1" }],
  description: `Beispiel ${i}: ein längerer Beschreibungstext, der im Fenster vollständig steht und lang genug ist, um bei schmalen Bildschirmen umzubrechen.`, priority: "medium", watched: false,
  reviewed_at: null, reviewed_by: null, level: 5 + (i % 5), fix_version: "6.12.5-1", source: "debian", published_at: "2026-10-01T00:00:00Z",
}));

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light", hasTouch: true });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const hosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const host = hosts[0];
  await page.route(new RegExp(`/api/v1/hosts/${host.id}/cves\\?(?!limit=1$)`), async (r) => {
    const url = new URL(r.request().url());
    if (url.pathname.endsWith("/groups")) return r.fallback();
    const real = await (await r.fetch()).json();
    return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...real, items: gen(5), total: 5 }) });
  });

  async function openPage(w, h, scheme) {
    await page.setViewportSize({ width: w, height: h });
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(`${base}/hosts/${host.id}`);
    await page.getByRole("button", { name: "Details zu CVE-2026-10000" }).first().waitFor();
  }
  const dlg = () => page.getByRole("dialog", { name: "CVE-2026-10000" });
  const trigger = () => page.getByRole("button", { name: "Details zu CVE-2026-10000" }).first();
  const locked = () => page.evaluate(() => getComputedStyle(document.documentElement).overflow === "hidden");
  const focusIsTrigger = () => page.evaluate(() => document.activeElement?.getAttribute("aria-label") === "Details zu CVE-2026-10000");

  for (const [w, h, scheme] of [[1440, 900, "light"], [1920, 1000, "dark"], [768, 900, "light"], [390, 700, "dark"]]) {
    const L = `${w}/${scheme}`;
    await openPage(w, h, scheme);
    const tap = w < 768;
    // Öffnen, Aufbau: modal, Titel verknüpft, Seite gesperrt.
    await (tap ? trigger().tap() : trigger().click());
    await dlg().waitFor();
    await page.waitForTimeout(400); // Einblend-Animation abwarten
    ok(await dlg().getAttribute("aria-modal") === "true", `${L}: aria-modal`);
    ok(await locked(), `${L}: Scrollen der Seite dahinter gesperrt`);
    ok(await page.evaluate(() => document.querySelector("dialog[open]").matches(":modal")), `${L}: echtes modales Fenster (Hintergrund nicht bedienbar)`);
    // Größe: nie größer als das Fenster, nichts läuft über den Rand.
    const m = await page.evaluate(() => { const d = document.querySelector("dialog[open]"); const r = d.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom, sw: d.scrollWidth, cw: d.clientWidth, vw: innerWidth, vh: innerHeight }; });
    ok(m.l >= 0 && m.r <= m.vw + 0.5 && m.t >= 0 && m.b <= m.vh + 0.5, `${L}: Fenster liegt im Bildschirm (${Math.round(m.l)}..${Math.round(m.r)} von ${m.vw}, bis ${Math.round(m.b)} von ${m.vh})`);
    ok(m.sw <= m.cw, `${L}: kein horizontaler Überlauf im Fenster`);
    if (w < 768) ok(Math.abs(m.r - m.l - m.vw) < 1, `${L}: Bottom-Sheet in voller Breite`);
    await page.evaluate(axeSrc);
    const v = await page.evaluate(() => axe.run(document.querySelector("dialog[open]"), { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
    ok(v.length === 0, `${L}: axe ${v.join(", ") || "keine Verstöße"}`);
    if (shots) await page.screenshot({ path: `${shots}/dialog-${w}-${scheme}.png` });

    // Klick im Fenster schließt nicht (Titel, Textfläche, Rand innen).
    const box = await dlg().boundingBox();
    await page.mouse.click(box.x + box.width / 2, box.y + 12);
    ok(await dlg().isVisible(), `${L}: Klick im Fenster schließt nicht`);
    await page.mouse.click(box.x + 3, box.y + 3);
    ok(await dlg().isVisible(), `${L}: Klick auf den Fensterrand innen schließt nicht`);
    // Textauswahl, die im Fenster beginnt und außerhalb endet, schließt nicht.
    if (w >= 768 && box.x > 20) {
      await page.mouse.move(box.x + 30, box.y + 14);
      await page.mouse.down();
      await page.mouse.move(Math.max(2, box.x - 15), box.y + 14, { steps: 5 });
      await page.mouse.up();
      ok(await dlg().isVisible(), `${L}: Ziehen von innen nach außen schließt nicht`);
    }
    // Klick auf den Hintergrund schließt; Fokus zurück; Sperre frei.
    if (tap) await page.touchscreen.tap(w / 2, 20); else await page.mouse.click(box.x > 40 ? box.x / 2 : 4, 4);
    await dlg().waitFor({ state: "hidden" });
    ok(true, `${L}: Klick/Tipp auf den Hintergrund schließt`);
    ok(!(await locked()), `${L}: Scrollsperre freigegeben`);
    // Die Fokusrückgabe läuft im `close`-Ereignis des Dialogs, das der Browser erst als eigene Aufgabe nach dem Schließen
    // auslöst. "hidden" kann also schon erfüllt sein, bevor der Fokus zurück ist (Race im Test, nicht im Web: mit
    // Wartezeit stets korrekt). Darum auf den Zustand warten statt auf feste Pausen; bleibt er aus, schlägt der Test fehl.
    const focusBack = await page.waitForFunction(() => document.activeElement?.getAttribute("aria-label") === "Details zu CVE-2026-10000", null, { timeout: 2000 }).then(() => true, () => false);
    ok(focusBack, `${L}: Fokus kehrt zur Schaltfläche zurück`);

    // Escape schließt (Tastatur öffnet mit Enter).
    await trigger().focus();
    await page.keyboard.press("Enter");
    await dlg().waitFor();
    ok(await page.evaluate(() => document.querySelector("dialog[open]").contains(document.activeElement)), `${L}: Fokus im Fenster`);
    // Fokusfalle: Tab verlässt das Fenster nie.
    for (let i = 0; i < 8; i++) await page.keyboard.press("Tab");
    ok(await page.evaluate(() => document.querySelector("dialog[open]").contains(document.activeElement)), `${L}: Fokusfalle hält den Fokus im Fenster`);
    await page.keyboard.press("Escape");
    await dlg().waitFor({ state: "hidden" });
    await page.waitForFunction(() => document.activeElement?.getAttribute("aria-label") === "Details zu CVE-2026-10000", null, { timeout: 2000 }).catch(() => {}); // gleiche Race wie oben
    ok(!(await locked()) && (await focusIsTrigger()), `${L}: Escape schließt, Sperre frei, Fokus zurück`);
    // Der Hintergrund hat danach keinen Fokusverlust: Tastatur arbeitet weiter auf der Seite.
    await page.keyboard.press("Tab");
    ok(await page.evaluate(() => document.activeElement !== document.body), `${L}: Tastatur arbeitet danach auf der Seite weiter`);
  }
} finally {
  await browser.close();
}
