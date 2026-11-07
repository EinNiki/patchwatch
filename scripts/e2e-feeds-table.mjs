// E2E: Tabelle "CVE-Quellen" (Spalten, ein "Nächster Versuch" je Quelle, Fehler nur bei Fehler, keine Platzhalter,
// kein Überlauf, axe). Die Feed-Liste wird per page.route nachgestellt; der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-feeds-table.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axe = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const json = (status, body) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const iso = (min) => new Date(Date.now() + min * 60_000).toISOString();

const feed = (o) => ({ source: "debian", type: "debian", label: "Debian", ecosystem: null, takes_ecosystem: false, kind: "builtin", enabled: true, configured: true, enrich_only: false, takes_secret: false, takes_base_url: false, secret_set: false, base_url: null, interval_minutes: 60, state: "ok", healthy: true, last_attempt_at: iso(-1), last_success_at: iso(-1), stale_since: null, last_error: null, last_error_at: null, consecutive_failures: 0, failed_runs: 0, next_attempt_at: iso(59), error_text: null, backfill: null, bulk: null, ...o });
const bulk = (hourly = {}, extra = []) => ({
  complete: true, bulk_interval_minutes: 1440,
  releases: [{ release: "resolute", state: "ok", result_text: "importiert", imported_at: iso(-300), verified_at: iso(-300), bytes: 4_700_000, records: 10, status: null, retry_after_secs: null, next_attempt_at: null, fresh_until: iso(1000) }, ...extra],
  hourly: { last_run_at: iso(-3), last_ok_at: iso(-3), page_size: 10, max_page: null, pages_last: 1, failures: 0, status: null, retry_after_secs: null, error_text: null, next_attempt_at: iso(57), hint: null, ...hourly },
});
const GOOD = [feed(), feed({ source: "ubuntu", type: "ubuntu", label: "Ubuntu", bulk: bulk() })];
const BAD = [feed(), feed({ source: "ubuntu", type: "ubuntu", label: "Ubuntu", state: "incomplete", stale_since: iso(-90), last_error: "HTTP 503", last_error_at: iso(-1), consecutive_failures: 4, failed_runs: 4, error_text: "Ubuntu meldet 503, nächster Versuch in 12 Minuten", next_attempt_at: iso(12),
  bulk: bulk({ failures: 4, status: 503, error_text: "Ubuntu meldet 503, nächster Versuch in 12 Minuten", hint: "Die Ubuntu-API antwortet seit 4 Läufen mit 503/504 (überlastet)." }, [{ release: "noble", state: "error", result_text: "Ubuntu meldet 503, nächster Versuch in 12 Minuten", imported_at: null, verified_at: null, bytes: null, records: null, status: 503, retry_after_secs: null, next_attempt_at: iso(12), fresh_until: null }]) })];

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light", reducedMotion: "reduce" });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  let data = GOOD;
  await page.route(/\/api\/v1\/feeds$/, (r) => (r.request().method() === "GET" ? r.fulfill(json(200, data)) : r.continue()));
  await page.route("**/api/v1/feeds/runs**", (r) => r.fulfill(json(200, { runs: [] })));

  async function check(label, size, scheme, withError) {
    data = withError ? BAD : GOOD;
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.setViewportSize(size);
    await page.goto(`${base}/cves`);
    const table = page.getByRole("table", { name: "Zustand der CVE-Quellen" });
    await table.waitFor();
    const rows = table.locator("tbody > tr:not(.run-row)");
    ok((await rows.count()) === 2, `${label}: zwei Quellen`);
    if (size.width >= 768) {
      const heads = (await table.locator("thead th").allInnerTexts()).map((t) => t.trim());
      ok(JSON.stringify(heads) === JSON.stringify(["Quelle", "Zustand", "Letzter erfolgreicher Abruf", "Intervall", "Nächster Versuch", "Details", "Aktionen"]), `${label}: Spalten ${heads.join(" | ")}`);
      ok(!heads.includes("Fehler"), `${label}: keine Spalte "Fehler"`);
    }
    for (let i = 0; i < 2; i++) {
      const text = (await rows.nth(i).innerText()).toLowerCase();
      ok((text.match(/nächster versuch/g) ?? []).length === 0, `${label}: Zeile ${i} wiederholt "nächster Versuch" nicht im Text`);
    }
    // Genau ein Zeitpunkt des nächsten Versuchs je Quelle: die Zelle der Spalte (Desktop) bzw. das Label (mobil).
    if (size.width >= 768) {
      for (let i = 0; i < 2; i++) ok((await rows.nth(i).locator("td").nth(4).locator("time").count()) === 1, `${label}: Zeile ${i} hat genau einen nächsten Versuch`);
    }
    const deb = (await rows.nth(0).innerText());
    ok(!/(^|\s)–(\s|$)/.test(deb), `${label}: Debian ohne Platzhalter "–"`);
    ok(!/Abruf (gestört|fehlgeschlagen)/.test(deb), `${label}: Debian ohne Fehler-Chip`);
    const ubu = rows.nth(1);
    if (withError) {
      ok(await ubu.getByText("Abruf fehlgeschlagen").isVisible(), `${label}: Fehler-Chip bei Ubuntu`);
      ok(await ubu.getByText("Ubuntu meldet 503 (4× in Folge)").first().isVisible(), `${label}: Fehlerzeile im Klartext`);
      const btn = ubu.getByRole("button", { name: /Details anzeigen/ });
      ok(await btn.isVisible(), `${label}: Details anzeigen vorhanden`);
      const lineCount = async () => ubu.locator("[id^=feed-details-] > div").count();
      ok((await lineCount()) === 2, `${label}: zwei Zeilen sichtbar`);
      await btn.click();
      ok((await lineCount()) > 2, `${label}: Details aufgeklappt`);
      ok(await ubu.getByRole("button", { name: /Details ausblenden/ }).getAttribute("aria-expanded") === "true", `${label}: aria-expanded`);
    } else {
      ok(!(await ubu.innerText()).includes("Abruf gestört"), `${label}: kein Fehler ohne Fehler`);
    }
    const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    ok(over <= 0, `${label}: kein horizontaler Überlauf (${over})`);
    await page.evaluate(axe);
    const res = await page.evaluate(() => globalThis.axe.run(document.querySelector("#feeds"), { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa", "best-practice"] }));
    ok(res.violations.length === 0, `${label}: axe ${res.violations.map((v) => v.id).join(",")}`);
    if (shots) await page.locator("#feeds").screenshot({ path: `${shots}/feeds-${size.width}-${scheme}-${withError ? "err" : "ok"}.png` });
  }
  for (const w of [390, 768, 1440, 1920]) for (const scheme of ["light", "dark"]) for (const err of [false, true]) await check(`${w}/${scheme}/${err ? "Fehler" : "ok"}`, { width: w, height: 900 }, scheme, err);
} finally {
  await browser.close();
}
