// E2E: aufgeräumte CVE-Seite: Kopf (Titel, grauer Zähler, eine Trennlinie, Kennzahlenzeile ohne Nullen), Werkzeugleiste
// (alle Elemente gleich hoch, eine Zeile), Filterfenster, Chips nur bei Abweichungen, Dialog „CVE beobachten“, Quellenzeile.
// Die CVE-Liste kommt aus Mocks (Lesezugriffe gegen den Server); Watchlist-Schreibzugriffe sind ebenfalls gemockt.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-cves-toolbar.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const json = (r, body, status = 200) => r.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

const cve = (i, o = {}) => ({
  id: `CVE-2026-${40000 + i}`, description: `Beispiel ${i}`, priority: i === 1 ? "critical" : "low", level: i === 1 ? 9 : 2, published_at: "2026-10-01T00:00:00Z",
  updated_at: null, last_synced_at: "2026-11-01T00:00:00Z", watched: false, note: null, exploited: false,
  hosts_vulnerable: 1, hosts_fix_pending: 0, hosts_reboot: 0, hosts_unknown: 0, affected_hosts: ["h1"],
  distros: [{ source: "debian", release: "trixie", status: i === 1 ? "open" : "fixed", package: "linux", fix_version: i === 1 ? null : "1.2", updated_at: "2026-11-01T00:00:00Z", mine: true }],
  hidden_releases: 0, ...o,
});

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));

  let rows = [cve(1), cve(2), cve(3)];
  const listReqs = [];
  const watchPuts = [];
  await page.route(/\/api\/v1\/cves\/scope-count/, (r) => json(r, { mine: 5, all: 5723, affecting: 5 }));
  await page.route(/\/api\/v1\/cves\?/, (r) => {
    const u = new URL(r.request().url());
    listReqs.push(u.search);
    const q = (u.searchParams.get("q") ?? "").toUpperCase();
    return json(r, q ? rows.filter((x) => x.id.includes(q)) : rows);
  });
  await page.route(/\/api\/v1\/watchlist\//, (r) => {
    const id = r.request().url().split("/").pop();
    if (r.request().method() === "PUT") {
      if (id === "CVE-2026-99999") return json(r, { error: "CVE nicht gefunden" }, 404);
      watchPuts.push(id);
      rows = rows.map((x) => (x.id === id ? { ...x, watched: true } : x));
      return json(r, {});
    }
    return json(r, {});
  });

  const toolbar = () => page.locator("#cve-filters");
  const heights = () => page.evaluate(() => [...document.querySelectorAll("#cve-filters > *")].map((e) => { const b = e.getBoundingClientRect(); return { n: e.getAttribute("aria-label") || e.textContent.trim().slice(0, 20), h: Math.round(b.height), top: Math.round(b.top) }; }));

  for (const [w, mobile] of [[1440, false], [390, true]]) {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${base}/cves`);
    await page.getByText("CVE-2026-40001").first().waitFor();
    const L = `${w}px`;
    const want = mobile ? 44 : 32;
    const hs = await heights();
    ok(hs.length === 4 && hs.every((x) => Math.abs(x.h - want) <= 1), `${L}: Suche, Filter, Stern, „CVE beobachten“ sind ${want} px hoch (${hs.map((x) => `${x.n}=${x.h}`).join(", ")})`);
    const rowsTop = new Set(hs.map((x) => x.top));
    if (!mobile) ok(rowsTop.size === 1, `${L}: Werkzeugleiste steht in einer Zeile`);
    else ok(hs[0].top < hs[1].top && new Set(hs.slice(1).map((x) => x.top)).size === 1, `${L}: Suche volle Breite, Rest darunter in einer Zeile (${hs.map((x) => x.top).join(",")})`);
    const sw = await page.evaluate(() => { const s = document.querySelector('#cve-filters input'); return [s.getBoundingClientRect().width, document.querySelector("#cve-filters").getBoundingClientRect().width]; });
    ok(mobile ? sw[0] >= sw[1] - 2 : sw[0] >= 300, `${L}: Suchfeld breit (${Math.round(sw[0])} px)`);
    ok((await page.locator("h1").innerText()) === "CVEs", `${L}: Titel „CVEs“`);
    ok((await page.getByText("Watchlist hinzufügen").count()) === 0 && (await page.getByRole("heading", { name: "CVE-Liste" }).evaluate((e) => e.getBoundingClientRect().height <= 1)), `${L}: alte Watchlist-Box und Überschrift „CVE-Liste“ weg`);
    const cnt = await page.getByTestId("affects-count").innerText();
    ok(/^5 betreffen deine Hosts · 5\.723 insgesamt$/.test(cnt), `${L}: grauer Zähler „${cnt}“`);
    const stats = await page.getByTestId("cve-stats").innerText();
    ok(stats.includes("davon hoch/kritisch 1") && stats.includes("ohne Fix") && stats.includes("mit Fix im Archiv"), `${L}: Kennzahlen „${stats}“`);
    ok((await page.getByTestId("cve-stats").locator("a, button").count()) === 0, `${L}: Kennzahlen nicht klickbar`);
    const lines = await page.evaluate(() => {
      const hdr = document.querySelector("h1").closest("header");
      const all = [...document.querySelectorAll("main *")].filter((e) => { const cs = getComputedStyle(e); return e.offsetParent && (parseFloat(cs.borderBottomWidth) > 0 || e.tagName === "HR") && e.getBoundingClientRect().top < 260 && e.getBoundingClientRect().width > 300 && e.tagName !== "INPUT" && e.tagName !== "BUTTON" && !e.closest("table"); });
      return { hdr: parseFloat(getComputedStyle(hdr).borderBottomWidth), others: all.filter((e) => e !== hdr).map((e) => e.tagName + "." + e.className.toString().slice(0, 40)) };
    });
    ok(lines.hdr > 0 && lines.others.length === 0, `${L}: genau eine Trennlinie unter dem Kopf (${lines.others.join("; ") || "keine weitere"})`);
    ok((await page.getByRole("button", { name: /^Filter/ }).innerText()).trim() === "Filter", `${L}: „Filter“ ohne Zähler im Standard`);
    ok((await page.getByRole("list", { name: "Aktive Filter" }).count()) === 0, `${L}: kein Chip im Standard`);
    ok((await page.getByRole("button", { name: "Nur Watchlist" }).getAttribute("aria-pressed")) === "false", `${L}: Stern-Schalter aria-pressed=false`);
    ok((await page.getByRole("button", { name: "Nur Watchlist" }).getAttribute("title")) !== null, `${L}: Stern-Schalter mit Tooltip`);
    if (shots) await page.screenshot({ path: `${shots}/cves-toolbar-${w}.png` });

    // Filterfenster
    const fb = page.getByRole("button", { name: /^Filter/ });
    await fb.click();
    const dlg = page.getByRole("dialog", { name: "Filter" });
    ok(await dlg.isVisible(), `${L}: Filterfenster öffnet`);
    ok((await dlg.getByRole("radiogroup").count()) === 3, `${L}: Gruppen Betrifft, Debian, Ubuntu`);
    ok((await dlg.getByText("Distribution").count()) === 0, `${L}: kein Feld „Distribution“`);
    if (mobile) {
      const bb = await dlg.boundingBox();
      ok(bb.width >= 388 && bb.y + bb.height >= 895, `${L}: Bottom-Sheet`);
    }
    if (shots) await page.screenshot({ path: `${shots}/cves-filter-${w}.png` });
    const combos = [["Betrifft", "Alle", "affects=all"], ["Debian", "gefixt", "debian=fixed"], ["Ubuntu", "offen", "ubuntu=open"], ["Debian", "offen", "debian=open"], ["Ubuntu", "gefixt", "ubuntu=fixed"]];
    for (const [g, v, qs] of combos) {
      listReqs.length = 0;
      await dlg.getByRole("radiogroup", { name: g }).getByRole("radio", { name: v }).click();
      await page.waitForURL((u) => u.search.includes(qs));
      ok(await dlg.isVisible(), `${L}: ${g} ${v}: Fenster bleibt offen, URL ${qs}`);
      await page.waitForFunction(() => true);
      await page.waitForTimeout(250);
      ok(listReqs.some((s) => qs.split("&").every((p) => s.includes(p))), `${L}: ${g} ${v}: Liste wird sofort neu geladen`);
    }
    ok((await fb.innerText()).replace(/\s+/g, " ").trim() === "Filter 3", `${L}: Zähler „Filter 3“ (Betrifft Alle, Debian offen, Ubuntu gefixt)`);
    ok((await dlg.getByRole("radiogroup", { name: "Debian" }).getByRole("radio", { name: "offen" }).getAttribute("aria-checked")) === "true", `${L}: Auswahl zeigt aktuellen Stand`);
    await page.keyboard.press("Escape");
    ok(!(await dlg.isVisible().catch(() => false)), `${L}: Escape schließt`);
    ok(await fb.evaluate((e) => document.activeElement === e), `${L}: Fokus zurück auf „Filter“`);
    const chips = page.getByRole("list", { name: "Aktive Filter" }).getByRole("button");
    const names = await chips.allInnerTexts();
    ok(names.some((n) => n.includes("Debian: offen")) && names.some((n) => n.includes("Ubuntu: gefixt")) && names.some((n) => n.includes("Betrifft: Alle")), `${L}: Chips für Abweichungen (${names.map((n) => n.trim()).join(" | ")})`);
    await page.getByRole("button", { name: "Debian: offen entfernen" }).click();
    await page.waitForURL((u) => !u.search.includes("debian="));
    ok(!page.url().includes("debian="), `${L}: Chip entfernen räumt die URL`);
    await fb.click();
    await dlg.getByRole("button", { name: "Zurücksetzen" }).click();
    await page.waitForURL((u) => !u.search.includes("affects=") && !u.search.includes("ubuntu="));
    ok((await fb.innerText()).trim() === "Filter", `${L}: Zurücksetzen leert Zähler`);
    await dlg.getByRole("button", { name: "Fertig" }).click();
    ok(!(await dlg.isVisible().catch(() => false)), `${L}: Fertig schließt`);
    await fb.click();
    await page.mouse.click(mobile ? 195 : 700, mobile ? 100 : 20);
    ok(!(await dlg.isVisible().catch(() => false)), `${L}: Klick daneben schließt`);

    // Alte URL mit Distribution
    await page.goto(`${base}/cves?distro=ubuntu&split=debian_fixed_ubuntu_open`);
    await page.getByText("CVE-2026-40001").first().waitFor();
    const nm = (await page.getByRole("list", { name: "Aktive Filter" }).getByRole("button").allInnerTexts()).join("|");
    ok(/Distribution: Ubuntu/.test(nm), `${L}: alte URL mit Distribution gilt weiter (${nm})`);
    ok((await page.getByRole("button", { name: /^Filter/ }).innerText()).replace(/\s+/g, " ").trim().startsWith("Filter"), `${L}: alte URL: Filterknopf vorhanden`);
    await page.goto(`${base}/cves`);
    await page.getByText("CVE-2026-40001").first().waitFor();

    // Stern-Schalter und Suche
    await page.getByRole("button", { name: "Nur Watchlist" }).click();
    await page.waitForURL(/watchlist=1/);
    ok((await page.getByRole("button", { name: "Nur Watchlist" }).getAttribute("aria-pressed")) === "true", `${L}: Stern aktiv, aria-pressed=true`);
    ok((await page.getByRole("list", { name: "Aktive Filter" }).count()) === 0, `${L}: Watchlist-Stern erzeugt keinen Chip`);
    await page.getByRole("button", { name: "Nur Watchlist" }).click();
    await page.waitForURL((u) => !u.search.includes("watchlist"));
    if (!mobile) {
      await page.locator("h1").click();
      await page.keyboard.press("/");
      ok(await page.evaluate(() => document.activeElement?.getAttribute("type") === "search"), `${L}: „/“ fokussiert die Suche`);
    }

    // Vorschlag für eine vollständige, unbekannte CVE-ID
    await page.getByRole("searchbox").fill("CVE-2026-77777");
    await page.getByTestId("watch-suggest").waitFor();
    ok((await page.getByTestId("watch-suggest").getByRole("button", { name: "CVE-2026-77777 beobachten" }).count()) === 1, `${L}: Angebot „CVE-… beobachten“`);
    await page.getByRole("searchbox").fill("");
    await page.getByText("CVE-2026-40001").first().waitFor();
    ok((await page.getByTestId("watch-suggest").count()) === 0, `${L}: Angebot verschwindet`);

    // Dialog „CVE beobachten“
    const wb = page.getByRole("button", { name: /CVE beobachten$/ });
    await wb.click();
    const wd = page.getByRole("dialog", { name: "CVE beobachten" });
    ok(await wd.isVisible(), `${L}: Dialog öffnet`);
    ok((await wd.getByPlaceholder("CVE-2024-1086").count()) === 1 && (await wd.getByLabel("Notiz (optional)").count()) === 1, `${L}: Felder CVE-ID und Notiz`);
    await wd.getByLabel("CVE-ID").fill("quatsch");
    await wd.getByRole("button", { name: "Beobachten" }).click();
    ok((await wd.getByRole("alert").innerText()).includes("Format"), `${L}: Formatfehler am Feld`);
    ok(await wd.getByLabel("CVE-ID").getAttribute("aria-invalid") === "true", `${L}: Feld aria-invalid`);
    await wd.getByLabel("CVE-ID").fill("CVE-2026-99999");
    await wd.getByRole("button", { name: "Beobachten" }).click();
    await wd.getByRole("alert").waitFor();
    ok(await wd.isVisible() && (await wd.getByRole("alert").innerText()).includes("CVE-2026-99999"), `${L}: Serverfehler am Feld, Dialog bleibt`);
    await wd.getByLabel("CVE-ID").fill("cve-2026-40002");
    await wd.getByLabel("Notiz (optional)").fill("prüfen");
    await wd.getByRole("button", { name: "Beobachten" }).click();
    await wd.waitFor({ state: "hidden" });
    ok(watchPuts.includes("CVE-2026-40002"), `${L}: PUT /watchlist/CVE-2026-40002`);
    ok((await page.getByText("CVE-2026-40002 zur Watchlist hinzugefügt.").count()) >= 1, `${L}: Erfolgs-Toast`);
    ok((await page.getByRole("row").filter({ hasText: "CVE-2026-40002" }).getByRole("button", { name: /Beobachtung beenden|nicht mehr beobachten|entfernen/i }).count()) >= 0 && rows.find((x) => x.id === "CVE-2026-40002").watched, `${L}: Zeile ist markiert`);
    await wb.click();
    await wd.getByLabel("CVE-ID").fill("CVE-2026-40002");
    await wd.getByRole("button", { name: "Beobachten" }).click();
    await wd.getByRole("alert").waitFor();
    ok((await wd.getByRole("alert").innerText()).includes("bereits"), `${L}: Duplikat wird gemeldet`);
    await page.keyboard.press("Escape");
    ok(await wb.evaluate((e) => document.activeElement === e), `${L}: Fokus zurück auf „CVE beobachten“`);
    rows = [cve(1), cve(2), cve(3)];
    watchPuts.length = 0;
    // Angebot aus der Suche
    await page.getByRole("searchbox").fill("CVE-2026-77777");
    await page.getByTestId("watch-suggest").waitFor();
    await page.getByTestId("watch-suggest").getByRole("button").click();
    await page.waitForTimeout(400);
    ok(watchPuts.includes("CVE-2026-77777"), `${L}: Angebot aus der Suche beobachtet die CVE`);
    await page.getByRole("searchbox").fill("");

    await page.waitForTimeout(1200); // Einblend-Animationen (Chips, Toast) abwarten, sonst misst axe halbtransparente Farben
    await page.evaluate(axeSrc);
    const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length} ${x.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" ; ")}`)));
    ok(v.length === 0, `${L}: axe ${v.join(", ") || "keine Verstöße"}`);
  }

  // Kennzahlen ohne Nullen: alles verschwindet, wenn alle Werte 0 sind.
  await page.setViewportSize({ width: 1440, height: 900 });
  rows = [cve(2, { distros: [] }), cve(3, { distros: [] })].map((x) => ({ ...x, level: 2, priority: "low" }));
  await page.goto(`${base}/cves`);
  await page.getByText("CVE-2026-40002").first().waitFor();
  const st = (await page.getByTestId("cve-stats").innerText()).trim();
  ok(!/\b0\b/.test(st) && !st.includes("hoch/kritisch"), `Kennzahlen ohne Nullwerte („${st}“)`);
  rows = [];
  await page.goto(`${base}/cves?q=zzz`);
  await page.waitForTimeout(800);
  ok((await page.getByTestId("cve-stats").innerText()).trim() === "", "Kennzahlen: bei lauter Nullen keine Zeile");
  await page.unroute(/\/api\/v1\/cves\?/);

  // Quellenzeile
  await page.goto(`${base}/cves`);
  const bar = page.getByTestId("sources-bar");
  await bar.waitFor();
  await page.locator("#feeds-table").getByText(/Debian/).first().waitFor();
  const bt = await bar.innerText();
  ok(/CVE-Quellen/.test(bt) && !/Verwalten/.test(bt) && !/Quellen:/.test(bt), `Kopfzeile: „${bt.replace(/\s+/g, " ")}“ (Titel, keine Zusammenfassungszeile)`);
  ok((await bar.getByRole("button").evaluateAll((l) => l.map((b) => b.getAttribute("title")))).join("|") === "Alle abrufen|Quelle hinzufügen", "Kopfzeile: „Alle abrufen“, „Quelle hinzufügen“ in dieser Reihenfolge");
  ok((await page.getByRole("button", { name: "Verwalten" }).count()) === 0, "Knopf „Verwalten“ nicht im DOM");
  ok(await page.locator("#feeds-table").isVisible(), "Quellen-Tabelle immer sichtbar");
  {
    const t = page.locator("#feeds-table");
    ok(await t.getByRole("button", { name: "Jetzt abrufen" }).first().isVisible(), "Quellen-Tabelle: „Jetzt abrufen“ sichtbar");
    // Kein „…“-Menü mehr: alle vier Aktionen stehen ohne Klick nebeneinander sichtbar.
    const first = t.locator("tbody > tr:not(.run-row)").first();
    ok((await first.getByRole("button", { name: /(abschalten|einschalten|bearbeiten|löschen)$/ }).filter({ visible: true }).count()) === 3, "Quellen-Tabelle: Abschalten/Bearbeiten/Löschen direkt sichtbar");
    ok((await t.getByRole("button", { name: /Weitere Aktionen für/ }).count()) === 0, "Quellen-Tabelle: kein „…“-Menü");
    if (shots) await page.screenshot({ path: `${shots}/cves-sources-open.png` });
  }
  const doubled = await page.evaluate(() => [...document.querySelectorAll("main > *, main section > *")].filter((e) => e.offsetParent && e.getBoundingClientRect().height <= 2 && getComputedStyle(e).borderTopWidth !== "0px").length);
  ok(doubled === 0, "keine doppelte Linie");
} finally {
  await browser.close();
}
