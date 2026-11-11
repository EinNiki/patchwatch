// E2E: Tabellen über die volle Breite (Hosts, Agents, CVEs), Quellenbereich der CVE-Seite (Knopfreihe, Zustandschip, Karten)
// und Aktionen je Quelle (vier Knöpfe nebeneinander, kein „…“-Menü). Quellen per page.route nachgestellt; keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-fullwidth.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axe = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const json = (status, body) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const iso = (min) => new Date(Date.now() + min * 60_000).toISOString();
const feed = (o) => ({ source: "debian", type: "debian", label: "Debian", ecosystem: null, takes_ecosystem: false, kind: "builtin", enabled: true, configured: true, enrich_only: false, takes_secret: false, takes_base_url: false, secret_set: false, base_url: null, interval_minutes: 60, state: "ok", healthy: true, last_attempt_at: iso(-1), last_success_at: iso(-1), stale_since: null, last_error: null, last_error_at: null, consecutive_failures: 0, failed_runs: 0, next_attempt_at: iso(59), error_text: null, backfill: null, bulk: null, ...o });
const mkRun = (o) => ({ id: 1, source: "", trigger: "manual", started_by: "admin", status: "running", phase: "connect", created_at: new Date().toISOString(), started_at: new Date().toISOString(), finished_at: null, bytes: 0, items: null, hosts: null, error: null, phases: {}, ...o });
const FEEDS = [
  feed(),
  feed({ source: "ubuntu", type: "ubuntu", label: "Ubuntu", state: "incomplete", stale_since: iso(-90), last_error: "HTTP 503", last_error_at: iso(-1), consecutive_failures: 4, failed_runs: 4, error_text: "Ubuntu meldet 503, nächster Versuch in 12 Minuten", next_attempt_at: iso(12) }),
  feed({ source: "osv", type: "osv", label: "Aus", enabled: false, state: "disabled", next_attempt_at: null }),
];

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
const state = { writes: [], runs: [] };
try {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  await page.addInitScript(() => { try { localStorage.setItem("pw-feeds-manage", "1"); } catch {} });
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.route(/\/api\/v1\/feeds$/, (r) => (r.request().method() === "GET" ? r.fulfill(json(200, FEEDS)) : r.continue()));
  await page.route("**/api/v1/feeds/runs**", (r) => r.fulfill(json(200, { runs: state.runs })));
  await page.route(/\/api\/v1\/feeds\/[a-z]+$/, (r) => {
    const m = r.request().method();
    if (m === "GET") return r.continue();
    state.writes.push(`${m} ${new URL(r.request().url()).pathname}`);
    return r.fulfill(m === "DELETE" ? { status: 204 } : json(200, FEEDS[0]));
  });

  const setView = async (width, scheme) => {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.setViewportSize({ width, height: 900 });
  };
  const axeRun = async (tag) => {
    await page.evaluate(axe);
    const res = await page.evaluate(() => globalThis.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag22aa", "best-practice"] }));
    const bad = res.violations.filter((v) => !["region", "landmark-one-main", "page-has-heading-one"].includes(v.id));
    ok(bad.length === 0, `${tag}: axe ohne Verstöße ${bad.map((v) => v.id + ":" + v.nodes[0]?.target + " " + v.nodes[0]?.any?.[0]?.message).join(", ")}`);
  };

  // ---------- A: Tabellen über die volle Breite ----------
  const measure = () => page.evaluate(() => {
    const out = [];
    const norm = (a) => (a === "start" ? "left" : a === "end" ? "right" : a);
    for (const t of document.querySelectorAll("table.tbl:not([data-t])")) {
      // Inhaltsbereich: rechter Rand der Seitenüberschrift/Werkzeugleiste (Fenster minus 24 px Seitenrand).
      const contentRight = document.querySelector("main h1").closest("main").getBoundingClientRect().right - 24;
      const tr = t.getBoundingClientRect();
      const ths = [...t.querySelectorAll("thead th")].filter((h) => h.getBoundingClientRect().width > 0);
      const row = t.querySelector("tbody tr");
      const tds = [...row.children].filter((c) => c.getBoundingClientRect().width > 0);
      const lastRight = ths[ths.length - 1].getBoundingClientRect().right;
      const narrow = ths.filter((h) => h.getBoundingClientRect().width < parseFloat(getComputedStyle(h).minWidth) - 0.5).map((h) => h.textContent.trim());
      const align = ths.length === tds.length ? ths.map((h, i) => [h.textContent.trim(), norm(getComputedStyle(h).textAlign), norm(getComputedStyle(tds[i]).textAlign)]).filter(([, a, b]) => a !== b) : ["Spaltenzahl"];
      const over = [...ths, ...tds].filter((c) => c.scrollWidth > c.clientWidth + 1).map((c) => c.textContent.trim().slice(0, 20));
      out.push({ name: t.querySelector("caption")?.textContent.slice(0, 14), gap: Math.abs(lastRight - contentRight), tableGap: Math.abs(tr.right - contentRight), narrow, align, over, page: document.documentElement.scrollWidth - innerWidth, cols: ths.length });
    }
    return out;
  });
  for (const path of ["/", "/agents", "/cves"]) {
    for (const scheme of ["light", "dark"]) {
      for (const w of [1280, 1440, 1920, 2560]) {
        await setView(w, scheme);
        await page.goto(`${base}${path}`);
        await page.locator("table.tbl:not([data-t]) tbody tr").first().waitFor();
        await page.waitForTimeout(400);
        for (const m of await measure()) {
          const tag = `${path} ${m.name} ${w}px ${scheme}`;
          ok(m.gap <= 1 && m.tableGap <= 1, `${tag}: letzte Spalte endet am Inhaltsrand (±1 px; ${m.gap.toFixed(1)})`);
          ok(m.narrow.length === 0, `${tag}: keine Spalte unter ihrer Mindestbreite ${m.narrow}`);
          ok(m.align.length === 0, `${tag}: Kopf und Zelle gleich ausgerichtet ${JSON.stringify(m.align)}`);
          ok(m.over.length === 0, `${tag}: kein Textüberlauf ${m.over}`);
          ok(m.page <= 0, `${tag}: kein Seitenüberlauf (${m.page})`);
        }
        if (w === 1280 || w === 2560) await axeRun(`${path} ${w}px ${scheme}`);
      }
    }
  }
  // Unter 1024 px weniger Spalten, nie Seitenüberlauf; unter 768 px gestapelt.
  for (const path of ["/", "/agents", "/cves"]) {
    for (const w of [390, 768, 1024]) {
      await setView(w, "light");
      await page.goto(`${base}${path}`);
      await page.locator("table.tbl:not([data-t]) tbody tr").first().waitFor();
      const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      ok(over <= 0, `${path} ${w}px: kein Seitenüberlauf (${over})`);
    }
  }
  // Hosts-Kopf: Updates und Uptime rechtsbündig (Kopf und Zelle), Sortierpfeil direkt am Text.
  await setView(1440, "light");
  await page.goto(`${base}/`);
  await page.locator("table.tbl tbody tr").first().waitFor();
  const heads = await page.evaluate(() => [...document.querySelectorAll("table.tbl thead th")].map((h) => [h.textContent.trim(), getComputedStyle(h).textAlign]));
  for (const n of ["Updates", "Uptime"]) ok(heads.some(([t, a]) => t.startsWith(n) && (a === "right" || a === "end")), `Hosts: Spalte ${n} rechtsbündig`);

  // ---------- B: Quellenbereich ----------
  const bar = page.getByTestId("sources-bar");
  const box = (l) => l.boundingBox();
  for (const scheme of ["light", "dark"]) {
    for (const w of [390, 639, 640, 768, 1024, 1099, 1100, 1280, 1440, 1650, 1920]) {
      await setView(w, scheme);
      await page.goto(`${base}/cves`);
      const table = page.getByRole("table", { name: "Zustand der CVE-Quellen" });
      await table.waitFor();
      await page.waitForTimeout(300);
      const tag = `Quellen ${w}px ${scheme}`;
      const names = ["Alle abrufen", "Quelle hinzufügen", "Verwalten"];
      // Layout abwarten (Kopfzeile lädt nach): zweimal hintereinander gleiche Lage.
      let bs = [], prev = "";
      for (let k = 0; k < 20; k++) {
        bs = [];
        for (const n of names) bs.push(await box(bar.getByRole("button", { name: n })));
        const cur = JSON.stringify(bs);
        if (cur === prev) break;
        prev = cur;
        await page.waitForTimeout(150);
      }
      const sameRow = bs.every((b) => Math.abs(b.y - bs[0].y) <= 1);
      const ordered = bs[0].x < bs[1].x && bs[1].x < bs[2].x;
      ok(sameRow && ordered, `${tag}: drei Knöpfe in einer Reihe, Reihenfolge Alle abrufen, Quelle hinzufügen, Verwalten ${JSON.stringify(bs.map((b) => [b.x, b.y, b.width].map(Math.round)))}`);
      const wantH = w < 768 ? 44 : 32;
      ok(bs.every((b) => Math.abs(b.height - wantH) <= 1), `${tag}: Knopfhöhe ${wantH} (${bs.map((b) => Math.round(b.height))})`);
      ok(bs[2].x + bs[2].width <= w - 8 && bs[2].x + bs[2].width >= w * 0.8, `${tag}: rechts im Kopf ausgerichtet ${Math.round(bs[2].x + bs[2].width)}`);
      if (w >= 640) ok(Math.abs(bs[1].x - bs[0].x - bs[0].width - 8) <= 1 && Math.abs(bs[2].x - bs[1].x - bs[1].width - 8) <= 1, `${tag}: 8 px Abstand`);
      const textVisible = await bar.getByRole("button", { name: "Quelle hinzufügen" }).evaluate((b) => { const t = [...b.querySelectorAll("span")].pop(); return t.getBoundingClientRect().width > 4 && getComputedStyle(t).position !== "absolute"; });
      ok(textVisible === (w >= 1100), `${tag}: ${w >= 1100 ? "Knöpfe mit Text" : "nur Symbole"}`);
      if (w < 1100) for (const n of names) ok(!!(await bar.getByRole("button", { name: n }).getAttribute("title")), `${tag}: ${n} hat Tooltip und Namen`);
      if (w < 640) {
        const text = await box(bar.locator("p").first());
        ok(bs[0].y >= text.y + text.height - 1 && Math.abs(bs[0].width - bs[1].width) <= 1 && Math.abs(bs[1].width - bs[2].width) <= 1, `${tag}: eigene Reihe, gleich breit ${JSON.stringify(bs.map((b) => [b.x, b.y, b.width].map(Math.round)))}`);
      }
      // Primär nur „Quelle hinzufügen“.
      const bg = await Promise.all(names.map((n) => bar.getByRole("button", { name: n }).evaluate((b) => getComputedStyle(b).backgroundColor)));
      ok(bg[1] !== bg[0] && bg[0] === bg[2], `${tag}: nur „Quelle hinzufügen“ ist primär`);
      // Zustandschip: nur das Wort, Datum klein darunter; kein Überlappen mit Nachbarzellen.
      const ub = table.locator("tbody > tr:not(.run-row)").nth(1);
      const chip = ub.locator("[data-status-badge], .badge, span").filter({ hasText: /^Unvollständig$/ }).first();
      ok((await chip.count()) === 1, `${tag}: Chip zeigt nur „Unvollständig“`);
      ok(await ub.getByText(/^seit \d/).count() === 1, `${tag}: Datum „seit …“ steht gesondert`);
      const bad = await ub.evaluate((row) => {
        const cells = [...row.children].filter((c) => c.getBoundingClientRect().width > 0);
        const res = [];
        // Text in visuell versteckten Spans (sr-only) zählt nicht.
        const inner = (c) => {
          const out = [];
          const w = document.createTreeWalker(c, NodeFilter.SHOW_TEXT);
          for (let n = w.nextNode(); n; n = w.nextNode()) {
            const cs = getComputedStyle(n.parentElement);
            if (!n.textContent.trim() || (cs.position === "absolute" && parseFloat(cs.width) <= 1.5)) continue;
            const r = document.createRange(); r.selectNodeContents(n);
            out.push(...[...r.getClientRects()].filter((x) => x.width > 2 && x.height > 2));
          }
          return out;
        };
        cells.forEach((c, i) => {
          const cr = c.getBoundingClientRect();
          for (const r of inner(c)) {
            if (r.left < cr.left - 1 || r.right > cr.right + 1) res.push(`Zelle ${i} ragt heraus ${Math.round(r.left)}-${Math.round(r.right)} vs ${Math.round(cr.left)}-${Math.round(cr.right)} ${c.textContent.trim().slice(0, 30)}`);
          }
          cells.forEach((d, j) => {
            if (j <= i) return;
            for (const a of inner(c)) for (const b of inner(d)) if (a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5) res.push(`Zelle ${i}/${j} überlappen`);
          });
        });
        return res;
      });
      ok(bad.length === 0, `${tag}: keine Überlappung der Zellinhalte ${bad.slice(0, 2)}`);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
      ok(over <= 0, `${tag}: kein Seitenüberlauf (${over})`);
      if (w >= 1024) {
        const hs = await table.locator("thead th").evaluateAll((l) => l.filter((h) => h.getBoundingClientRect().width > 0).map((h) => [h.textContent.trim(), h.scrollWidth > h.clientWidth + 1]));
        ok(hs.every(([, o]) => !o), `${tag}: Kopf nicht abgeschnitten`);
        const names2 = hs.map(([t]) => t);
        ok(names2.includes("Intervall") === (w >= 1280), `${tag}: Spalte Intervall ${w >= 1280 ? "sichtbar" : "entfällt"}`);
        ok(names2[names2.length - 1] === "Aktionen", `${tag}: Aktionen zuletzt`);
        const al = await table.locator("thead th").last().evaluate((h) => getComputedStyle(h).textAlign);
        ok(al === "right" || al === "end", `${tag}: Aktionen rechtsbündig`);
      } else {
        const hidden = await table.locator("thead").evaluate((h) => getComputedStyle(h).display === "none" || h.getBoundingClientRect().height <= 1);
        ok(hidden, `${tag}: Karten statt Tabellenkopf`);
      }
      if (w === 390 || w === 1024 || w === 1650) await axeRun(tag);
    }
  }

  // ---------- C: Aktionen ----------
  for (const w of [390, 768, 1024, 1280, 1440, 1920, 2560]) {
    await setView(w, "light");
    await page.goto(`${base}/cves`);
    const table = page.getByRole("table", { name: "Zustand der CVE-Quellen" });
    await table.waitFor();
    await page.waitForTimeout(300);
    const tag = `Aktionen ${w}px`;
    const rows = table.locator("tbody > tr:not(.run-row)");
    ok((await table.getByRole("button", { name: /^(Weitere Aktionen|…|⋯)/ }).count()) === 0 && (await table.locator("[aria-haspopup]").count()) === 0, `${tag}: kein „…“-Menü`);
    for (let i = 0; i < 3; i++) {
      const row = rows.nth(i);
      const f = FEEDS[i];
      const btns = [
        row.getByRole("button", { name: `${f.label} jetzt abrufen` }),
        row.getByRole("button", { name: `${f.label} ${f.enabled ? "abschalten" : "einschalten"}` }),
        row.getByRole("button", { name: `${f.label} bearbeiten` }),
        row.getByRole("button", { name: `${f.label} löschen` }),
      ];
      // Warten, bis die Zeile ruhig steht (Details und Höhen setzen sich kurz nach dem Laden), dann alle vier Boxen messen.
      let bs = [];
      for (let k = 0, prevJ = ""; k < 30; k++) {
        bs = [];
        for (const b of btns) { await b.waitFor({ state: "visible" }); bs.push(await b.boundingBox()); }
        const j = JSON.stringify(bs);
        if (j === prevJ && bs.every((b) => Math.abs(b.y - bs[0].y) <= 1 || w < 1024)) break;
        prevJ = j;
        await page.waitForTimeout(200);
      }
      if (w >= 1024) {
        ok(bs.every((b) => Math.abs(b.y - bs[0].y) <= 1), `${tag} ${f.label}: vier Knöpfe in einer Reihe, ohne Umbruch ${JSON.stringify(bs.map((b) => [b.x, b.y, b.width, b.height].map(Math.round)))}`);
        ok(bs.every((b) => Math.abs(b.height - 32) <= 1), `${tag} ${f.label}: Höhe 32 (${bs.map((b) => Math.round(b.height))})`);
        ok(Math.abs(bs[1].x - bs[0].x - bs[0].width - 8) <= 1 && Math.abs(bs[2].x - bs[1].x - bs[1].width - 8) <= 1, `${tag} ${f.label}: 8 px Abstand`);
        ok(Math.abs(bs[3].x - bs[2].x - bs[2].width - 16) <= 1, `${tag} ${f.label}: Löschen mit 16 px Abstand zu Bearbeiten`);
        const cont = await btns[0].evaluate((b) => b.parentElement.parentElement.getBoundingClientRect().width);
        const icon = cont < 448;
        const txt = await btns[2].evaluate((b) => [...b.querySelectorAll("span")].some((s) => getComputedStyle(s).position !== "absolute" && s.getBoundingClientRect().width > 4));
        ok(txt === !icon, `${tag} ${f.label}: ${icon ? "Symbolmodus" : "Textmodus"} (Spalte ${Math.round(cont)} px)`);
        if (icon) {
          ok(bs[1].width <= 33 && bs[2].width <= 33 && bs[3].width <= 33, `${tag} ${f.label}: Symbolknöpfe 32 px`);
          for (const b of btns.slice(1)) ok(!!(await b.getAttribute("title")) && !!(await b.getAttribute("aria-label")), `${tag} ${f.label}: Symbolknopf mit Tooltip und aria-label`);
          ok((await btns[2].locator("svg").evaluate((s) => [s.getAttribute("width"), s.getAttribute("stroke-width")])).join() === "16,1.5", `${tag}: Symbol 16 px, Strich 1,5`);
        }
        const txt0 = await btns[0].innerText();
        ok(/^Jetzt abrufen$/i.test(txt0.trim()) || !f.enabled, `${tag} ${f.label}: „Jetzt abrufen“ behält den Text`);
      } else {
        const rowsY = new Set(bs.map((b) => Math.round(b.y)));
        ok(rowsY.size <= 2 && bs.every((b) => b.height >= (w < 768 ? 43 : 31)), `${tag} ${f.label}: Karten, höchstens zwei Reihen, Höhe passend`);
        const widths = bs.map((b) => b.width);
        ok(Math.max(...widths) - Math.min(...widths) <= 2 || rowsY.size === 2, `${tag} ${f.label}: Knöpfe gleich breit`);
        ok(bs.every((b) => b.x >= 0 && b.x + b.width <= w), `${tag} ${f.label}: Knöpfe im Fenster`);
      }
    }
    ok((await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)) <= 0, `${tag}: kein Seitenüberlauf`);
  }

  // Beschriftung für abgeschaltete Quellen.
  await setView(1920, "light");
  await page.goto(`${base}/cves`);
  const table = page.getByRole("table", { name: "Zustand der CVE-Quellen" });
  await table.waitFor();
  const off = table.locator("tbody > tr:not(.run-row)").nth(2);
  ok((await off.getByRole("button", { name: "Aus einschalten" }).innerText()).trim() === "Einschalten", "Abgeschaltete Quelle: Knopf „Einschalten“");
  ok(await off.getByRole("button", { name: "Aus jetzt abrufen" }).isDisabled(), "Abgeschaltete Quelle: „Jetzt abrufen“ gesperrt");

  // Tastaturreihenfolge und Fokusring.
  const deb = table.locator("tbody > tr:not(.run-row)").first();
  await deb.getByRole("button", { name: "Debian jetzt abrufen" }).focus();
  const order = [];
  for (let i = 0; i < 4; i++) {
    order.push(await page.evaluate(() => document.activeElement?.getAttribute("aria-label")));
    if (i === 0) { const ring = await page.evaluate(() => { const s = getComputedStyle(document.activeElement); return s.outlineStyle !== "none" || s.boxShadow !== "none"; }); ok(ring, "Fokusring sichtbar"); }
    await page.keyboard.press("Tab");
  }
  ok(JSON.stringify(order) === JSON.stringify(["Debian jetzt abrufen", "Debian abschalten", "Debian bearbeiten", "Debian löschen"]), `Tastaturreihenfolge ${order.join(" > ")}`);

  // Löschen nur nach Bestätigung (Name und Folgen im Dialog), Abbrechen ändert nichts.
  state.writes.length = 0;
  await deb.getByRole("button", { name: "Debian löschen" }).click();
  const dlg = page.getByRole("dialog");
  ok(await dlg.getByText(/Quelle „Debian“ löschen/).isVisible(), "Löschen: Dialog nennt die Quelle");
  ok(/unbekannt/i.test(await dlg.innerText()), "Löschen: Dialog nennt die Folgen (Hosts unbekannt)");
  ok(state.writes.length === 0, "Löschen: vor der Bestätigung kein DELETE");
  await dlg.getByRole("button", { name: "Abbrechen" }).click();
  ok(state.writes.length === 0, "Löschen: Abbrechen sendet nichts");
  await deb.getByRole("button", { name: "Debian löschen" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Löschen" }).click();
  await page.waitForTimeout(400);
  ok(state.writes.some((x) => x.startsWith("DELETE")), "Löschen: nach Bestätigung DELETE");

  // Abschalten: ohne Rückfrage, Toast mit „Rückgängig“.
  state.writes.length = 0;
  await deb.getByRole("button", { name: "Debian abschalten" }).click();
  await page.waitForTimeout(300);
  ok(!(await page.getByRole("dialog").count()) && state.writes.some((x) => x.startsWith("PUT")), "Abschalten: ohne Rückfrage");
  const undo = page.getByRole("region", { name: "Benachrichtigungen" }).getByRole("button", { name: "Rückgängig" });
  ok(await undo.isVisible(), "Abschalten: Toast mit „Rückgängig“");
  state.writes.length = 0;
  await undo.click();
  await page.waitForTimeout(300);
  ok(state.writes.some((x) => x.startsWith("PUT")), "Rückgängig schaltet wieder ein");

  // Lauf aktiv: „läuft“, gesperrt; Löschen bleibt möglich, Dialog warnt.
  state.runs = [mkRun({ id: 7, source: "debian", status: "running", phase: "download", bytes: 1000 })];
  await page.goto(`${base}/cves`);
  await table.waitFor();
  const deb2 = table.locator("tbody > tr:not(.run-row)").first();
  const run = deb2.getByRole("button", { name: /Debian.*(jetzt abrufen|Abruf läuft)/ });
  ok(/läuft/i.test(await run.innerText()), "Lauf aktiv: Knopf zeigt „läuft“");
  ok((await run.getAttribute("aria-busy")) === "true" || (await run.isDisabled()), "Lauf aktiv: Knopf gesperrt");
  ok(await deb2.getByRole("button", { name: "Debian abschalten" }).isEnabled() && await deb2.getByRole("button", { name: "Debian löschen" }).isEnabled(), "Lauf aktiv: Abschalten und Löschen bleiben nutzbar");
  await deb2.getByRole("button", { name: "Debian löschen" }).click();
  ok(await page.getByRole("dialog").getByText(/läuft gerade ein Abruf/).isVisible(), "Lauf aktiv: Warnung im Löschdialog");
} finally {
  await browser.close();
}
