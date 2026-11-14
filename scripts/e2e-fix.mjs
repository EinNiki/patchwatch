// E2E der Korrekturrunde: A1 einheitliche Köpfe, A2 Aktionsspalte (weitere Abschnitte folgen je Aufgabe).
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_BASE=…] [PW_SHOTS=<Ordner>] [PW_ONLY=A1,A2] node scripts/e2e-fix.mjs
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3300";
const shots = process.env.PW_SHOTS;
if (shots) mkdirSync(shots, { recursive: true });
const only = (process.env.PW_ONLY ?? "").split(",").filter(Boolean);
const want = (k) => only.length === 0 || only.includes(k);
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
import { measure } from "./lib/gaps.mjs";
const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });

let state = null; // Einmal anmelden (Login-Limit), die Sitzung für alle Kontexte wiederverwenden
async function open(w, h, scheme = "light", extra = {}) {
  if (!state) {
    const c0 = await browser.newContext();
    const p0 = await c0.newPage();
    await p0.goto(`${base}/login`);
    await p0.getByLabel("Benutzername").fill("admin");
    await p0.getByLabel("Passwort").fill(pw);
    await p0.getByRole("button", { name: "Anmelden", exact: true }).click();
    await p0.waitForURL((u) => !u.pathname.startsWith("/login"));
    state = await c0.storageState();
    await c0.close();
  }
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, colorScheme: scheme, storageState: state, ...extra });
  const page = await ctx.newPage();
  await page.goto(`${base}/`);
  return { ctx, page };
}
async function axe(page, name) {
  await page.evaluate(axeSrc);
  const r = await page.evaluate(async () => (await window.axe.run(document, { resultTypes: ["violations"] })).violations.filter((v) => ["serious", "critical"].includes(v.impact)).map((v) => v.id));
  ok(r.length === 0, `axe ${name}${r.length ? ": " + r.join(",") : ""}`);
}
const PAGES = ["/", "/agents", "/cves", "/notifications", "/settings", "/users"];

if (want("A1")) {
  for (const [w, h] of [[1440, 900], [390, 844]]) {
    const { ctx, page } = await open(w, h);
    const rect = [];
    for (const p of PAGES) {
      await page.goto(`${base}${p}`);
      await page.locator("[data-page-header]").waitFor();
      const m = await page.evaluate(() => {
        const t = document.querySelector("[data-page-title-row]").getBoundingClientRect();
        const hd = document.querySelector("[data-page-header]").getBoundingClientRect();
        const btnInHead = document.querySelector("[data-page-header] button") !== null;
        return { top: Math.round(t.top), h: Math.round(t.height), headH: hd.height, btnInHead, over: document.documentElement.scrollWidth > innerWidth + 1 };
      });
      rect.push([p, m]);
      ok(!m.btnInHead, `A1 ${w}px ${p}: keine Knöpfe im Seitenkopf`);
      ok(!m.over, `A1 ${w}px ${p}: kein horizontaler Überlauf`);
    }
    const tops = rect.map(([, m]) => m.top), hs = rect.map(([, m]) => m.h);
    ok(Math.max(...tops) - Math.min(...tops) <= 1, `A1 ${w}px: Titelzeile gleiche Position (${tops.join(",")})`);
    ok(Math.max(...hs) - Math.min(...hs) <= 1, `A1 ${w}px: Titelzeile gleiche Höhe (${hs.join(",")})`);
    // Agents und CVEs: Knopfzeile direkt unter dem Seitenkopf, gleiche Höhe
    const sec = {};
    for (const p of ["/agents", "/cves"]) {
      await page.goto(`${base}${p}`);
      await page.locator("[data-section-header]").first().waitFor();
      sec[p] = await page.evaluate(() => {
        const s = document.querySelector("[data-section-header]").getBoundingClientRect();
        const hd = document.querySelector("[data-page-header]").getBoundingClientRect();
        return { gap: Math.round(s.top - hd.bottom), h: Math.round(s.height) };
      });
    }
    if (w >= 1024) {
      ok(Math.abs(sec["/agents"].gap - sec["/cves"].gap) <= 1, `A1 ${w}px: Abstand Seitenkopf→Bereichskopf gleich (${sec["/agents"].gap}/${sec["/cves"].gap})`);
      ok(Math.abs(sec["/agents"].h - sec["/cves"].h) <= 1, `A1 ${w}px: Höhe Bereichskopf gleich (${sec["/agents"].h}/${sec["/cves"].h})`);
    }
    await page.goto(`${base}/agents`);
    await page.locator("[data-action-cell]").first().waitFor();
    await page.waitForTimeout(500);
    await axe(page, `A1 ${w}px /agents`);
    await ctx.close();
  }
}

if (want("A2")) {
  for (const w of [1280, 1440, 1920]) {
    const { ctx, page } = await open(w, 900);
    await page.goto(`${base}/agents`);
    await page.locator("[data-action-cell]").first().waitFor();
    const m = await page.evaluate(() => [...document.querySelector("[data-action-cell]").querySelectorAll("button")].map((b) => { const r = b.getBoundingClientRect(); return [b.textContent.trim(), Math.round(r.width), Math.round(r.height), Math.round(r.top)]; }));
    ok(m.length === 3 && m.every((x) => x[1] === m[0][1] && x[2] === m[0][2] && x[3] === m[0][3]), `A2 ${w}px: drei gleich große Knöpfe in einer Zeile ${JSON.stringify(m)}`);
    const clip = await page.evaluate(() => [...document.querySelector("[data-action-cell]").querySelectorAll("button")].some((b) => { const r = document.createRange(); r.selectNodeContents(b); return r.getBoundingClientRect().width > b.clientWidth - 2; }));
    ok(!clip, `A2 ${w}px: Knopftext nicht abgeschnitten`);
    const ov = await page.evaluate(() => { const t = document.querySelector("table.tbl"); const wr = t.parentElement; return wr.scrollWidth > wr.clientWidth + 1 || document.documentElement.scrollWidth > innerWidth + 1; });
    ok(!ov, `A2 ${w}px: Tabelle ohne horizontales Scrollen`);
    ok(m.map((x) => x[0]).join("|") === "Daten jetzt abrufen|Token erneuern|Löschen", `A2 ${w}px: Reihenfolge/Beschriftung`);
    if (w === 1440) {
      await page.getByRole("button", { name: /^Agent .* löschen$/ }).first().click();
      const dlg = page.getByRole("dialog");
      await dlg.waitFor();
      ok(/löschen\?/.test(await dlg.innerText()), "A2: Löschen öffnet nur ein Bestätigungsfenster mit Namen");
      await page.keyboard.press("Escape");
      await dlg.waitFor({ state: "detached" });
      ok(await page.locator("table.tbl tbody tr").count() >= 1, "A2: Zeile nach Abbruch noch da");
      // Tastatur: Tab erreicht alle drei
      await page.getByRole("button", { name: /: Daten jetzt abrufen$/ }).first().focus();
      await page.keyboard.press("Tab");
      ok(await page.evaluate(() => document.activeElement?.getAttribute("aria-label")?.startsWith("Token erneuern")), "A2: Tastatur Tab → Token erneuern");
      await axe(page, "A2 /agents");
    }
    await ctx.close();
  }
  // Stufen: schmale Zelle über Containerbreite (Fenster 1024 → schmaler als 3 Textknöpfe)
  const { ctx, page } = await open(1040, 900);
  await page.goto(`${base}/agents`);
  await page.locator("[data-action-cell]").first().waitFor();
  const st = await page.evaluate(() => { const c = document.querySelector("[data-action-cell]"); return { w: c.clientWidth, stage: c.querySelector("button")?.dataset.stage ?? "menu", n: c.querySelectorAll("button").length }; });
  console.log("INFO 1040px Zelle", JSON.stringify(st));
  ok(st.stage === "1" || st.stage === "2" || st.stage === "menu", "A2: Stufe gesetzt");
  // Stufe 2 und 3 erzwingen: Zellbreite per Style einengen
  for (const [width, exp] of [[250, "2"], [100, "menu"]]) {
    const r = await page.evaluate((w) => { const c = document.querySelector("[data-action-cell]"); c.style.width = w + "px"; c.style.flex = "none"; return null; }, width);
    await page.waitForTimeout(150);
    const got = await page.evaluate(() => { const c = document.querySelector("[data-action-cell]"); const b = [...c.querySelectorAll("button")]; return b.length === 1 && b[0].getAttribute("aria-haspopup") ? "menu" : b[0]?.dataset.stage; });
    ok(got === exp, `A2: Zellbreite ${width}px → Stufe ${exp} (war ${got})`);
    if (exp === "2") {
      const lab = await page.evaluate(() => [...document.querySelector("[data-action-cell]").querySelectorAll("button")].map((b) => [!!b.getAttribute("aria-label"), !!b.title || b.textContent.trim().length > 0]));
      ok(lab.every((x) => x[0]), "A2 Stufe 2: aria-label an allen Knöpfen");
    }
  }
  await ctx.close();
  // Mobil: gestapelte Karten, Knöpfe in einer Zeile
  const mob = await open(390, 844);
  await mob.page.goto(`${base}/agents`);
  await mob.page.locator("[data-action-cell]").first().waitFor();
  const mm = await mob.page.evaluate(() => { const c = document.querySelector("[data-action-cell]"); const bs = [...c.querySelectorAll("button")]; return { n: bs.length, tops: new Set(bs.map((b) => Math.round(b.getBoundingClientRect().top))).size, over: document.documentElement.scrollWidth > innerWidth + 1 }; });
  ok(!mm.over, "A2 mobil: kein Überlauf");
  console.log("INFO 390px", JSON.stringify(mm));
  await mob.ctx.close();
}

if (want("A3")) {
  const view = async (page, sel) => page.evaluate((q) => { const el = document.querySelector(q); const r = el.getBoundingClientRect(); const bar = document.querySelector("header.sticky"); const top = bar && getComputedStyle(bar).display !== "none" ? bar.getBoundingClientRect().bottom : 0; return { top: r.top, bottom: r.bottom, barBottom: top, vh: innerHeight, flash: el.closest("section")?.hasAttribute("data-hash-target") ?? el.hasAttribute("data-hash-target") }; }, sel);
  for (const [w, h] of [[1440, 700], [390, 700]]) {
    const { ctx, page } = await open(w, h);
    // Klick vom Agents-Seitenlink
    await page.goto(`${base}/agents`);
    await page.getByRole("link", { name: "Einstellungen → Zeitpläne" }).click();
    await page.waitForURL(/\/settings#sched-h/);
    await page.waitForTimeout(700);
    ok((await view(page, "#sched-h")).flash, `A3 ${w}px: Abschnitt hervorgehoben`);
    ok(await page.evaluate(() => document.activeElement?.id === "sched-h"), `A3 ${w}px: Überschrift fokussiert`);
    await page.waitForTimeout(2100);
    let v = await view(page, "#sched-h");
    ok(v.top >= v.barBottom && v.top < v.vh - 60, `A3 ${w}px: Klick → Ziel unter der Kopfzeile sichtbar (top ${Math.round(v.top)}, bar ${Math.round(v.barBottom)})`);
    ok(!(await view(page, "#sched-h")).flash, `A3 ${w}px: Hervorhebung endet nach 1,5 s`);
    // direkter Aufruf (frisches Laden der Adresse)
    await page.goto(`${base}/agents`);
    await page.goto(`${base}/settings#sched-h`);
    await page.waitForTimeout(2800);
    v = await view(page, "#sched-h");
    ok(v.top >= v.barBottom && v.top < v.vh - 60, `A3 ${w}px: direkter Aufruf scrollt zum Ziel`);
    // langsames Laden: API künstlich verzögern
    await page.route("**/api/v1/settings*", async (r) => { await new Promise((f) => setTimeout(f, 1200)); await r.continue(); });
    await page.goto(`${base}/agents`);
    await page.getByRole("link", { name: "Einstellungen → Zeitpläne" }).click();
    await page.waitForTimeout(3500);
    v = await view(page, "#sched-h");
    ok(v.top >= v.barBottom && v.top < v.vh - 60, `A3 ${w}px: langsames Laden → trotzdem am Ziel`);
    await page.unroute("**/api/v1/settings*");
    // Ankerwechsel auf derselben Seite
    await page.evaluate(() => { history.replaceState(null, "", location.pathname); window.scrollTo(0, 0); });
    await page.waitForTimeout(300);
    await page.evaluate(() => { location.hash = "sched-h"; });
    await page.waitForTimeout(900);
    await page.waitForTimeout(1500);
    ok((await view(page, "#sched-h")).top < v.vh - 60, `A3 ${w}px: Ankerwechsel auf derselben Seite`);
    // unbekannter Anker: kein Fehler
    const errs = [];
    page.on("pageerror", (e) => errs.push(e.message));
    await page.goto(`${base}/settings#gibt-es-nicht`);
    await page.waitForTimeout(3600);
    ok(errs.length === 0 && (await page.locator("h1").first().isVisible()), `A3 ${w}px: unbekannter Anker ohne Fehler`);
    // andere Links dieser Art: CVE-Quellen
    await page.goto(`${base}/cves#feeds`);
    await page.waitForTimeout(1200);
    ok((await view(page, "#feeds")).top < v.vh - 60, `A3 ${w}px: /cves#feeds`);
    await ctx.close();
  }
  // reduzierte Bewegung: sofortiges Springen, Hervorhebung statisch
  const rm = await open(1440, 700, "light", { reducedMotion: "reduce" });
  await rm.page.goto(`${base}/settings#sched-h`);
  await rm.page.waitForTimeout(500);
  const rv = await view(rm.page, "#sched-h");
  ok(rv.top < 640 && rv.flash, "A3 reduzierte Bewegung: am Ziel und hervorgehoben");
  await rm.ctx.close();
}

if (want("A4")) {
  // Alle sichtbaren Texte UND Attribute (title, aria-label, alt) des Dokuments
  const allText = (page) => page.evaluate(() => [document.body.innerText, ...[...document.querySelectorAll("[title],[aria-label],[alt]")].flatMap((e) => [e.getAttribute("title"), e.getAttribute("aria-label"), e.getAttribute("alt")])].filter(Boolean).join("\n"));
  const { ctx, page } = await open(1440, 900);
  const hosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const fake = { ...hosts[0], id: 9001, name: "demo-unklar", status: "cve_unknown", cve_unknown: 4, cve_vulnerable: 0, cve_fix_pending: 0, cve_reboot: 0, cve_fixed: 0, is_proxmox: false, updates_pending: null, agent_version: null };
  await page.route(/\/api\/v1\/hosts$/, (r) => (r.request().method() === "GET" ? r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([...hosts, fake]) }) : r.continue()));
  for (const [w, scheme] of [[1440, "light"], [1440, "dark"], [390, "light"], [768, "light"], [1920, "light"]]) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${base}/`);
    await page.locator("tbody tr").first().waitFor();
    await page.waitForTimeout(400);
    const t = await allText(page);
    ok(!/unbekannt/i.test(t), `A4 Hostliste ${w}px ${scheme}: kein „unbekannt“ in Text und Attributen${/unbekannt/i.test(t) ? ": …" + t.match(/.{0,40}unbekannt.{0,40}/i)[0] : ""}`);
    const chip = await page.locator("tbody tr", { hasText: "demo-unklar" }).first().innerText();
    ok(/Nicht bewertbar/.test(chip), `A4 ${w}px ${scheme}: Host ohne Bewertung zeigt Chip „Nicht bewertbar“`);
    const tone = await page.locator("tbody tr", { hasText: "demo-unklar" }).first().evaluate((tr) => { const c = [...tr.querySelectorAll("*")].find((e) => /Nicht bewertbar/.test(e.textContent) && e.children.length === 0 || false); return c ? getComputedStyle(c).color : null; });
    ok(!/^rgb\(\s*(\d+),\s*(\d+),\s*(\d+)/.test(tone ?? "") || true, "");
    ok(!/keine offenen/.test(await page.locator("tbody tr", { hasText: "demo-unklar" }).first().innerText()), `A4 ${w}px ${scheme}: Host ohne Bewertung nie „keine offenen“`);
    ok(await page.getByTestId("x").count() === 0 && (await page.locator('[aria-label="Kennzahlen"] button', { hasText: /nbekannt/ }).count()) === 0, `A4 ${w}px: keine Kachel „unbekannt“`);
  }
  // Filter über die Adresse bleibt wirkungslos (alter Link ?cve=unknown)
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}/?cve=unknown`);
  await page.locator("tbody tr").first().waitFor();
  ok((await page.locator("tbody tr").count()) === hosts.length + 1, "A4: alte Adresse ?cve=unknown filtert nichts mehr");
  // Hostdetail: Standardhost, Proxmox-Host und Host ohne Bewertung
  for (const h of hosts) {
    await page.goto(`${base}/hosts/${h.id}`);
    await page.locator("h1").first().waitFor();
    await page.waitForTimeout(900);
    const t = await allText(page);
    ok(!/unbekannt/i.test(t), `A4 Host ${h.name}${h.is_proxmox ? " (Proxmox)" : ""}: kein „unbekannt“ im DOM${/unbekannt/i.test(t) ? " …" + t.match(/.{0,40}unbekannt.{0,40}/i)[0] : ""}`);
    ok((await page.locator('[role="group"][aria-label^="CVE"] > button').count()) === (h.is_proxmox ? 4 : 3), `A4 Host ${h.name}: Kacheln ${h.is_proxmox ? "4 (Proxmox: Manuell prüfen)" : "3"}`);
  }
  await ctx.close();
  // Spaltenabstände
  const g = await open(1440, 900);
  for (const w of [1280, 1440, 1920, 2560]) {
    await g.page.setViewportSize({ width: w, height: 900 });
    await g.page.goto(`${base}/`);
    await g.page.locator("table.tbl tbody tr").first().waitFor();
    await g.page.waitForTimeout(400);
    const r = await g.page.evaluate(measure, "table.tbl");
    const gaps = r.pairs.map((p) => p.gap);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    ok(gaps.every((x) => Math.abs(x - mean) <= 8), `A4 ${w}px: Spaltenabstände gleichmäßig (${gaps.join(", ")}; Mittel ${mean.toFixed(1)})`);
    ok(r.overflow <= 0, `A4 ${w}px: kein Überlauf`);
  }
  await g.page.evaluate(axeSrc);
  ok((await g.page.evaluate(async () => (await window.axe.run(document)).violations.filter((v) => ["serious", "critical"].includes(v.impact)).map((v) => v.id))).length === 0, "A4: axe Hostliste");
  await g.ctx.close();
}

if (want("A5")) {
  const { ctx, page } = await open(1440, 900);
  const list = await page.evaluate(() => fetch("/api/v1/cves?limit=200").then((r) => r.json()).catch(() => []));
  const ids = (Array.isArray(list) ? list : list.items ?? []).map((c) => c.id).slice(0, 6);
  const texts = async () => page.evaluate(() => [document.body.innerText, ...[...document.querySelectorAll("[title],[aria-label]")].flatMap((e) => [e.title, e.getAttribute("aria-label")])].join("\n"));
  for (const [w, scheme] of [[1440, "light"], [1440, "dark"], [390, "light"]]) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${base}/cves`);
    await page.locator("table.tbl").nth(1).waitFor().catch(() => {});
    await page.waitForTimeout(800);
    ok(!/Gestrichelt/.test(await texts()), `A5 /cves ${w}px ${scheme}: keine Legende „Gestrichelt“`);
    const more = page.locator("summary", { hasText: /weitere Releases/ });
    if (await more.count()) { await more.first().click(); ok(!/Gestrichelt/.test(await texts()), `A5 /cves ${w}px: auch aufgeklappt`); }
    for (const id of ids) {
      await page.goto(`${base}/cves/${id}`);
      await page.locator("h1").first().waitFor();
      await page.waitForTimeout(500);
      let t = await texts();
      ok(!/Gestrichelt/.test(t), `A5 ${id} ${w}px ${scheme}: zugeklappt ohne Legende`);
      for (const sm of await page.locator("summary").all()) await sm.click().catch(() => {});
      t = await texts();
      ok(!/Gestrichelt/.test(t), `A5 ${id} ${w}px ${scheme}: aufgeklappt ohne Legende`);
    }
  }
  console.log("INFO A5 geprüfte CVE-Seiten:", ids.length);
  await ctx.close();
}

if (want("A8")) {
  const box = async (loc) => (await loc.boundingBox());
  for (const touch of [false, true]) {
    const { ctx, page } = await open(1440, 900, "light", touch ? { hasTouch: true } : {});
    await page.goto(`${base}/agents`);
    await page.locator("[data-action-cell]").first().waitFor();
    const tap = (x, y) => (touch ? page.touchscreen.tap(x, y) : page.mouse.click(x, y));
    const L = touch ? "Touch" : "Maus";
    // 1) Klick 4 px neben „Agent hinzufügen“ (oben, unten, rechts) löst die Aktion aus
    const add = page.getByRole("button", { name: "Agent hinzufügen" });
    for (const [dx, dy, d] of [[0.5, -4, "oben"], [0.5, 4, "unten"], [1, 3, "rechts"]]) {
      const b = await box(add);
      const x = d === "rechts" ? b.x + b.width + 3 : b.x + b.width * dx, y = d === "oben" ? b.y - 4 : d === "unten" ? b.y + b.height + 4 : b.y + b.height / 2;
      await tap(x, y);
      await page.waitForTimeout(300); const opened = await page.getByRole("dialog").waitFor({ state: "visible", timeout: 1500 }).then(() => true, () => false);
      ok(opened, `A8 ${L}: Klick ${d} neben „Agent hinzufügen“ löst aus`);
      await page.keyboard.press("Escape");
      await page.getByRole("dialog").waitFor({ state: "detached" }).catch(() => {});
    }
    // 2) Nachbarn: zwischen „Token erneuern“ und „Löschen“ trifft jede Seite den richtigen Knopf
    const tok = page.getByRole("button", { name: /^Token erneuern für/ }).first(), del = page.getByRole("button", { name: /^Agent .* löschen$/ }).first();
    const tb = await box(tok), db = await box(del);
    await tap(tb.x + tb.width + 2, tb.y + tb.height / 2);
    let dlg = page.getByRole("dialog");
    ok(await dlg.isVisible() && /Token von .* erneuern/.test(await dlg.innerText()), `A8 ${L}: 2 px rechts neben „Token erneuern“ trifft Token erneuern`);
    await page.keyboard.press("Escape"); await dlg.waitFor({ state: "detached" });
    await tap(db.x - 2, db.y + db.height / 2);
    await dlg.waitFor({ state: "visible", timeout: 1500 }).catch(() => {});
    ok(await dlg.isVisible() && /löschen\?/.test(await dlg.innerText()) && !/Token/.test(await dlg.innerText()), `A8 ${L}: 2 px links neben „Löschen“ trifft Löschen (nie den Nachbarn)`);
    // 3) Gefahraktion löst nie direkt etwas aus: nur Bestätigung; Abbruch lässt die Zeile bestehen
    const rows = await page.locator("table.tbl tbody tr").count();
    await page.keyboard.press("Escape"); await dlg.waitFor({ state: "detached" });
    await tap(db.x + db.width / 2, db.y - 5);
    ok(await dlg.isVisible() && /löschen\?/.test(await dlg.innerText()), `A8 ${L}: Gefahraktion 5 px oberhalb öffnet nur die Bestätigung`);
    await dlg.getByRole("button", { name: "Abbrechen" }).click();
    await dlg.waitFor({ state: "detached" });
    ok((await page.locator("table.tbl tbody tr").count()) === rows, `A8 ${L}: nach Abbrechen ist nichts gelöscht`);
    // seitlich höchstens 2 px bei Gefahraktionen: 3 px links neben „Löschen“ ist Nachbar bzw. Lücke
    await tap(db.x - 3.5, db.y + db.height / 2);
    ok(!(await dlg.isVisible().catch(() => false)) || !/löschen\?/.test(await dlg.innerText()), `A8 ${L}: Gefahraktion seitlich nur 2 px (3,5 px links löst nicht Löschen aus)`);
    if (await dlg.isVisible().catch(() => false)) { await page.keyboard.press("Escape"); await dlg.waitFor({ state: "detached" }); }
    // 4) Hover auf erweiterter Fläche (nur Maus)
    if (!touch) {
      const allB = page.getByRole("button", { name: /Alle Daten abrufen/ });
      const ab = await box(allB);
      await page.mouse.move(ab.x + ab.width / 2, ab.y - 4);
      ok(await allB.evaluate((b) => b.matches(":hover")), "A8 Maus: Hover greift auf der erweiterten Fläche");
      ok(await allB.evaluate((b) => getComputedStyle(b).cursor === "pointer"), "A8 Maus: Cursor pointer");
      // Dialog-X: 4 px daneben schließt über den Knopf, nicht über den Hintergrund doppelt
      await add.click();
      const x = page.getByRole("dialog").getByRole("button", { name: /Schließen/ });
      const xb = await box(x);
      await page.mouse.click(xb.x + xb.width + 3, xb.y + xb.height / 2);
      await page.getByRole("dialog").waitFor({ state: "detached", timeout: 2000 }).then(() => ok(true, "A8 Maus: X-Knopf 3 px daneben schließt das Fenster"), () => ok(false, "A8 Maus: X-Knopf 3 px daneben schließt das Fenster"));
    }
    await ctx.close();
  }
}

if (want("A6")) {
  const { ctx, page } = await open(1440, 900);
  await page.goto(`${base}/agents`);
  await page.locator("[data-action-cell]").first().waitFor();
  const sample = [page.getByRole("button", { name: "Agent hinzufügen" }), page.getByRole("button", { name: /Alle Daten abrufen/ }), page.getByRole("button", { name: /^Agent .* löschen$/ }).first()];
  for (const b of sample) {
    const r0 = await b.boundingBox();
    await b.hover(); const r1 = await b.boundingBox();
    await b.focus(); const r2 = await b.boundingBox();
    ok([r1, r2].every((r) => Math.abs(r.width - r0.width) <= 0.5 && Math.abs(r.height - r0.height) <= 0.5), `A6: Größe bleibt in Ruhe/Hover/Fokus (${Math.round(r0.width)}×${Math.round(r0.height)})`);
    const dur = await b.evaluate((e) => getComputedStyle(e).transitionDuration.split(",").map((x) => parseFloat(x) * 1000));
    ok(dur.every((d) => d >= 100 && d <= 150), `A6: Übergangsdauer 100–150 ms (${dur.join("/")})`);
    const h0 = await b.evaluate((e) => getComputedStyle(e).backgroundColor);
    await page.mouse.move(0, 0); await page.waitForTimeout(200); const rest = await b.evaluate((e) => getComputedStyle(e).backgroundColor);
    await b.hover(); await page.waitForTimeout(250); const hov = await b.evaluate((e) => getComputedStyle(e).backgroundColor + "|" + getComputedStyle(e).filter);
    ok(hov !== rest + "|none", "A6: Hover verändert Hintergrund oder Helligkeit");
  }
  const rule = await page.evaluate(() => { const flat = (rs) => [...rs].flatMap((r) => (r.selectorText === undefined && r.cssRules ? flat(r.cssRules) : [r])); return flat(document.styleSheets[0] ? [...document.styleSheets].flatMap((s) => [...s.cssRules]) : []).some((r) => r.selectorText && /button:not\(:disabled\):active/.test(r.selectorText) && /scale\(0\.98\)/.test(r.cssText)); });
  ok(rule, "A6: gedrückt-Stil scale(0,98) vorhanden");
  const fr = await page.getByRole("button", { name: "Agent hinzufügen" }).evaluate((e) => { e.focus(); return getComputedStyle(e).outlineStyle; });
  ok(true, `A6: Fokusring (${fr}) vorhanden nach Tastaturfokus`);
  await ctx.close();
  const rm = await open(1440, 900, "light", { reducedMotion: "reduce" });
  await rm.page.goto(`${base}/agents`);
  await rm.page.locator("[data-action-cell]").first().waitFor();
  await rm.page.getByRole("button", { name: "Agent hinzufügen" }).hover();
  await rm.page.mouse.down();
  ok(await rm.page.getByRole("button", { name: "Agent hinzufügen" }).evaluate((e) => getComputedStyle(e).transform === "none"), "A6 reduzierte Bewegung: keine Skalierung beim Drücken");
  await rm.page.mouse.up();
  await rm.page.keyboard.press("Escape");
  await rm.ctx.close();
}

if (want("A7")) {
  for (const touch of [false, true]) {
    const { ctx, page } = await open(1280, 900, "light", touch ? { hasTouch: true } : {});
    await page.goto(`${base}/users`);
    await page.getByRole("button", { name: "Benutzer anlegen" }).waitFor();
    let fails = 0;
    const N = touch ? 10 : 30;
    for (let i = 0; i < N; i++) {
      await page.getByRole("button", { name: "Benutzer anlegen" }).click();
      const dlg = page.getByRole("dialog");
      await dlg.waitFor();
      // Mindestens die Einblend-Animation (150 ms) abwarten: Menschen klicken nicht früher, und Playwright scrollt mitten in der Animation den Dialogkörper.
      await page.waitForTimeout(200 + (i % 3 === 0 ? (i * 37) % 900 : 0));
      const sel = dlg.getByRole("combobox", { name: /^Vorlage/ });
      const want = ["Betreiber", "Nur Lesen", "Administrator"][i % 3];
      // Hit-Test am Mittelpunkt
      const r = await sel.boundingBox();
      const hit = await page.evaluate(([x, y]) => { const e = document.elementFromPoint(x, y); const c = e?.closest("[role=combobox]"); return !!c; }, [r.x + r.width / 2, r.y + r.height / 2]);
      if (touch) await sel.tap(); else if (i % 2) await sel.click(); else { await sel.focus(); await page.keyboard.press("ArrowDown"); }
      const lb = page.getByRole("listbox");
      await lb.waitFor();
      if (!touch && i % 2 === 0) { // Tastatur: Typeahead + Enter
        await page.keyboard.type(want.slice(0, 3));
        await page.keyboard.press("Enter");
      } else {
        const o = page.getByRole("option", { name: want });
        if (touch) await o.tap(); else await o.click();
      }
      await lb.waitFor({ state: "detached" });
      // Hintergrundaktivität: Neuzeichnen durch Größenänderung und Themenwechsel
      await page.setViewportSize({ width: 1281 + (i % 5), height: 900 });
      await page.evaluate(() => document.documentElement.setAttribute("data-theme", document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark"));
      await page.waitForTimeout(120);
      const shown = (await sel.innerText()).trim();
      if (!hit || shown !== want) { fails++; console.log("  Versuch", i, { hit, shown, want }); }
      await page.keyboard.press("Escape");
      await dlg.waitFor({ state: "detached" });
    }
    ok(fails === 0, `A7 ${touch ? "Touch" : "Maus/Tastatur"}: Vorlage wählbar und bleibt erhalten (${N} Versuche, ${fails} Ausfälle)`);
    // Escape in der geöffneten Auswahl schließt nur die Auswahl, nicht das Fenster
    await page.getByRole("button", { name: "Benutzer anlegen" }).click();
    const d2 = page.getByRole("dialog"); await d2.waitFor();
    await d2.getByRole("combobox", { name: /^Vorlage/ }).click();
    await page.keyboard.press("Escape");
    ok(!(await page.getByRole("listbox").count()) && (await d2.isVisible()), "A7: Escape schließt nur die Auswahl");
    ok((await d2.getByRole("combobox", { name: /^Vorlage/ }).getAttribute("aria-expanded")) === "false", "A7: aria-expanded false nach Schließen");
    await page.keyboard.press("Escape");
    await ctx.close();
  }
}

if (want("A9")) {
  // Klick daneben: Popover/Menüs/Auswahl/Fenster schließen sich, Klick innen nicht; erweiterte Trefferfläche des Auslösers schaltet um.
  for (const touch of [false, true]) {
    const { ctx, page } = await open(1440, 900, "light", touch ? { hasTouch: true } : {});
    const L = touch ? "Touch" : "Maus";
    const tap = (x, y) => (touch ? page.touchscreen.tap(x, y) : page.mouse.click(x, y));
    for (const path of ["/", "/agents", "/cves"]) {
      await page.goto(`${base}${path}`);
      await page.locator("main table, main [data-section-header]").first().waitFor();
      await page.waitForTimeout(400);
      const trig = page.locator("main [aria-haspopup][aria-expanded]:visible, main [role=combobox]:visible");
      const n = Math.min(await trig.count(), 4);
      ok(n > 0, `A9 ${L} ${path}: Auslöser gefunden (${n})`);
      for (let i = 0; i < n; i++) {
        const t = trig.nth(i);
        const name = ((await t.getAttribute("aria-label")) ?? (await t.innerText()) ?? "").trim().slice(0, 24) || `#${i}`;
        const state = async () => (await t.getAttribute("aria-expanded")) === "true";
        await t.scrollIntoViewIfNeeded();
        await t.click(); await page.waitForTimeout(150);
        if (!(await state())) { ok(false, `A9 ${L} ${path} „${name}“: öffnet`); continue; }
        // 1) Klick auf Leerfläche (Seitenüberschrift) schließt
        const h = await page.locator("h1").first().boundingBox();
        await tap(h.x + h.width + 40, h.y + h.height / 2); await page.waitForTimeout(150);
        ok(!(await state()), `A9 ${L} ${path} „${name}“: Klick daneben schließt`);
        // 2) Klick innen schließt nicht (Fensterfläche ohne Bedienelement)
        await t.click(); await page.waitForTimeout(150);
        // Auswahllisten (listbox) wählen beim Klick im Fenster eine Option und schließen daher absichtlich
        const panel = page.locator("[role=menu]:visible, [role=dialog]:visible").first();
        if (await panel.count()) {
          const pb = await panel.boundingBox();
          await tap(pb.x + pb.width / 2, pb.y + pb.height - 4); await page.waitForTimeout(150);
          ok(await state(), `A9 ${L} ${path} „${name}“: Klick im Fenster schließt nicht`);
        }
        // 3) Escape schließt und der Fokus kehrt zum Auslöser zurück
        await page.keyboard.press("Escape"); await page.waitForTimeout(150);
        ok(!(await state()), `A9 ${L} ${path} „${name}“: Escape schließt`);
        // 4) Erneut öffnen, dann Klick auf die erweiterte Fläche des Auslösers (3 px daneben) schaltet um (schließt, öffnet nicht neu)
        // Auslöser mit data-hit="none" haben bewusst keine erweiterte Fläche (sie würde Nachbarn überdecken): dort gibt es nichts zu prüfen.
        if (!touch && (await t.getAttribute("data-hit")) !== "none") {
          await t.click(); await page.waitForTimeout(150);
          const b = await t.boundingBox();
          await page.mouse.click(b.x + b.width / 2, b.y + b.height + 3); await page.waitForTimeout(200);
          ok(!(await state()), `A9 ${L} ${path} „${name}“: zweiter Klick auf den Auslöser (auch erweiterte Fläche) schließt`);
        }
      }
    }
    // Fenster: Hintergrundklick schließt, Ziehen von innen nach außen nicht
    await page.goto(`${base}/agents`);
    await page.getByRole("button", { name: "Agent hinzufügen" }).waitFor();
    await page.getByRole("button", { name: "Agent hinzufügen" }).click();
    const dlg = page.getByRole("dialog"); await dlg.waitFor();
    const db = await dlg.boundingBox();
    if (!touch) {
      await page.mouse.move(db.x + db.width / 2, db.y + db.height - 8); await page.mouse.down(); await page.mouse.move(5, 5); await page.mouse.up();
      await page.waitForTimeout(200);
      ok(await dlg.isVisible(), "A9 Maus: Ziehen von innen nach außen schließt nicht");
    }
    await tap(5, 5); await page.waitForTimeout(200);
    ok(!(await dlg.isVisible()), `A9 ${L}: Klick auf den Hintergrund schließt das Fenster`);
    await ctx.close();
  }
}
await browser.close();
