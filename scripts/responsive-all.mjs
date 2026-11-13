// Responsiv-Prüfung über alle Seiten, Zustände und Breiten. Keine verändernden Aktionen (nichts speichern, löschen, abrufen).
//
//   PW_MODULE=… PW_CHROME=… PW_BASE=http://127.0.0.1:3300 PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=…/axe.min.js \
//   node scripts/responsive-all.mjs <ergebnis.md> [gruppe,gruppe,…]
//
// Vor jedem Lauf den Server neu starten (scripts/dev-stack.sh restart-server): setzt das Login-Limit zurück. Die Anmeldung
// geschieht einmal je Prozess; die Sitzung (storageState) wird von allen Gruppen und Kontexten wiederverwendet.
// Umgebung: PW_BASE, PW_USER (admin), PW_PASSWORD oder PW_PWFILE, AXE_JS, PW_VARIANTS (Kommaliste von Varianten-IDs zum Eingrenzen).
// Gruppen (nacheinander, je Gruppe ein Browser, danach geschlossen): login, hosts, host-detail, cves, cve-detail, cve-sources,
// agents, notifications, settings, notfound, sidebar. Exit 1 bei Verstößen; offene Verstöße bleiben rot, nichts wird ausgeblendet.
//
// Prüfungen (Nummern wie im Auftrag):
//  1 kein horizontaler Seitenüberlauf (documentElement.scrollWidth <= clientWidth)
//  2 kein abgeschnittener Text in Knöpfen, Chips, Tabellenköpfen (scrollWidth > clientWidth, ohne title / Ellipsen-Absicht)
//    und keine Überlappung gleichrangiger Knöpfe
//  3 offene Popover/Dialoge/Menüs vollständig im Viewport
//  4 unter 768 px: Trefferflächen >= 44x44 (Knöpfe, Links außerhalb von Fließtext, Formularfelder)
//  5 gleichrangige Knöpfe einer Zeile gleich hoch (±0,5 px)
//  6 Tabellen ab 1024 px: letzte Spalte endet am rechten Inhaltsrand (±1 px); gestapelte Tabellen (Kopf nur für Screenreader,
//    bei großer Schrift): die Einträge enden am rechten Inhaltsrand (±1 px)
//  9 axe: keine Verstöße der Stufen serious/critical (bei 390 und 1440, hell und dunkel)
// 10 Layoutsprung: Position der Hauptüberschrift 500 ms nach ihrem Erscheinen unverändert (±0,5 px)
//
// Begründete Ausnahmen (kein Verstoß, weil die Prüfung sonst falsch positiv wäre):
//  A1 Inline-Textlinks (display:inline, nicht in nav/aside): WCAG 2.5.8 nimmt Links im Fließtext von der Mindestgröße aus.
//  A2 Tabellenkopf-Knöpfe (Sortierung): der Kopf ist unter 768 px ausgeblendet (gestapelte Einträge), dort keine Bedienung.
//  A3 Elemente in [inert]/aria-hidden/visibility:hidden (geschlossenes Off-Canvas-Menü) und sr-only (<= 1 px) zählen nicht.
//  A6 Icon-Rail: Beschriftungen mit opacity:0 (Sidebar 768–1023 px, Tooltip und Name im Link) sind gewollt unsichtbar.
//  A4 Ellipsen-Absicht: text-overflow:ellipsis oder gesetztes title/aria-label gelten als gewollte Kürzung (Tooltip nennt den Text).
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";

const base = (process.env.PW_BASE ?? "http://127.0.0.1:3300").replace(/\/$/, "");
const user = process.env.PW_USER ?? "admin";
const password = process.env.PW_PASSWORD ?? (process.env.PW_PWFILE ? readFileSync(process.env.PW_PWFILE, "utf8").trim() : (console.error("PW_PASSWORD oder PW_PWFILE setzen"), process.exit(1)));
const axeSrc = readFileSync(process.env.AXE_JS ?? "web/node_modules/axe-core/axe.min.js", "utf8");
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE ?? "playwright");
const outFile = process.argv[2];
const wantGroups = process.argv[3]?.split(",");

// ---------- Varianten ----------
const WIDTHS = [320, 360, 390, 430, 768, 820, 1024, 1180, 1280, 1440, 1920, 2560];
const hOf = (w) => (w < 768 ? 844 : w >= 2560 ? 1440 : w >= 1920 ? 1080 : 900);
const VARIANTS = [
  ...WIDTHS.map((w) => ({ id: String(w), w, h: hOf(w), scheme: "light", axe: w === 390 || w === 1440 })),
  ...[390, 1024, 1440].map((w) => ({ id: `${w}d`, w, h: hOf(w), scheme: "dark", axe: w !== 1024 })),
  ...[390, 1440].map((w) => ({ id: `${w}rm`, w, h: hOf(w), scheme: "light", rm: true })),
  { id: "L844", w: 844, h: 390, scheme: "light" },
  { id: "L1024", w: 1024, h: 768, scheme: "light" },
  // Zoom 200 %: Ein 1440er-Fenster mit 200 % Browserzoom hat 720 CSS-px Breite bei doppelter Pixeldichte.
  { id: "Z200", w: 720, h: 450, scheme: "light", dsf: 2 },
  // Schriftzoom 200 %: html font-size verdoppelt (die Schriftstufen sind rem).
  { id: "F1280", w: 1280, h: 800, scheme: "light", font: true },
  { id: "F390", w: 390, h: 844, scheme: "light", font: true },
];
const onlyV = process.env.PW_VARIANTS?.split(",");

// ---------- Messfunktionen (laufen im Browser) ----------
/** Alle Layout-Prüfungen einer Seite. Gibt [{check, sev, key, msg}] zurück. */
function inspect({ narrow, wide1024 }) {
  const out = [];
  const add = (check, sev, key, msg) => out.push({ check, sev, key, msg });
  const vw = innerWidth, vh = innerHeight;
  const sr = (r) => r.width <= 1 || r.height <= 1;
  const hidden = (el) => {
    const cs = getComputedStyle(el);
    if (cs.visibility === "hidden" || cs.display === "none") return true;
    if (el.closest("[inert]") || el.closest('[aria-hidden="true"]')) return true; // A3
    // Visuell versteckter Bereich (sr-only, z. B. Tabellenkopf der gestapelten Ansicht): ein Vorfahr ist <= 1 px groß und schneidet ab.
    for (let e = el.parentElement, i = 0; e && e !== document.body && i < 8; e = e.parentElement, i++) {
      const r = e.getBoundingClientRect();
      if ((r.width <= 1 || r.height <= 1) && getComputedStyle(e).overflow !== "visible") return true;
    }
    return false;
  };
  const rectOf = (el) => (hidden(el) ? null : (() => { const r = el.getBoundingClientRect(); return sr(r) ? null : r; })());
  const label = (el) => `${el.tagName.toLowerCase()} "${(el.getAttribute("aria-label") || el.textContent || el.getAttribute("title") || el.getAttribute("name") || "").replace(/\s+/g, " ").trim().slice(0, 40)}"`;
  const inScroller = (el) => { for (let e = el.parentElement; e && e !== document.body; e = e.parentElement) if (/auto|scroll|hidden|clip/.test(getComputedStyle(e).overflowX) && e.scrollWidth > e.clientWidth) return true; return false; };

  // 1 Seitenüberlauf
  const de = document.documentElement;
  if (de.scrollWidth > de.clientWidth) {
    const culprits = [...document.body.querySelectorAll("*")].filter((e) => { const r = rectOf(e); return r && r.right > vw + 0.5 && !inScroller(e) && getComputedStyle(e).position !== "fixed"; }).slice(0, 3).map(label);
    add(1, 1, "Seitenüberlauf", `scrollWidth ${de.scrollWidth} > clientWidth ${de.clientWidth}${culprits.length ? "; z. B. " + culprits.join(", ") : ""}`);
  }

  // 2 abgeschnittener Text (Knöpfe, Chips, Tabellenköpfe) und Überlappung
  const textBoxes = document.querySelectorAll('button, [role="button"], summary, th, [role="tab"], [role="radio"], .chip-fade, [data-status-badge], [class*="rounded-xs"][class*="border"]');
  for (const el of textBoxes) {
    const r = rectOf(el);
    if (!r || getComputedStyle(el).display === "inline") continue;
    // Knöpfe haben ein ::before für die erweiterte Trefferfläche, das in scrollWidth mitzählt (Fehlalarm): dort wird die
    // tatsächliche Breite des Inhalts (Range) mit dem Knopf verglichen.
    let cut = el.scrollWidth > el.clientWidth + 1;
    if (cut && el.matches('button, [role="button"], summary')) {
      // Nur sichtbarer Text: verborgene Hilfstexte (sr-only, absolut positioniert) zählen nicht.
      const br = el.getBoundingClientRect();
      let over = false;
      const tw = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      for (let n = tw.nextNode(); n; n = tw.nextNode()) {
        if (!n.textContent.trim()) continue;
        const pe = n.parentElement;
        if (pe && pe.closest("[class*=\"sr-only\"]") && el.contains(pe.closest("[class*=\"sr-only\"]"))) continue;
        if (pe && getComputedStyle(pe).position === "absolute") continue;
        const rg = document.createRange();
        rg.selectNodeContents(n);
        const cr = rg.getBoundingClientRect();
        if (cr.width > 0 && (cr.right > br.right + 1 || cr.left < br.left - 1)) over = true;
      }
      cut = over;
    }
    if (cut) {
      const cs = getComputedStyle(el);
      // A6: Icon-Rail (768–1023 px) blendet Beschriftungen per opacity:0 aus; der Name bleibt im Link/Knopf lesbar.
      const railHidden = [...el.children].some((c) => c.textContent.trim() && getComputedStyle(c).opacity === "0");
      const intent = railHidden || cs.textOverflow === "ellipsis" || el.hasAttribute("title") || el.querySelector("[title]"); // A4
      if (!intent) add(2, 1, `Text abgeschnitten ${label(el)}`, `scrollWidth ${el.scrollWidth} > clientWidth ${el.clientWidth}`);
    }
  }
  const btnSel = 'button, [role="button"], summary';
  const kids = new Map();
  for (const b of document.querySelectorAll(btnSel)) {
    if (b.closest("thead")) continue; // A2
    const r = rectOf(b);
    if (!r) continue;
    const p = b.parentElement;
    if (!kids.has(p)) kids.set(p, []);
    kids.get(p).push([b, r]);
  }
  for (const [, list] of kids) {
    for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) {
      const [a, ra] = list[i], [b, rb] = list[j];
      const ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left), oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
      if (ox > 1 && oy > 1) add(2, 1, `Knöpfe überlappen ${label(a)} / ${label(b)}`, `${ox.toFixed(1)}x${oy.toFixed(1)} px`);
    }
    // 5 gleiche Höhe in einer Zeile (gleichrangige Knöpfe desselben Elternelements, vertikal überlappend)
    for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) {
      const [a, ra] = list[i], [b, rb] = list[j];
      const oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
      if (oy > Math.min(ra.height, rb.height) / 2 && Math.abs(ra.height - rb.height) > 0.5) add(5, 3, `Höhe ungleich ${label(a)} / ${label(b)}`, `${ra.height.toFixed(1)} vs ${rb.height.toFixed(1)} px`);
    }
  }

  // 3 Fenster im Viewport
  for (const el of document.querySelectorAll('dialog[open], [role="dialog"], [role="alertdialog"], [role="menu"], [role="listbox"], [role="tooltip"], [popover]:popover-open')) {
    const r = rectOf(el);
    if (!r) continue;
    const d = { l: r.left, t: r.top, r: vw - r.right, b: vh - r.bottom };
    if (d.l < -0.5 || d.t < -0.5 || d.r < -0.5 || d.b < -0.5) add(3, 1, `Fenster außerhalb ${label(el)}`, `Abstand links ${d.l.toFixed(1)}, oben ${d.t.toFixed(1)}, rechts ${d.r.toFixed(1)}, unten ${d.b.toFixed(1)} (Viewport ${vw}x${vh})`);
  }

  // 4 Trefferflächen unter 768 px
  if (narrow) {
    const els = document.querySelectorAll('a[href], button, [role="button"], summary, select, input:not([type="hidden"]), textarea, [role="tab"], [role="radio"], [role="menuitem"]');
    for (const el of els) {
      if (el.closest("thead")) continue; // A2
      const isBox = el.matches('input[type="checkbox"], input[type="radio"]');
      const target = isBox ? el.closest("label") ?? el : el;
      if (hidden(el) || hidden(target)) continue;
      const cs = getComputedStyle(target);
      const r = target.getBoundingClientRect();
      if (sr(r)) continue;
      if (r.right < 0 || r.left > vw) continue; // außerhalb des Fensters (Off-Canvas)
      if (cs.display === "inline" && target.tagName === "A" && !target.closest("nav, aside")) continue; // A1
      if (r.height < 43.5 || r.width < 43.5) add(4, 2, `Trefferfläche ${label(target)}`, `${r.width.toFixed(0)}x${r.height.toFixed(0)} px`);
    }
  }

  // 6 letzte Tabellenspalte am Inhaltsrand (ab 1024 px)
  if (wide1024) {
    const main = document.querySelector("main");
    for (const t of document.querySelectorAll("table.tbl:not([data-t])")) {
      const tr = rectOf(t);
      if (!tr || !main) continue;
      const contentRight = main.getBoundingClientRect().right - 24;
      const head = [...t.querySelectorAll("thead th")];
      // Gestapelte Ansicht (bei großer Schrift auch ab 1024 px): der Kopf ist nur für Screenreader da (A3), seine Zellen liegen
      // in einem 1-px-Ausschnitt und sind keine Spalten. Dann müssen die sichtbaren Einträge (Zeilen) am Rand enden.
      const stacked = head.length > 0 && head.every((h) => hidden(h));
      const ths = head.filter((h) => h.getBoundingClientRect().width > 0);
      const rows = [...t.querySelectorAll("tbody tr")].map((r) => r.getBoundingClientRect()).filter((r) => r.width > 0);
      if (stacked ? !rows.length : !ths.length) continue;
      const last = stacked ? Math.max(...rows.map((r) => r.right)) : ths[ths.length - 1].getBoundingClientRect().right;
      // Tabellen in schmalen Spalten (z. B. neben der Host-Details-Leiste) enden am Rand ihrer Spalte, nicht der Seite.
      const col = t.closest("section, div")?.getBoundingClientRect().right ?? contentRight;
      const edge = Math.min(contentRight, col);
      if (Math.abs(last - edge) > 1) add(6, 3, `Tabelle ${t.querySelector("caption")?.textContent.trim().slice(0, 30) ?? "?"}: ${stacked ? "gestapelte Einträge" : "letzte Spalte"}`, `endet bei ${last.toFixed(1)}, Rand ${edge.toFixed(1)}`);
    }
  }
  return out;
}

async function axeScan(page) {
  await page.evaluate(axeSrc);
  const r = await page.evaluate(() => globalThis.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] }));
  return r.violations.filter((v) => v.impact === "serious" || v.impact === "critical").map((v) => ({ check: 9, sev: 1, key: `axe ${v.id}`, msg: `${v.impact}: ${v.help}; ${v.nodes[0]?.target.join(" ")}` }));
}

// ---------- Zustände ----------
const settle = async (page) => { await page.waitForLoadState("networkidle").catch(() => {}); await page.waitForTimeout(400); };
const openFilter = async (page) => { await page.getByRole("button", { name: /^Filter/ }).click(); await page.getByRole("dialog", { name: "Filter" }).waitFor(); };
const first = (page) => page.getByRole("button", { name: /^Weitere Aktionen für / }).first();
const NOTIF = ["ntfy", "matrix", "gotify", "discord", "browser"];
/** state: { name, path, prep?(page, v) → "skip" | void, after?(page) } */
const GROUPS = {
  login: { auth: false, states: [
    { name: "Login", path: "/login" },
    // Fehlermeldung: die Antwort des Servers wird nachgestellt (401), damit kein echter Fehlversuch das Login-Limit belastet;
    // die Meldung selbst rendert die echte Seite.
    { name: "Login mit Fehlermeldung", path: "/login", shift: false, prep: async (page) => {
      await page.route("**/api/v1/auth/login", (r) => r.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ error: "unauthorized" }) }));
      await page.getByLabel("Benutzername").fill("admin");
      await page.getByLabel("Passwort").fill("falsches-passwort");
      await page.getByRole("button", { name: "Anmelden" }).click();
      await page.locator("form [role=alert]").waitFor();
    }, after: (page) => page.unroute("**/api/v1/auth/login") },
  ] },
  hosts: { states: [{ name: "Hosts", path: "/" }] },
  "host-detail": { states: [
    { name: "Host Ubuntu (offene CVEs, web-02)", path: "/hosts/host:web-02" },
    { name: "Host mit Neustart (db-02)", path: "/hosts/host:db-02?cve=reboot" },
    { name: "Host Proxmox (pve-01)", path: "/hosts/host:pve-01" },
    { name: "Host ohne Daten (neu-01)", path: "/hosts/host:neu-01" },
  ] },
  cves: { states: [
    { name: "CVEs Liste", path: "/cves" },
    { name: "CVEs Filter-Fenster offen", path: "/cves", shift: false, prep: openFilter },
    { name: "CVEs nur Watchlist", path: "/cves", shift: false, prep: async (page) => { await page.getByRole("button", { name: "Nur Watchlist" }).click(); await page.waitForTimeout(300); } },
    { name: "CVEs aktiver Filter", path: "/cves", shift: false, prep: async (page) => {
      await openFilter(page);
      await page.getByRole("dialog", { name: "Filter" }).getByRole("radiogroup", { name: "Debian" }).getByRole("radio", { name: "offen" }).click();
      await page.getByRole("dialog", { name: "Filter" }).getByRole("button", { name: "Fertig" }).click();
      await page.getByRole("list", { name: "Aktive Filter" }).waitFor();
    } },
    { name: "CVEs leeres Ergebnis", path: "/cves", shift: false, prep: async (page) => {
      await page.getByRole("searchbox").fill("zzzzzz");
      await page.waitForTimeout(800);
    } },
  ] },
  "cve-detail": { states: [{ name: "CVE-Detail", path: "/cves/CVE-2024-1086" }] },
  "cve-sources": { states: [
    { name: "Quellen-Tabelle", path: "/cves" },
    { name: "Dialog Quelle hinzufügen", path: "/cves", shift: false, prep: async (page) => {
      await page.getByRole("button", { name: "Quelle hinzufügen" }).first().click();
      await page.getByRole("dialog", { name: "Quelle hinzufügen" }).waitFor();
    }, after: async (page) => { await page.getByRole("dialog").getByRole("button", { name: "Abbrechen" }).click(); } },
  ] },
  agents: { states: [
    { name: "Agents Liste", path: "/agents" },
    { name: "Agents …-Menü offen", path: "/agents", shift: false, prep: async (page) => {
      // Das Zeilenmenü gibt es nur bei zu schmaler Aktionszelle (Stufe 3); sonst stehen die Knöpfe nebeneinander.
      await page.locator("[data-action-cell]").first().waitFor();
      if (!(await first(page).count())) return "skip";
      await first(page).click();
      await page.getByRole("dialog", { name: /^Weitere Aktionen für / }).waitFor();
    } },
    { name: "Dialog Agent hinzufügen", path: "/agents", shift: false, prep: async (page) => {
      await page.getByRole("button", { name: "Agent hinzufügen" }).first().click();
      await page.getByRole("dialog", { name: /Agent hinzufügen/ }).waitFor();
    }, after: async (page) => { await page.getByRole("dialog").getByRole("button", { name: "Abbrechen" }).click(); } },
  ] },
  notifications: { states: [
    { name: "Benachrichtigungen", path: "/notifications" },
    ...NOTIF.map((c) => ({ name: `Kanal ${c}`, path: `/notifications/${c}` })),
  ] },
  settings: { states: [{ name: "Einstellungen", path: "/settings" }] },
  notfound: { states: [{ name: "404-Seite", path: "/gibt-es-nicht" }] },
  sidebar: { states: [
    // Eingeklappt ab 1024 px per Knopf; darunter ist die Leiste fest (Icon-Rail bzw. Off-Canvas) und der Zustand entfällt.
    { name: "Sidebar eingeklappt", path: "/", shift: false, prep: async (page, v) => {
      if (v.w < 1024) return "skip";
      await page.getByRole("button", { name: "Seitenleiste ausblenden" }).click();
      await page.waitForTimeout(500);
    }, after: async (page, v) => { if (v.w >= 1024) { await page.getByRole("button", { name: "Seitenleiste einblenden" }).click(); await page.waitForTimeout(300); } } },
    { name: "Sidebar Off-Canvas offen", path: "/", shift: false, prep: async (page, v) => {
      if (v.w >= 768) return "skip";
      await page.getByRole("button", { name: "Menü", exact: true }).click();
      await page.getByRole("dialog", { name: "Navigation" }).waitFor();
      await page.waitForTimeout(400);
    } },
  ] },
};

// ---------- Lauf ----------
const ids = {};
let storageState;
const results = []; // {group, state, variant, viol: [...] , err?}

async function login(browser) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill(user);
  await page.getByLabel("Passwort").fill(password);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  Object.assign(ids, Object.fromEntries(await page.evaluate(async () => (await (await fetch("/api/v1/hosts")).json()).map((h) => [h.name, h.id]))));
  storageState = await ctx.storageState();
  await ctx.close();
}

async function runGroup(name, g) {
  const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
  try {
    if (g.auth !== false && !storageState) await login(browser);
    for (const v of VARIANTS) {
      if (onlyV && !onlyV.includes(v.id)) continue;
      const ctx = await browser.newContext({
        viewport: { width: v.w, height: v.h }, colorScheme: v.scheme, reducedMotion: v.rm ? "reduce" : "no-preference",
        deviceScaleFactor: v.dsf ?? 1, ...(g.auth === false ? {} : { storageState }),
      });
      const page = await ctx.newPage();
      for (const s of g.states) {
        const rec = { group: name, state: s.name, variant: v.id, viol: [] };
        results.push(rec);
        try {
          const path = s.path.replace(/host:([\w.-]+)/, (_, n) => ids[n] ?? (() => { throw new Error(`Host ${n} fehlt`); })());
          await page.goto(base + path, { waitUntil: "domcontentloaded" });
          if (v.font) await page.addStyleTag({ content: "html{font-size:200% !important}" });
          // 10 Layoutsprung: Hauptüberschrift 500 ms nach dem Erscheinen unverändert
          const h1 = page.locator("h1").first();
          await h1.waitFor({ state: "visible", timeout: 15000 });
          const pos = () => h1.evaluate((e) => { const r = e.getBoundingClientRect(); return [r.left, r.top + scrollY]; });
          const p1 = await pos();
          await page.waitForTimeout(500);
          const p2 = await pos();
          if (s.shift !== false && (Math.abs(p1[0] - p2[0]) > 0.5 || Math.abs(p1[1] - p2[1]) > 0.5)) {
            rec.viol.push({ check: 10, sev: 3, key: "Layoutsprung Hauptüberschrift", msg: `x ${p1[0].toFixed(1)} -> ${p2[0].toFixed(1)}, y ${p1[1].toFixed(1)} -> ${p2[1].toFixed(1)}` });
          }
          await settle(page);
          if (s.prep && (await s.prep(page, v)) === "skip") { rec.skip = true; continue; }
          await page.waitForTimeout(300);
          rec.viol.push(...(await page.evaluate(inspect, { narrow: v.w < 768, wide1024: v.w >= 1024 })));
          if (v.axe) rec.viol.push(...(await axeScan(page)));
          if (s.after) await s.after(page, v);
        } catch (e) {
          rec.viol.push({ check: 0, sev: 1, key: "Zustand nicht erreichbar", msg: String(e.message).split("\n")[0].slice(0, 160) });
        }
      }
      await ctx.close();
    }
  } finally {
    await browser.close(); // nach jeder Gruppe schließen
  }
}

for (const [name, g] of Object.entries(GROUPS)) {
  if (wantGroups && !wantGroups.includes(name)) continue;
  const t = Date.now();
  await runGroup(name, g);
  const n = results.filter((r) => r.group === name).reduce((a, r) => a + r.viol.length, 0);
  console.log(`${n ? "FAIL" : "OK  "} ${name}: ${n} Verstöße (${Math.round((Date.now() - t) / 1000)} s)`);
}

// ---------- Auswertung ----------
const SEV = { 1: "hoch", 2: "mittel", 3: "niedrig" };
const vids = VARIANTS.filter((v) => !onlyV || onlyV.includes(v.id)).map((v) => v.id);
const lines = ["# Responsiv-Prüfung", "", `Varianten: ${vids.join(", ")}. Zelle: ok = bestanden, Zahl = Anzahl Verstöße, – = Zustand entfällt.`, ""];
const rows = new Map();
for (const r of results) { const k = `${r.group} / ${r.state}`; if (!rows.has(k)) rows.set(k, new Map()); rows.get(k).set(r.variant, r); }
lines.push(`| Seite / Zustand | ${vids.join(" | ")} |`, `|---|${vids.map(() => "---").join("|")}|`);
for (const [k, m] of rows) lines.push(`| ${k} | ${vids.map((v) => { const r = m.get(v); return !r ? "" : r.skip ? "–" : r.viol.length ? String(r.viol.length) : "ok"; }).join(" | ")} |`);
// Verstöße gruppiert nach Seite, Prüfung, Schlüssel; Messwerte je Variante
const groups = new Map();
for (const r of results) for (const x of r.viol) {
  const k = `${r.state}|${x.check}|${x.key}`;
  if (!groups.has(k)) groups.set(k, { state: r.state, ...x, at: [] });
  groups.get(k).at.push(`${r.variant}: ${x.msg}`);
}
const list = [...groups.values()].sort((a, b) => a.sev - b.sev || a.check - b.check);
lines.push("", `## Verstöße (${list.length} verschieden)`, "");
if (!list.length) lines.push("Keine.");
for (const x of list) lines.push(`- **${SEV[x.sev]}** (Prüfung ${x.check}) ${x.state}: ${x.key}`, ...x.at.slice(0, 6).map((a) => `  - ${a}`), ...(x.at.length > 6 ? [`  - … und ${x.at.length - 6} weitere Varianten`] : []));
const total = results.reduce((a, r) => a + r.viol.length, 0);
lines.push("", `${results.length} Zustände x Varianten geprüft, ${total} Verstöße.`);
if (outFile) writeFileSync(outFile, lines.join("\n") + "\n");
console.log(`${results.length} Prüfungen, ${total} Verstöße, ${list.length} verschiedene`);
for (const x of list.slice(0, 60)) console.log(`  [${SEV[x.sev]}] ${x.state}: ${x.key} (${x.at.length}x) ${x.at[0]}`);
process.exit(total ? 1 : 0);
