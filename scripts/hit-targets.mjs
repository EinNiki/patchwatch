// Misst die tatsächliche Trefferfläche aller bedienbaren Elemente (elementFromPoint im Raster um das Element) und prüft:
//  (1) jede sichtbare Fläche eines Elements gehört ihm selbst (kein Nachbar mit erweiterter Fläche liegt darüber),
//  (2) die Trefferfläche erreicht (soweit der Platz es zulässt) 44 × 44 px; Ergebnis als Tabelle docs/hit-targets.md.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=… [PW_BASE=…] [HT_WIDTHS=1440,390] [HT_WRITE=docs/hit-targets.md] node scripts/hit-targets.mjs
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3300";
const widths = (process.env.HT_WIDTHS ?? "1440,390").split(",").map(Number);
const PAGES = ["/", "/agents", "/cves", "/notifications", "/settings", "/users"];

/** Läuft im Browser. */
function scan() {
  const SEL = 'a[href], button, [role="button"], [role="tab"], summary, input:not([type="hidden"]), select, textarea, [role="switch"], [role="checkbox"]';
  const vis = (e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none" && !e.closest("[inert],[aria-hidden='true'],.sr-only") && !(e.closest("thead") && getComputedStyle(e.closest("thead")).position === "absolute") && r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth; };
  const els = [...document.querySelectorAll(SEL)].filter(vis).filter((e) => !(e.tagName === "A" && e.closest("p, li, td, span, div")?.matches("p") && e.parentElement?.tagName === "P"));
  const name = (e) => (e.getAttribute("aria-label") || e.innerText || e.getAttribute("title") || e.getAttribute("name") || e.tagName).replace(/\s+/g, " ").trim().slice(0, 40);
  const out = [];
  for (const e of els) {
    const r = e.getBoundingClientRect();
    // (1) Eigene Fläche: mittlere Punkte und nahe den Ecken müssen auf das Element (oder Kind) treffen.
    const pts = [[0.5, 0.5], [0.15, 0.5], [0.85, 0.5], [0.5, 0.15], [0.5, 0.85]];
    let stolenBy = null;
    for (const [fx, fy] of pts) {
      const x = r.left + r.width * fx, y = r.top + r.height * fy;
      if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) continue;
      const h = document.elementFromPoint(x, y);
      // Bewusste Überlagerung: das Aufklappsymbol der Seitenleiste (data-hit-overlay) liegt über dem Auffüllrand seines Links.
      if (h && !h.closest("[data-hit-overlay]") && !(h === e || e.contains(h) || h.contains(e) || h.closest("label") === e.closest("label") && e.closest("label"))) { stolenBy = (h.closest(SEL) ?? h).tagName + ":" + name(h.closest(SEL) ?? h); break; }
    }
    // (2) Trefferfläche: Raster ±30 px, Schritt 1 px; Ausdehnung der Treffer pro Achse.
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    const own = (h) => h && (h === e || e.contains(h) || (e.closest("label") && h.closest("label") === e.closest("label")));
    for (let y = Math.floor(r.top - 30); y <= r.bottom + 30; y += 1) {
      for (let x = Math.floor(r.left - 30); x <= r.right + 30; x += 1) {
        if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) continue;
        if (own(document.elementFromPoint(x, y))) { minX = Math.min(minX, x); maxX = Math.max(maxX, x); minY = Math.min(minY, y); maxY = Math.max(maxY, y); }
      }
    }
    const hw = Number.isFinite(minX) ? Math.max(r.width, maxX - minX + 1) : r.width;
    const hh = Number.isFinite(minY) ? Math.max(r.height, maxY - minY + 1) : r.height;
    out.push({ name: name(e), tag: e.tagName.toLowerCase() + (e.getAttribute("role") ? `[${e.getAttribute("role")}]` : ""), vw: Math.round(r.width), vh: Math.round(r.height), hw: Math.round(hw), hh: Math.round(hh), stolenBy, left: Math.round(r.left), top: Math.round(r.top) });
  }
  // (3) Geometrie: erweiterte Flächen (sichtbar + --hit-x/--hit-y, nur Knöpfe) benachbarter Elemente überlappen nie.
  const ext = els.map((e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); const on = e.tagName === "BUTTON" && !e.disabled; const hx = on ? parseFloat(cs.getPropertyValue("--hit-x")) || 0 : 0; const hy = on ? parseFloat(cs.getPropertyValue("--hit-y")) || 0 : 0; return { e, l: r.left - hx, r: r.right + hx, t: r.top - hy, b: r.bottom + hy }; });
  const overlaps = [];
  for (let i = 0; i < ext.length; i++) for (let j = i + 1; j < ext.length; j++) {
    const a = ext[i], b = ext[j];
    if (a.e.contains(b.e) || b.e.contains(a.e)) continue;
    if (a.e.hasAttribute("data-hit-overlay") || b.e.hasAttribute("data-hit-overlay")) continue;
    if (Math.min(a.r, b.r) - Math.max(a.l, b.l) > 0.5 && Math.min(a.b, b.b) - Math.max(a.t, b.t) > 0.5 && (a.e.tagName === "BUTTON" || b.e.tagName === "BUTTON")) overlaps.push(name(a.e) + " ↔ " + name(b.e));
  }
  return { items: out, overlaps, overflow: document.documentElement.scrollWidth - innerWidth };
}

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
let bad = 0, under = 0, total = 0;
const rows = [];
try {
  for (const w of widths) {
    const ctx = await browser.newContext({ viewport: { width: w, height: 900 } });
    const page = await ctx.newPage();
    await page.goto(`${base}/login`);
    await page.getByLabel("Benutzername").fill("admin");
    await page.getByLabel("Passwort").fill(pw);
    await page.getByRole("button", { name: "Anmelden" }).click();
    await page.waitForURL((u) => !u.pathname.startsWith("/login"));
    for (const p of PAGES) {
      await page.goto(`${base}${p}`);
      if (process.env.HT_NOEXT) await page.addStyleTag({ content: "button::before{display:none!important}" });
      await page.waitForTimeout(1200);
      const r = await page.evaluate(scan);
      for (const it of r.items) {
        total++;
        if (it.stolenBy) { bad++; console.log(`FAIL ${w}px ${p}: „${it.name}“ (${it.tag}) wird überdeckt von ${it.stolenBy}`); }
        if (it.hw < 44 || it.hh < 44) under++;
        rows.push([`${p} (${w}px)`, `${it.tag} „${it.name}“`, `${it.vw}×${it.vh}`, `${it.hw}×${it.hh}`]);
      }
      for (const o of r.overlaps) { bad++; console.log(`FAIL ${w}px ${p}: erweiterte Flächen überlappen: ${o}`); }
      if (r.overflow > 0) { bad++; console.log(`FAIL ${w}px ${p}: horizontaler Überlauf ${r.overflow}px`); }
    }
    await ctx.close();
  }
} finally {
  await browser.close();
}
console.log(`${total} bedienbare Elemente, ${under} mit Trefferfläche unter 44 px (Breite oder Höhe), ${bad} Verstöße`);
if (process.env.HT_WRITE) {
  const md = ["# Trefferflächen", "", "Erzeugt von `scripts/hit-targets.mjs` (Raster per `elementFromPoint`). Regel: web/DESIGN.md, Abschnitt „Trefferflächen“.", "", `${total} Elemente, ${under} mit Trefferfläche unter 44 px in einer Richtung.`, "", "| Seite | Element | sichtbar | Trefferfläche |", "|---|---|---|---|", ...rows.map((r) => `| ${r.join(" | ")} |`), ""].join("\n");
  writeFileSync(process.env.HT_WRITE, md);
}
process.exitCode = bad ? 1 : 0;
