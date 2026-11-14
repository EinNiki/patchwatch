// E2E: Fußbereich der Seitenleiste folgt dem Raster der Navigation: gleiche Zeilenhöhe, Symbolspalte 20 px, Text am selben x,
// gleiche Schrift, Profilbild 20 px, eingeklappt mittig in derselben Spalte, lange Namen, Tooltips, Tastaturfokus, axe.
// /auth/me wird per page.route für lange Namen und das eigene Bild nachgestellt; der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-sidebar-footer.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const near = (a, b, t = 1) => Math.abs(a - b) <= t;
const SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="40"><rect width="80" height="40" fill="#c33"/></svg>';

// Messung im Seitenkontext: vier Fußzeilen plus erster Navigationseintrag.
const MEASURE = (root) => {
  const r = document.querySelector(root);
  const rect = (e) => e.getBoundingClientRect();
  const row = (el) => {
    const label = [...el.querySelectorAll("span, p")].find((n) => n.className.includes("truncate"));
    const icon = el.querySelector("span.grid");
    const cs = getComputedStyle(label ?? el);
    const rr = rect(el), ir = rect(icon), lr = label ? rect(label) : null;
    return { h: rr.height, textX: lr ? lr.left : null, iconW: ir.width, iconCx: ir.left + ir.width / 2, fs: cs.fontSize, fw: cs.fontWeight, lh: cs.lineHeight, color: cs.color, label: (label?.textContent ?? "").trim(), truncated: label ? label.scrollWidth > label.clientWidth + 1 : false, rowRight: rr.right };
  };
  const feed = r.querySelector('a[href="/cves#feeds"]');
  const live = [...r.querySelectorAll('p[role="status"]')][0];
  const logout = [...r.querySelectorAll("button")].find((b) => b.textContent.includes("Abmelden"));
  const userRow = [...r.querySelectorAll("div")].find((d) => d.title && d.querySelector("p") && d.querySelector("span.grid") && !d.querySelector("button"));
  const nav = r.querySelector('a[href="/cves"]');
  const out = { feed: feed && row(feed), live: live && row(live), user: userRow && row(userRow), logout: logout && row(logout), nav: nav && row(nav) };
  const av = userRow?.querySelector("img, span[aria-hidden]");
  if (av) { const a = rect(av); const cs = getComputedStyle(av); out.avatar = { w: a.width, h: a.height, tag: av.tagName, fit: cs.objectFit, fs: cs.fontSize, fw: cs.fontWeight, bg: cs.backgroundColor, color: cs.color, title: userRow.title }; }
  out.asideOverflow = r.scrollWidth - r.clientWidth;
  out.over = [...r.querySelectorAll('*')].filter((e) => e.getBoundingClientRect().right > r.getBoundingClientRect().right + 0.5 && e.getBoundingClientRect().width > 0 && !e.closest('.pointer-events-none')).slice(0, 4).map((e) => `${e.tagName}.${String(e.className).slice(0, 40)}`);
  out.rootW = rect(r).width;
  out.sepAfterLive = !!r.querySelector('[role="separator"]');
  return out;
};
const lum = (c) => { const [r, g, b] = c.match(/[\d.]+/g).slice(0, 3).map((v) => { v = Number(v) / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  let me = null; // null = echte Antwort
  await page.route("**/api/v1/auth/me", async (r) => {
    if (!me) return r.continue();
    const real = await (await r.fetch()).json();
    return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...real, ...me }) });
  });
  await page.route("**/api/v1/auth/avatar**", (r) => r.fulfill({ status: 200, contentType: "image/svg+xml", body: SVG }));

  async function open(w, scheme, collapsedRail) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.setViewportSize({ width: w, height: 900 });
    await page.addInitScript((c) => { try { localStorage.setItem("pw-nav:collapsed", c ? "1" : "0"); } catch {} }, collapsedRail);
    await page.goto(`${base}/`);
    await page.waitForSelector("#main", { state: "attached", timeout: 8000 }).catch(async (e) => { console.log(page.url(), (await page.locator("body").innerText()).slice(0, 300)); throw e; });
    if (w < 768) { await page.getByRole("button", { name: "Menü", exact: true }).click(); await page.waitForTimeout(450); return "#mobile-menu"; }
    await page.waitForTimeout(450);
    return "#sidebar";
  }

  async function check(label, w, scheme, { collapsed = false, name = null, avatar = false } = {}) {
    me = name || avatar ? { ...(name ? { username: name } : {}), avatar: avatar ? 123 : null } : null;
    const root = await open(w, scheme, collapsed);
    const m = await page.evaluate(MEASURE, root);
    const rows = ["feed", "live", "user", "logout"];
    ok(rows.every((k) => m[k]), `${label}: vier Fußzeilen und Navigation vorhanden`);
    const all = rows.map((k) => m[k]);
    const hMin = w < 768 ? 44 : 36;
    ok(all.every((r) => near(r.h, all[0].h) && r.h >= hMin - 0.5), `${label}: Zeilenhöhen gleich (${all.map((r) => r.h).join("/")}), mindestens ${hMin} px`);
    ok(near(m.nav.h, all[0].h), `${label}: Höhe wie Navigationseintrag (${m.nav.h})`);
    ok(all.every((r) => near(r.iconW, 20, 0.5)) && near(m.nav.iconW, 20, 0.5), `${label}: Symbolspalte 20 px (${all.map((r) => r.iconW)})`);
    ok(all.every((r) => near(r.iconCx, m.nav.iconCx)), `${label}: Symbole mittig in derselben Spalte (${all.map((r) => r.iconCx.toFixed(1))} / Navigation ${m.nav.iconCx.toFixed(1)})`);
    ok(all.every((r) => r.fs === "13px" && r.fw === "500" && r.lh === all[0].lh && r.color === all[0].color), `${label}: Schrift 13 px, Gewicht 500, gleiche Höhe und Farbe (${all.map((r) => `${r.fs}/${r.fw}`)})`);
    ok(Number(m.logout.fw) <= Number(m.live.fw) && m.logout.fs === m.live.fs, `${label}: "Abmelden" nicht fetter und nicht größer als "Live"`);
    ok(m.avatar && near(m.avatar.w, 20, 0.5) && near(m.avatar.h, 20, 0.5), `${label}: Profilbild 20 x 20 px (${m.avatar?.w}x${m.avatar?.h})`);
    ok(m.sepAfterLive, `${label}: Trennlinie zwischen Zustand und Benutzer`);
    // Tooltips der Rail ragen absichtlich über die Leiste hinaus und zählen nicht als Überlauf.
    ok(m.over.length === 0, `${label}: kein Inhalt ragt aus der Leiste (${m.over.join(' | ') || 'ok'})`);
    if (!collapsed) {
      ok(all.every((r) => near(r.textX, all[0].textX)) && near(m.nav.textX, all[0].textX), `${label}: Text beginnt überall am selben x (${all.map((r) => r.textX.toFixed(1))} / Navigation ${m.nav.textX.toFixed(1)})`);
    } else {
      ok(all.every((r) => near(r.iconCx, m.rootW / 2, 1.5)), `${label}: eingeklappt mittig in der Rail (Mitte ${(m.rootW / 2).toFixed(1)}, Symbole ${all.map((r) => r.iconCx.toFixed(1))})`);
    }
    if (m.avatar.tag === "SPAN") {
      ok(m.avatar.fs === "10px" && m.avatar.fw === "600", `${label}: Initialen 10 px, Gewicht 600 (${m.avatar.fs}/${m.avatar.fw})`);
      const c = contrast(m.avatar.bg, m.avatar.color);
      ok(c >= 4.5, `${label}: Kontrast der Initialen ${c.toFixed(2)}:1`);
    } else ok(m.avatar.fit === "cover", `${label}: eigenes Bild füllt den Kreis (object-fit ${m.avatar.fit})`);
    if (name) {
      ok(m.user.truncated && m.user.label.endsWith(name), `${label}: langer Name wird gekürzt`);
      ok(m.avatar.title === name, `${label}: Tooltip zeigt den vollen Namen`);
      ok(near(m.user.rowRight, m.live.rowRight), `${label}: Zeile bleibt in der Leiste`);
    }
    // Tooltips (eingeklappt) bei Hover und Tastaturfokus; Fokusring sichtbar.
    if (collapsed) {
      const logout = page.locator(`${root} button`, { hasText: "Abmelden" });
      await logout.hover();
      await page.waitForTimeout(250);
      const tipHover = await logout.evaluate((b) => Number(getComputedStyle(b.parentElement.querySelector('span[aria-hidden="true"].pointer-events-none')).opacity));
      ok(tipHover > 0.9, `${label}: Tooltip "Abmelden" bei Hover (${tipHover})`);
      await page.mouse.move(700, 500);
    }
    if (w >= 768) {
      await page.keyboard.press("Tab");
      await page.locator(`${root} button`, { hasText: "Abmelden" }).focus();
      await page.keyboard.press("Shift+Tab"); await page.keyboard.press("Tab");
      await page.waitForTimeout(300);
      const f = await page.locator(`${root} button`, { hasText: "Abmelden" }).evaluate((b) => { const cs = getComputedStyle(b); return { outline: cs.outlineStyle, w: parseFloat(cs.outlineWidth), focused: document.activeElement === b, tip: Number(getComputedStyle(b.parentElement.querySelector("span.pointer-events-none")).opacity) }; });
      ok(f.focused && f.outline !== "none" && f.w >= 1, `${label}: Fokusring beim Tastaturfokus (${f.outline} ${f.w}px)`);
      if (collapsed) ok(f.tip > 0.9, `${label}: Tooltip beim Tastaturfokus (${f.tip})`);
    }
    await page.evaluate(axeSrc);
    const v = await page.evaluate((s) => axe.run(document.querySelector(s), { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)), root);
    ok(v.length === 0, `${label}: axe ${v.join(", ") || "keine Verstöße"}`);
    if (shots) await page.locator(root).screenshot({ path: `${shots}/footer-${label.replace(/[^a-z0-9]+/gi, "-")}.png` });
  }

  for (const scheme of ["light", "dark"]) {
    await check(`1440 ${scheme}`, 1440, scheme);
    await check(`1920 ${scheme}`, 1920, scheme);
    await check(`1440 ${scheme} eingeklappt`, 1440, scheme, { collapsed: true });
    await check(`768 ${scheme} Rail`, 768, scheme);
    await check(`390 ${scheme} Menü`, 390, scheme);
  }
  await check("1440 lange Namen", 1440, "light", { name: "sehr.langer.benutzername.der.nicht.in.die.leiste.passt" });
  await check("390 lange Namen", 390, "dark", { name: "sehr.langer.benutzername.der.nicht.in.die.leiste.passt" });
  await check("1440 eigenes Bild", 1440, "light", { avatar: true });
  await check("768 eigenes Bild", 768, "dark", { avatar: true });
} finally {
  await browser.close();
}
