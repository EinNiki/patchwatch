// E2E: Host-Details (rechte Spalte ab 1280 px bzw. aufklappbar darunter): kein horizontaler Überlauf, lange Kernelversionen
// brechen nur an Bindestrichen/Punkten, Beschriftung über dem Wert in der schmalen Spalte, axe.
// Der Host wird per page.route mit langen Kernel-Angaben nachgestellt; der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=<axe.min.js> [PW_SHOTS=<Ordner>] node scripts/e2e-hostdetails.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };

const LONG = {
  running_kernel: "7.0.0-42-generic", newest_kernel: "7.0.0-42-generic", newest_kernel_version: "7.0.0-42.42",
  kernel_package: "linux-image-7.0.0-42-generic", kernel_package_version: "7.0.0-42.42", agent_version: "0.1.1",
  reboot_needed: true, reboot_needed_kernel: true, reboot_required_file: true,
};
const EXTRA_LONG = { ...LONG, running_kernel: "6.12.57+deb13-cloud-amd64-unsigned-extra-long", kernel_package: "linux-image-6.12.57+deb13-cloud-amd64-unsigned-extra-long", kernel_package_version: "6.12.57-1~bpo13+1+really.long.version-1.2.3" };

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light" });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const hosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const host = hosts[0];
  let patch = LONG;
  await page.route(new RegExp(`/api/v1/hosts/${host.id}$`), async (r) => {
    const real = await (await r.fetch()).json();
    return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...real, ...patch }) });
  });

  // Umbrüche prüfen: nach jedem Zeichen, hinter dem die Zeile wechselt, muss "-", ".", "/" oder ein Leerzeichen stehen.
  const badBreaks = (scopeSel) => page.evaluate((sel) => {
    const bad = [];
    for (const dd of document.querySelectorAll(`${sel} dd`)) {
      const w = document.createTreeWalker(dd, NodeFilter.SHOW_TEXT);
      for (let n = w.nextNode(); n; n = w.nextNode()) {
        const t = n.textContent; const rg = document.createRange();
        let prevTop = null;
        for (let i = 0; i < t.length; i++) {
          if (/\s/.test(t[i])) { prevTop = null; continue; }
          rg.setStart(n, i); rg.setEnd(n, i + 1);
          const top = Math.round(rg.getBoundingClientRect().top);
          if (prevTop !== null && top > prevTop + 2 && !/[-./]/.test(t[i - 1])) bad.push(`${t.slice(Math.max(0, i - 4), i)}|${t.slice(i, i + 4)}`);
          prevTop = top;
        }
      }
    }
    return bad;
  }, scopeSel);

  async function check(label, w, scheme, p, scopeSel) {
    patch = p;
    await page.setViewportSize({ width: w, height: 900 });
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(`${base}/hosts/${host.id}`);
    await page.locator(w < 1280 ? "summary:text(\"Host-Details\")" : "aside[aria-labelledby=facts]").first().waitFor({ timeout: 15000 });
    if (w < 1280) await page.locator("details", { hasText: "Host-Details" }).first().locator("summary").click();
    const aside = page.locator(scopeSel);
    await aside.waitFor();
    await page.waitForTimeout(200);
    const m = await aside.evaluate((el) => {
      const box = el.getBoundingClientRect();
      const out = [];
      for (const dd of el.querySelectorAll("dd")) { const r = dd.getBoundingClientRect(); if (r.right > box.right + 0.5 || dd.scrollWidth > dd.clientWidth + 1) out.push(dd.textContent.slice(0, 40)); }
      const dl = el.querySelector("dl"); const dt = dl.querySelector("dt"); const dd = dl.querySelector("dd");
      return { sw: el.scrollWidth, cw: el.clientWidth, w: Math.round(box.width), over: out, stacked: dd.getBoundingClientRect().top > dt.getBoundingClientRect().bottom - 2, docW: document.documentElement.scrollWidth - document.documentElement.clientWidth };
    });
    ok(m.sw <= m.cw + 1 && m.over.length === 0, `${label}: kein Überlauf der Spalte (Breite ${m.w}, Abweichler: ${m.over.join(" | ") || "keine"})`);
    ok(m.docW <= 0, `${label}: kein horizontaler Überlauf der Seite`);
    ok(m.stacked === (m.w < 384), `${label}: Beschriftung ${m.stacked ? "über" : "neben"} dem Wert bei Spaltenbreite ${m.w}`);
    const bad = await badBreaks(scopeSel);
    ok(bad.length === 0, `${label}: Umbrüche nur an - . / (${bad.join(", ") || "ok"})`);
    await page.evaluate(axeSrc);
    const v = await page.evaluate((s) => axe.run(document.querySelector(s), { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)), scopeSel);
    ok(v.length === 0, `${label}: axe ${v.join(", ") || "keine Verstöße"}`);
    if (shots) await aside.screenshot({ path: `${shots}/details-${label.replace(/[^a-z0-9]+/gi, "-")}.png` });
  }

  for (const [w, scheme] of [[1280, "light"], [1440, "dark"], [1440, "light"], [1920, "light"], [1920, "dark"]]) {
    await check(`${w}/${scheme}/lang`, w, scheme, LONG, "aside[aria-labelledby=facts]");
    await check(`${w}/${scheme}/sehr lang`, w, scheme, EXTRA_LONG, "aside[aria-labelledby=facts]");
  }
  // Unter 1280 px: Abschnitt im aufklappbaren Bereich (volle Breite).
  for (const [w, scheme] of [[390, "dark"], [768, "light"]]) await check(`${w}/${scheme}/Abschnitt`, w, scheme, EXTRA_LONG, "details:has(dl)");
} finally {
  await browser.close();
}
