// E2E: Benutzerverwaltung. Menü nur für Administratoren, 403-Seite, Anlegen mit Rechtevorschau, Einmalpasswort nur einmal,
// Bearbeiten/Sperren/Löschen-Dialoge mit X, Tastaturbedienung, Schreibaktionen für "Nur Lesen" ausgeblendet,
// axe (serious/critical) und kein Überlauf bei 390/768/1024/1440 px, hell und dunkel.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_BASE=http://127.0.0.1:3300] [PW_SHOTS=<Ordner>] node scripts/e2e-users.mjs
// Läuft gegen den Wegwerf-Stack (scripts/dev-stack.sh); legt Benutzer mit Präfix "e2e-" an. Kennwörter nur als Testwerte.
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3300";
const shots = process.env.PW_SHOTS;
if (shots) mkdirSync(shots, { recursive: true });
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const tag = Date.now().toString(36).slice(-5);
// Eigene Auswahl (Listbox): öffnen, Eintrag anklicken.
async function pickRole(dlg, label) {
  await dlg.page().waitForTimeout(350); // Einblend-Animation des Dialogs abwarten
  await dlg.getByRole("combobox", { name: /^Vorlage/ }).click();
  await dlg.page().getByRole("option", { name: label }).click();
}
const NEW_PW = "TESTWERT-e2e-passwort-12345";

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });

async function login(ctx, user, password) {
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill(user);
  await page.getByLabel("Passwort").fill(password);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  return page;
}

async function axe(page, label) {
  await page.evaluate(axeSrc);
  const r = await page.evaluate(async () => (await window.axe.run(document, { resultTypes: ["violations"] })).violations.filter((v) => ["serious", "critical"].includes(v.impact)).map((v) => `${v.id}: ${v.nodes[0]?.target}`));
  ok(r.length === 0, `axe ${label}${r.length ? ` -> ${r.join("; ")}` : ""}`);
}

async function noOverflow(page, label) {
  const o = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  ok(o <= 0, `kein Seitwärtsscrollen ${label} (${o})`);
}

async function createUser(page, name, roleLabel) {
  await page.getByRole("button", { name: "Benutzer anlegen" }).first().click();
  const dlg = page.getByRole("dialog");
  await dlg.waitFor();
  await page.waitForTimeout(350); // Einblend-Animation abwarten: mitten darin ist das Fenster noch verschoben
  ok(!(await dlg.getByText(/wird mit .* angelegt/).count()), "Zusammenfassung erscheint nicht ohne Namen");
  await dlg.getByLabel("Name", { exact: true }).fill(name);
  await pickRole(dlg, roleLabel);
  const summary = new RegExp(`Benutzer ${name} wird mit der Vorlage ${roleLabel} \\(\\d+ Rechte\\) angelegt`);
  ok(await dlg.getByText(summary).isVisible(), `Zusammenfassung "${summary}"`);
  return dlg;
}

try {
  const adminCtx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await login(adminCtx, "admin", pw);
  await page.getByRole("navigation", { name: "Hauptnavigation" }).getByRole("link", { name: "Benutzer" }).waitFor({ timeout: 10000 }).catch(() => {});
  ok(await page.getByRole("navigation", { name: "Hauptnavigation" }).getByRole("link", { name: "Benutzer" }).isVisible(), "Menüpunkt Benutzer für Administrator");

  await page.goto(`${base}/users`);
  await page.getByRole("tab", { name: "Benutzer" }).waitFor();
  ok((await page.getByRole("tab").count()) === 2, "zwei Tabs Benutzer | Aktivität (OIDC liegt unter Einstellungen)");

  // --- Betreiber anlegen: Vorschau, Zusammenfassung, Einmalpasswort -----------------------------------------------
  const opName = `e2e-op-${tag}`;
  let dlg = await createUser(page, opName, "Betreiber");
  ok(!(await dlg.getByText("Kann Geheimnisse sehen").count()), "keine Zeile 'Kann Geheimnisse sehen'");
  ok(!(await dlg.getByText(/darf nicht/).count()), "kein Text 'darf nicht' (Schalter)");
  ok(!(await dlg.getByRole("switch", { name: /^Benutzer verwalten/ }).isChecked()), "Betreiber: Schalter 'Benutzer verwalten' aus");
  ok(await dlg.getByRole("switch", { name: /^Hosts ansehen/ }).isChecked(), "Betreiber: Schalter 'Hosts ansehen' an");
  await axe(page, "Dialog Benutzer anlegen");
  await dlg.getByRole("button", { name: "Benutzer anlegen" }).click();
  const otp = page.getByRole("dialog", { name: /Einmalpasswort/ });
  await otp.waitFor();
  const opPw = (await otp.locator("code, .mono, pre").first().innerText()).trim();
  ok(opPw.length >= 20, `Einmalpasswort hat mindestens 20 Zeichen (${opPw.length})`);
  ok(!(await otp.getByRole("button", { name: "Schließen" }).count()), "Einmalpasswort-Dialog ohne X (Wert nur einmal sichtbar)");
  await otp.getByRole("button", { name: /Fertig/ }).click();
  await page.waitForTimeout(300);
  ok(!(await page.content()).includes(opPw), "Einmalpasswort steht nach dem Schließen nirgends mehr im Dokument");

  // --- Nur-Lesen-Benutzer ----------------------------------------------------------------------------------------
  const viName = `e2e-vi-${tag}`;
  dlg = await createUser(page, viName, "Nur Lesen");
  await dlg.getByRole("button", { name: "Benutzer anlegen" }).click();
  const otp2 = page.getByRole("dialog", { name: /Einmalpasswort/ });
  await otp2.waitFor();
  const viPw = (await otp2.locator("code, .mono, pre").first().innerText()).trim();
  await otp2.getByRole("button", { name: /Fertig/ }).click();
  ok(await page.getByRole("row").filter({ hasText: viName }).isVisible(), "neuer Benutzer steht in der Tabelle");

  // --- Bearbeiten: X schließt, Rollenwechsel verlangt Namensbestätigung ------------------------------------------
  await page.getByRole("button", { name: `${opName} bearbeiten` }).click();
  dlg = page.getByRole("dialog", { name: /bearbeiten/ });
  await dlg.getByRole("button", { name: "Schließen" }).click();
  await page.waitForTimeout(300);
  ok(!(await dlg.isVisible()), "X-Knopf schließt den Bearbeiten-Dialog");
  await page.getByRole("button", { name: `${opName} bearbeiten` }).click();
  dlg = page.getByRole("dialog", { name: /bearbeiten/ });
  await pickRole(dlg, "Nur Lesen");
  await dlg.getByRole("button", { name: "Speichern" }).click();
  ok(await dlg.getByText(/Namen des Benutzers eingeben/).isVisible(), "Rollenwechsel ohne Namensbestätigung wird gestoppt");
  await dlg.getByRole("button", { name: "Abbrechen" }).click();

  // --- Sperren / Entsperren -------------------------------------------------------------------------------------
  // Die Aktionen stehen jetzt direkt in der Zeile (ActionCell); kein Zeilenmenü mehr.
  const rowMenu = () => ({ click: async () => {} });
  await rowMenu(viName).click();
  await page.getByRole("button", { name: `${viName} sperren` }).click();
  const lock = page.getByRole("dialog", { name: /sperren\?/ });
  await lock.getByRole("button", { name: "Schließen" }).click();
  await page.waitForTimeout(300);
  ok(!(await lock.isVisible()), "X-Knopf schließt die Sperr-Bestätigung");
  await rowMenu(viName).click();
  await page.getByRole("button", { name: `${viName} sperren` }).click();
  await page.getByRole("dialog", { name: /sperren\?/ }).getByRole("button", { name: "Sperren" }).click();
  await page.getByRole("row").filter({ hasText: viName }).getByText("gesperrt").waitFor();
  ok(true, "Benutzer gesperrt (Chip mit Symbol und Text)");
  await rowMenu(viName).click();
  await page.getByRole("button", { name: `${viName} entsperren` }).click();
  await page.getByRole("row").filter({ hasText: viName }).getByText("aktiv").waitFor();
  ok(true, "Benutzer entsperrt");

  // --- Anmeldung der neuen Benutzer: Passwortwechsel erzwungen; Rechte in der Oberfläche -------------------------
  async function firstLogin(name, oneTime) {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const p = await ctx.newPage();
    await p.goto(`${base}/login`);
    await p.getByLabel("Benutzername").fill(name);
    await p.getByLabel("Passwort").fill(oneTime);
    await p.getByRole("button", { name: "Anmelden" }).click();
    await p.getByLabel("Aktuelles (Start-)Passwort").waitFor();
    await p.getByLabel("Aktuelles (Start-)Passwort").fill(oneTime);
    await p.getByLabel(/^Neues Passwort \(/).fill(NEW_PW);
    await p.getByLabel("Neues Passwort wiederholen").fill(NEW_PW);
    await p.getByRole("button", { name: /Passwort (ändern|speichern|setzen)/i }).click();
    await p.getByLabel("Aktuelles (Start-)Passwort").waitFor({ state: "detached", timeout: 15000 }).catch(async () => { console.log("Passwortwechsel:", (await p.locator("body").innerText()).replace(/\s+/g, " ").slice(0, 400)); });
    return p;
  }
  const opPage = await firstLogin(opName, opPw);
  await opPage.goto(`${base}/agents`);
  await opPage.getByRole("heading", { name: "Agents" }).waitFor({ timeout: 8000 }).catch(async () => { if (shots) await opPage.screenshot({ path: `${shots}/op-agents-fail.png` }); console.log(await opPage.locator("body").innerText()); });
  ok(!(await opPage.getByRole("navigation", { name: "Hauptnavigation" }).getByRole("link", { name: "Benutzer" }).count()), "Betreiber: kein Menüpunkt Benutzer");
  ok(await opPage.getByRole("button", { name: "Agent hinzufügen" }).isVisible(), "Betreiber darf Agents anlegen");
  await opPage.goto(`${base}/users`);
  await opPage.getByText("Kein Zugriff (403)").waitFor({ timeout: 8000 }).catch(() => {});
  ok(await opPage.getByText("Kein Zugriff (403)").isVisible(), "Betreiber sieht auf /users die 403-Seite");

  const viPage = await firstLogin(viName, viPw);
  await viPage.goto(`${base}/agents`);
  if (shots) await viPage.waitForTimeout(2500).then(() => viPage.screenshot({ path: `${shots}/viewer-agents.png` }));
  await viPage.getByRole("heading", { name: "Agents" }).waitFor();
  ok(!(await viPage.getByRole("button", { name: "Agent hinzufügen" }).count()), "Nur Lesen: kein Knopf 'Agent hinzufügen'");
  ok(!(await viPage.getByRole("button", { name: /Daten jetzt abrufen|Alle Agents abrufen/ }).count()), "Nur Lesen: keine Abrufknöpfe");
  await viPage.goto(`${base}/users`);
  await viPage.getByText("Kein Zugriff (403)").waitFor({ timeout: 8000 }).catch(() => {});
  ok(await viPage.getByText("Kein Zugriff (403)").isVisible(), "Nur Lesen sieht auf /users die 403-Seite");
  await viPage.context().close();
  await opPage.context().close();

  // --- Löschen mit Namensbestätigung ----------------------------------------------------------------------------
  await page.goto(`${base}/users`);
  await rowMenu(opName).click();
  await page.getByRole("button", { name: `Benutzer ${opName} löschen` }).click();
  const del = page.getByRole("dialog", { name: /löschen\?/ });
  await del.getByRole("button", { name: "Benutzer löschen" }).click();
  ok(await del.getByText("Der eingegebene Name stimmt nicht.").isVisible(), "Löschen ohne Namen wird abgelehnt");
  await del.getByRole("button", { name: "Schließen" }).click();
  await page.waitForTimeout(300);
  ok(!(await del.isVisible()), "X-Knopf schließt den Löschen-Dialog");
  await rowMenu(opName).click();
  await page.getByRole("button", { name: `Benutzer ${opName} löschen` }).click();
  await page.getByRole("dialog", { name: /löschen\?/ }).getByRole("textbox").fill(opName);
  await page.getByRole("dialog", { name: /löschen\?/ }).getByRole("button", { name: "Benutzer löschen" }).click();
  await page.getByRole("row").filter({ hasText: opName }).waitFor({ state: "detached" });
  ok(true, "Benutzer nach Namensbestätigung gelöscht");

  // --- Tastatur: Tabs mit Pfeiltasten, Dialog per Enter, Esc schließt --------------------------------------------
  await page.getByRole("tab", { name: "Benutzer" }).focus();
  await page.keyboard.press("ArrowRight");
  ok((await page.getByRole("tab", { name: "Aktivität" }).getAttribute("aria-selected")) === "true", "Pfeil rechts wechselt zum Tab Aktivität");
  await page.getByRole("tab", { name: "Benutzer" }).click();
  await page.getByRole("button", { name: "Benutzer anlegen" }).focus();
  await page.keyboard.press("Enter");
  await page.getByRole("dialog", { name: "Benutzer anlegen" }).waitFor();
  await page.keyboard.press("Escape");
  ok(!(await page.getByRole("dialog", { name: "Benutzer anlegen" }).isVisible()), "Esc schließt den Dialog");

  // --- Aktivität enthält die Ereignisse, aber keine Geheimnisse --------------------------------------------------
  await page.getByRole("tab", { name: "Aktivität" }).click();
  await page.getByText("Benutzer angelegt").first().waitFor();
  const body = await page.content();
  ok(!body.includes(opPw) && !body.includes(viPw) && !body.includes(NEW_PW), "Aktivitätsprotokoll zeigt keine Passwörter");
  ok(body.includes("Benutzer gelöscht") && body.includes("Benutzer gesperrt"), "Aktivität zeigt Anlegen, Sperren und Löschen");

  // --- Responsiv, hell und dunkel, axe ---------------------------------------------------------------------------
  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const w of [1440, 1024, 768, 390]) {
      await page.setViewportSize({ width: w, height: 900 });
      for (const tab of ["Benutzer", "Aktivität"]) {
        await page.goto(`${base}/users`);
        await page.getByRole("tab", { name: tab }).click();
        await page.waitForTimeout(400);
        await noOverflow(page, `${tab} ${w}px ${scheme}`);
        if (shots) await page.screenshot({ path: `${shots}/users-${tab === "Aktivität" ? "audit" : tab.toLowerCase()}-${w}-${scheme}.png`, fullPage: true });
        if (w === 1440 || w === 390) await axe(page, `${tab} ${w}px ${scheme}`);
      }
      // Dialog mit Rechtevorschau
      await page.goto(`${base}/users`);
      await page.getByRole("button", { name: "Benutzer anlegen" }).click();
      await page.getByRole("dialog").waitFor();
      await page.waitForTimeout(250);
      await noOverflow(page, `Dialog ${w}px ${scheme}`);
      if (shots) await page.screenshot({ path: `${shots}/users-dialog-${w}-${scheme}.png` });
      if (w === 390 || w === 1440) await axe(page, `Dialog ${w}px ${scheme}`);
      await page.keyboard.press("Escape");
    }
  }

  // --- Dialogzustände (B2): alle Vorlagen, Bearbeiten (fremd/eigen), Fehler, Abhängigkeiten, 5 Breiten, hell/dunkel ----
  async function dialogChecks(label) {
    const dlg = page.getByRole("dialog");
    const r = await dlg.evaluate((d) => {
      const vh = innerHeight;
      const body = d.querySelector("[data-dialog-body]");
      const scrollers = [d, ...d.querySelectorAll("*")].filter((e) => {
        const o = getComputedStyle(e).overflowY;
        return (o === "auto" || o === "scroll") && e.scrollHeight > e.clientHeight + 1;
      });
      if (body) body.scrollTop = body.scrollHeight;
      const rect = (e) => e?.getBoundingClientRect();
      const head = rect(d.querySelector("h2"));
      const foot = rect(d.querySelector("button[type=submit]"));
      // Nichts ragt aus dem Dialog (Rechteck jedes Elements; Pseudo-Elemente der Trefferflächen zählen nicht) und keine Auslassungspunkte aktiv.
      const dr = d.getBoundingClientRect();
      const out = [...d.querySelectorAll("*")].filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && (r.right > dr.right + 1 || r.left < dr.left - 1); });
      const ell = [...d.querySelectorAll("*")].filter((e) => getComputedStyle(e).textOverflow === "ellipsis" && e.scrollWidth > e.clientWidth + 1);
      const cut = out.length + ell.length;
      if (body) body.scrollTop = 0;
      return {
        scrollers: scrollers.map((e) => e.tagName + (e === d ? "(dialog)" : "." + (e.getAttribute("data-dialog-body") !== null ? "body" : e.className))),
        headIn: head && head.top >= 0 && head.bottom <= vh,
        footIn: foot && foot.top >= 0 && foot.bottom <= vh,
        cut,
        wide: d.scrollWidth - d.clientWidth,
        switches: d.querySelectorAll("[role=switch]").length,
        secrets: /Kann Geheimnisse sehen/.test(d.innerText),
        darf: /darf nicht/.test(d.innerText),
      };
    });
    ok(r.scrollers.length <= 1 && !r.scrollers.some((x) => x.includes("(dialog)")), `${label}: genau ein Scrollbereich (${r.scrollers.join(",") || "keiner nötig"})`);
    ok(r.headIn && r.footIn, `${label}: Kopf und Fußleiste sichtbar auch ganz unten`);
    ok(r.cut === 0 && r.wide <= 0, `${label}: nichts abgeschnitten, kein Seitwärtsscrollen`);
    ok(r.switches === 20, `${label}: 20 Schalter (${r.switches})`);
    ok(!r.secrets && !r.darf, `${label}: kein 'Kann Geheimnisse sehen', kein 'darf nicht'`);
  }
  const widths = [390, 768, 1280, 1440, 1920];
  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const w of widths) {
      await page.setViewportSize({ width: w, height: w === 390 ? 760 : 900 });
      await page.goto(`${base}/users`);
      await page.getByRole("tab", { name: "Benutzer" }).waitFor();
      const shot = async (n) => shots && (await page.screenshot({ path: `${shots}/dlg-${n}-${w}-${scheme}.png` }));
      // Anlegen: jede Vorlage, mit Namen
      await page.getByRole("button", { name: "Benutzer anlegen" }).first().click();
      let dlg = page.getByRole("dialog");
      await dlg.waitFor();
      await page.waitForTimeout(250);
      await dialogChecks(`Anlegen leer ${w}px ${scheme}`);
      await shot("create-empty");
      await dlg.getByLabel("Name", { exact: true }).fill("Beispiel");
      for (const t of ["Administrator", "Betreiber", "Nur Lesen", "Eigene"]) {
        await pickRole(dlg, t);
        await page.waitForTimeout(120);
        if (t === "Administrator") ok(await dlg.getByLabel("Dein Passwort (zur Bestätigung)").isVisible(), `Anlegen Administrator ${w}px: Passwortfeld erscheint`);
        await dialogChecks(`Anlegen ${t} ${w}px ${scheme}`);
        await shot(`create-${t.toLowerCase().replace(" ", "-")}`);
      }
      // Abhängigkeiten: Löschen schaltet Lesen/Schreiben mit ein, Lesen aus schaltet abhängige aus
      await pickRole(dlg, "Nur Lesen");
      await dlg.getByRole("switch", { name: /^Hosts löschen/ }).check();
      ok(await dlg.getByRole("switch", { name: /^Hosts anlegen und ändern/ }).isChecked() && (await dlg.getByRole("switch", { name: /^Hosts ansehen/ }).isChecked()), `Abhängigkeit ${w}px: Hosts löschen schaltet Schreiben und Lesen mit ein`);
      await dlg.getByRole("switch", { name: /^Hosts ansehen/ }).uncheck();
      ok(!(await dlg.getByRole("switch", { name: /^Hosts löschen/ }).isChecked()), `Abhängigkeit ${w}px: Lesen aus schaltet Löschen aus`);
      ok(await dlg.getByRole("combobox", { name: /^Vorlage/ }).innerText().then((t) => t.includes("Eigene")), `Vorlage zeigt Eigene nach Abweichung ${w}px`);
      // Fehlerzustand: ohne Namen speichern
      await dlg.getByLabel("Name", { exact: true }).fill("");
      await dlg.getByRole("button", { name: "Benutzer anlegen" }).click();
      ok(await dlg.getByText("Bitte einen Namen angeben.").isVisible(), `Fehlerzustand ${w}px: Name fehlt`);
      await dialogChecks(`Fehlerzustand ${w}px ${scheme}`);
      await shot("create-error");
      await page.keyboard.press("Escape");
      await page.waitForTimeout(250);
      // Bearbeiten: fremdes Konto (Nur-Lesen-Benutzer) und eigenes Konto
      await page.getByRole("button", { name: `${viName} bearbeiten` }).click();
      dlg = page.getByRole("dialog");
      await page.waitForTimeout(250);
      await dialogChecks(`Bearbeiten fremd ${w}px ${scheme}`);
      await shot("edit-other");
      await dlg.getByRole("switch", { name: /^Hosts anlegen und ändern/ }).check();
      ok(await dlg.getByLabel(/Zur Bestätigung den Namen/).isVisible(), `Bearbeiten ${w}px: Namensbestätigung nach Rechteänderung`);
      await dialogChecks(`Bearbeiten geändert ${w}px ${scheme}`);
      await shot("edit-changed");
      await page.keyboard.press("Escape");
      await page.waitForTimeout(250);
      await page.getByRole("row").filter({ hasText: "(du)" }).getByRole("button", { name: /bearbeiten/ }).click();
      dlg = page.getByRole("dialog");
      await page.waitForTimeout(250);
      ok(await dlg.getByRole("switch").first().isDisabled(), `Bearbeiten eigen ${w}px: Schalter gesperrt`);
      await dialogChecks(`Bearbeiten eigen ${w}px ${scheme}`);
      await shot("edit-self");
      if (w === 390 || w === 1440) await axe(page, `Dialog Bearbeiten eigen ${w}px ${scheme}`);
      await page.keyboard.press("Escape");
      await page.waitForTimeout(250);
    }
  }

  // --- Löschschutz in der Liste (B3) ------------------------------------------------------------------------------
  await page.emulateMedia({ colorScheme: "light" });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}/users`);
  const selfRow = page.getByRole("row").filter({ hasText: "(du)" });
  const selfDel = selfRow.getByRole("button", { name: /löschen/ });
  await selfDel.waitFor();
  ok((await selfDel.getAttribute("aria-disabled")) === "true", "Eigenes Konto: Löschen ist aria-disabled");
  ok(((await selfDel.getAttribute("title")) ?? "").length > 10, "Eigenes Konto: Tooltip nennt den Grund");
  ok(await selfRow.locator("[data-guard-reason]").isVisible(), "Eigenes Konto: Grund steht sichtbar in der Zeile");
  await selfDel.click({ force: true });
  await page.waitForTimeout(200);
  ok(!(await page.getByRole("dialog").isVisible()), "Eigenes Konto: Klick auf gesperrtes Löschen öffnet nichts");
  if (shots) await page.screenshot({ path: `${shots}/users-guard.png` });

  // --- OIDC unter Einstellungen (B4) ----------------------------------------------------------------------------
  await page.goto(`${base}/users#oidc`);
  await page.waitForURL(/\/settings#oidc/);
  ok(true, "/users#oidc leitet auf /settings#oidc um");
  await page.getByRole("heading", { name: "OIDC-Anmeldung" }).waitFor();
  ok(await page.getByRole("navigation", { name: "Bereiche der Einstellungen" }).getByRole("link", { name: "OIDC" }).isVisible(), "Unternavigation mit OIDC");
  ok(!(await page.getByRole("heading", { name: "Single Sign-On" }).count()), "alter doppelter OIDC-Abschnitt ist weg");
  // Der Routenansager von Next (next-route-announcer, role=alert) ist kein Fehlerbanner.
  const banners = await page.evaluate(() => [...document.querySelectorAll("[role=alert]")].filter((e) => !e.closest("next-route-announcer") && e.textContent.trim()).map((e) => e.textContent.trim().slice(0, 80)));
  ok(banners.length === 0, `OIDC-Formular: kein Fehlerbanner im Ausgangszustand${banners.length ? ` -> ${banners.join("; ")}` : ""}`);
  const testBtn = page.getByRole("button", { name: "Verbindung testen" });
  ok((await testBtn.getAttribute("aria-disabled")) === "true" && ((await testBtn.getAttribute("title")) ?? "").length > 10, "Verbindung testen gesperrt mit Grund (Tooltip)");
  ok(await page.getByText(/Speichere zuerst/).first().isVisible(), "Grund steht sichtbar neben dem Knopf");
  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const w of widths) {
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(`${base}/settings#oidc`);
      await page.getByRole("heading", { name: "OIDC-Anmeldung" }).waitFor();
      await page.waitForTimeout(600);
      await noOverflow(page, `Einstellungen OIDC ${w}px ${scheme}`);
      if (shots) await page.screenshot({ path: `${shots}/settings-oidc-${w}-${scheme}.png` });
      if (w === 390 || w === 1440) await axe(page, `Einstellungen OIDC ${w}px ${scheme}`);
    }
  }
} finally {
  await browser.close();
}
