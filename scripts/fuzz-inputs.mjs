// Robustheit der Eingaben: schickt an alle Routen mit Text-/Zahlparametern ungewöhnliche Werte (leer, 10.000 Zeichen, Unicode,
// Steuerzeichen, NUL, negative/riesige Zahlen, Nicht-Zahlen, falsche JSON-Typen). Erwartung je Antwort: nie 5xx, Antwortzeit
// unter 5 s, danach /readyz erreichbar. Nur fetch, keine Abhängigkeit. Exit 1 bei jedem Fehler.
//
//   scripts/dev-stack.sh restart-server        # davor (setzt das In-Memory-Login-Limit zurück)
//   PW_PWFILE=<Admin-Passwort-Datei> [PW_API=http://127.0.0.1:8091] [PW_USER=admin] node scripts/fuzz-inputs.mjs
//
// Schreibende Routen bekommen nur Werte, die abgelehnt werden sollen (ungültige Namen, falsche Typen, bestehende IDs werden
// ausgespart); es wird nichts Gültiges angelegt oder gelöscht. Wird ein solcher Aufruf trotzdem angenommen (2xx), meldet das
// Skript einen HINWEIS (kein Fehler). Für den Seed-Zustand danach: scripts/dev-stack.sh down && up.
// Nicht abgedeckt (braucht gültige Host-Tokens bzw. legt Daten an): authentifizierte Reports, Avatar-Upload mit gültigem Bild.
import { readFileSync } from "node:fs";

const API = process.env.PW_API ?? "http://127.0.0.1:8091";
const USER = process.env.PW_USER ?? "admin";
const PW = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const MAX_MS = 5000;

const T0 = Date.now();
let waited429 = 0, skipped429 = 0;
let n = 0, fails = 0, hints = 0, slowest = 0;
const byStatus = {};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const short = (s) => (s.length > 60 ? `${s.slice(0, 40)}…(${s.length} Zeichen)` : s);
const show = (s) => short(String(s).replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`));

let cookie = "", csrf = "";
// call: eine Anfrage; Rückgabe {status}. 429 wird nach Retry-After wiederholt (allgemeines Limit 600/min je IP).
async function call(label, method, path, { body, raw, ctype, auth = true, token, write = false } = {}) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const h = {};
    if (auth && cookie) h.cookie = cookie;
    if (auth && csrf && method !== "GET") h["x-csrf-token"] = csrf;
    if (token !== undefined) h.authorization = `Bearer ${token}`;
    let data;
    if (raw !== undefined) { data = raw; if (ctype) h["content-type"] = ctype; }
    else if (body !== undefined) { h["content-type"] = "application/json"; data = typeof body === "string" ? body : JSON.stringify(body); }
    const t0 = Date.now();
    let r, err, text = "";
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 15000);
    try { r = await fetch(API + path, { method, headers: h, body: data, redirect: "manual", signal: ac.signal }); text = await r.text(); }
    catch (e) { err = e; }
    clearTimeout(timer);
    const ms = Date.now() - t0;
    if (r?.status === 429 && attempt < 2 && Number(r.headers.get("retry-after")) <= 60) { waited429++; await sleep(Math.min(65000, (Number(r.headers.get("retry-after")) || 5) * 1000 + 200)); continue; }
    n++;
    if (r?.status === 429) { skipped429++; if (skipped429 <= 5) console.log(`INFO ${label}: ${method} ${show(path)} -> 429 (Limit, übersprungen)`); }
    if (n % 500 === 0) console.log(`...  ${n} Anfragen, ${Math.round((Date.now() - T0) / 1000)} s, 429 gewartet: ${waited429}`);
    slowest = Math.max(slowest, ms);
    if (err) { fails++; console.log(`FAIL ${label}: ${method} ${show(path)} Netzfehler ${err.cause?.code ?? err.message}`); return { status: 0 }; }
    byStatus[Math.floor(r.status / 100)] = (byStatus[Math.floor(r.status / 100)] ?? 0) + 1;
    if (r.status >= 500) { fails++; console.log(`FAIL ${label}: ${method} ${show(path)} -> ${r.status}${body !== undefined ? ` Body ${show(JSON.stringify(body)).slice(0, 120)}` : ""}`); }
    else if (ms > MAX_MS) { fails++; console.log(`FAIL ${label}: ${method} ${show(path)} dauerte ${ms} ms`); }
    else if (write && method !== "DELETE" && r.status < 300) { hints++; console.log(`HINWEIS ${label}: ${method} ${show(path)} -> ${r.status} (erwartet: abgelehnt)`); }
    return { status: r.status, text };
  }
}
const j = async (method, path, opts) => { const r = await fetch(API + path, { method, headers: { cookie, "x-csrf-token": csrf, ...(opts?.h ?? {}) } }); return r.json(); };

// ---- Werte -----------------------------------------------------------------------------------------------------------
// Text: bereits als Roh-String; Schlüssel "enc" = so in die URL schreiben (z. B. %00 bereits kodiert).
const TEXT = [
  "", " ", "a".repeat(10000), "café", "日本語", "😀🎉", "e\u0301\u0301\u0301\u0301", "\u202Eevil\u202C", "\u200b\ufeff",
  "\x01\x02\x07\x1b\x1f\x7f", "a\r\nb", "a\tb", "a\u0000b", "'; DROP TABLE hosts;--", "%", "%zz", "a%00b", "../../etc/passwd",
  "\\", "\"", "<script>1</script>", "{{7*7}}", "%_", "a,b,,c", "CVE-2024-1086", "CVE-9999-0", "CVE-2024-" + "9".repeat(50),
];
const NUMS = ["-1", "0", "1", "2", "100", "1000000", "2147483647", "2147483648", "4294967296", "9223372036854775807", "9223372036854775808",
  "-9223372036854775808", "-9223372036854775809", "1e308", "1e400", "-0", "1.5", "NaN", "Infinity", "abc", "0x10", "1e3", "+5", " 5", "５", "١٢"];
const ALL = [...TEXT, ...NUMS];
// URL-Kodierung: die meisten Werte per encodeURIComponent; "a%00b" und "%zz" bleiben roh, dazu das kodierte NUL.
const enc = (v) => (v === "a%00b" || v === "%zz" || v === "%" ? v : encodeURIComponent(v));
const RAW_EXTRA = ["%00", "a%00", "%00a", "%c3%28", "%ff%fe", "%e2%80%ae", "%0d%0a"];
const queryValues = [...ALL.map(enc), ...RAW_EXTRA];
const SMALL = ["", "a".repeat(10000), "café", "日本語😀", "%E2%80%AE", "%01%1f%7f", "%00", "a%00b", "-1", "0", "2147483648", "9223372036854775807", "9223372036854775808", "1e308", "abc", "NaN"].map((v) => (v.startsWith("%") || v.includes("%00") ? v : enc(v)));
const pathValues = queryValues.filter((v) => v !== "");

// JSON-Typen für Felder, die Text/Zahl/Bool/Liste erwarten.
const JSON_ODD = [null, true, false, 0, -1, 1.5, 2 ** 31, 2 ** 63, 1e308, "", [], {}, [1, "a", null], { a: 1 }, "a\u0000b", "x".repeat(10000), "café", "日本語😀", "\u202Eabc", "\x01\x1f\x7f"];

// ---- Anmeldung -------------------------------------------------------------------------------------------------------
{
  const r = await fetch(API + "/api/v1/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: USER, password: PW }) });
  if (r.status !== 200) { console.log(`FAIL Anmeldung -> ${r.status} (davor scripts/dev-stack.sh restart-server)`); process.exit(1); }
  const sc = r.headers.getSetCookie();
  cookie = sc.map((c) => c.split(";")[0]).join("; ");
  csrf = (await r.json()).csrf_token;
}

// Bestehende IDs/Namen: schreibende Routen bekommen sie nie.
const hosts = await j("GET", "/api/v1/hosts");
const realHostIds = new Set((Array.isArray(hosts) ? hosts : hosts.items ?? []).map((h) => String(h.id)));
const hostId = [...realHostIds][0] ?? "1";
const feeds = await j("GET", "/api/v1/feeds");
const realFeeds = new Set((feeds.sources ?? feeds.items ?? (Array.isArray(feeds) ? feeds : [])).map((f) => f.source ?? f.id ?? f.name));
const NOEXIST = "999999999";

// ---- GET: Query-Parameter --------------------------------------------------------------------------------------------
const GET = [
  ["/api/v1/hosts", []],
  ["/api/v1/cves", ["q", "releases", "distro", "split", "debian", "ubuntu", "affects", "sort", "dir", "limit", "offset", "watchlist"]],
  ["/api/v1/cves/scope-count", ["q", "releases", "distro", "split", "debian", "ubuntu", "affects", "watchlist"]],
  [`/api/v1/hosts/${hostId}/history`, ["limit"]],
  [`/api/v1/hosts/${hostId}/cves`, ["group", "status", "q", "sort", "dir", "limit", "offset"]],
  [`/api/v1/hosts/${hostId}/cves/groups`, ["kind", "q", "level_min"]],
  [`/api/v1/hosts/${hostId}/updates`, ["limit", "offset", "q"]],
  ["/api/v1/watchlist", []],
  ["/api/v1/matrix", ["cves", "hosts"]],
  ["/api/v1/notifications", []],
  ["/api/v1/settings", []],
  ["/api/v1/settings/oidc", []],
  ["/api/v1/feeds", []],
  ["/api/v1/feeds/runs", ["active", "source", "limit"]],
  ["/api/v1/auth/me", []],
  ["/api/v1/auth/providers", []],
  ["/api/v1/auth/oidc/login", []],
  ["/api/v1/auth/oidc/callback", ["code", "state", "error"]],
];
for (const [path, params] of GET) {
  await call("GET", "GET", path);
  for (const p of params) {
    const full = path === "/api/v1/cves" || path.endsWith("/cves");
    const vals = p === "kind" ? [...SMALL, "reboot", "fixed"] : full ? queryValues : SMALL;
    for (const v of vals) await call(`Query ${p}`, "GET", `${path}?${p}=${v}`);
    // gleicher Parameter doppelt und leer ohne Wert
    await call(`Query ${p}`, "GET", `${path}?${p}`);
    await call(`Query ${p}`, "GET", `${path}?${p}=1&${p}=2`);
  }
  // alle Parameter gleichzeitig mit demselben Wert (Kombinationen)
  for (const v of ["%00", "-1", "9223372036854775807", "café", "a".repeat(2000)]) {
    if (params.length) await call("Query alle", "GET", `${path}?${params.map((p) => `${p}=${enc(v)}`).join("&")}`);
  }
}
// Pfad-IDs der lesenden Routen
for (const v of pathValues) {
  await call("Pfad", "GET", `/api/v1/hosts/${v}`);
  await call("Pfad", "GET", `/api/v1/hosts/${v}/history`);
  await call("Pfad", "GET", `/api/v1/hosts/${v}/cves`);
  await call("Pfad", "GET", `/api/v1/hosts/${v}/cves/groups?kind=fixed`);
  await call("Pfad", "GET", `/api/v1/hosts/${v}/updates`);
  await call("Pfad", "GET", `/api/v1/cves/${v}`);
  await call("Pfad", "GET", `/api/v1/notifications/${v}`);
}
// /live ist ein Strom: nur die Kopfzeile prüfen, dann abbrechen.
for (const qs of ["", "?x=%00", "?x=" + "a".repeat(5000)]) {
  const ac = new AbortController(); const t0 = Date.now(); n++;
  try { const r = await fetch(API + "/api/v1/live" + qs, { headers: { cookie }, signal: ac.signal }); ac.abort();
    if (r.status >= 500) { fails++; console.log(`FAIL GET /live${show(qs)} -> ${r.status}`); } if (Date.now() - t0 > MAX_MS) { fails++; console.log("FAIL /live Kopfzeile zu langsam"); } }
  catch (e) { if (e.name !== "AbortError") { fails++; console.log(`FAIL /live ${e.message}`); } }
}

// ---- Schreibende Routen: nur Werte, die abgelehnt werden sollen -------------------------------------------------------
// Rust parst auch "+5" und führende Zeichen als Zahl: darum die dekodierte, numerisch gelesene Form gegen echte IDs prüfen.
const valid = (v) => /^CVE-\d{4}-\d{4,}$/.test(v);
const notReal = (v) => { let d = v; try { d = decodeURIComponent(v); } catch {} const num = String(Number.parseInt(d.trim(), 10)); return !realHostIds.has(v) && !realHostIds.has(num) && !realFeeds.has(v) && !realFeeds.has(d); };
for (const v of pathValues.filter(notReal)) {
  await call("Pfad", "POST", `/api/v1/hosts/${v}/request-report`, { write: true });
  await call("Pfad", "POST", `/api/v1/hosts/${v}/rotate-token`, { write: true });
  await call("Pfad", "DELETE", `/api/v1/hosts/${v}`, { write: true });
  await call("Pfad", "PUT", `/api/v1/hosts/${NOEXIST}/cves/${v}/review`, { write: true });
  await call("Pfad", "DELETE", `/api/v1/hosts/${NOEXIST}/cves/${v}/review`, { write: true });
  if (!valid(v)) await call("Pfad", "PUT", `/api/v1/watchlist/${v}`, { body: {}, write: true });
  await call("Pfad", "DELETE", `/api/v1/watchlist/${v}`, { write: true });
  await call("Pfad", "POST", `/api/v1/feeds/${v}/run`, { write: true });
  await call("Pfad", "DELETE", `/api/v1/feeds/${v}`, { write: true });
  await call("Pfad", "PUT", `/api/v1/feeds/${v}`, { body: { enabled: true }, write: true });
  await call("Pfad", "PUT", `/api/v1/notifications/${v}`, { body: { enabled: true }, write: true });
  await call("Pfad", "POST", `/api/v1/notifications/${v}/test`, { write: true });
}
// Hosts anlegen: nur Namen, die nicht gültig sind (gültig = 1-63 Zeichen aus [A-Za-z0-9._-]).
const validHostName = (s) => /^[A-Za-z0-9._-]{1,63}$/.test(s);
for (const v of [...TEXT, ...JSON_ODD].filter((x) => typeof x !== "string" || !validHostName(x))) await call("POST /hosts name", "POST", "/api/v1/hosts", { body: { name: v }, write: true });
for (const b of ["", "{", "null", "[]", "\"x\"", "{\"name\":\"a\u0000\"}", "{\"name\":\"a\\u0000\"}", "{}", "{\"name\":\"x\",\"name\":\"y\"}"]) {
  await call("POST /hosts Body", "POST", "/api/v1/hosts", { body: b === "" ? undefined : b, raw: b === "" ? "" : undefined, ctype: "application/json", write: !/\{\"name\":\"x\"/.test(b) });
}
// Watchlist-Notiz an einer ungültigen ID (wird abgelehnt) und falsche Typen an gültiger ID.
for (const v of JSON_ODD) {
  await call("Watchlist note", "PUT", "/api/v1/watchlist/CVE-2099-0001", { body: { note: v }, write: true });
  if (v !== null) await call("Watchlist note", "PUT", "/api/v1/watchlist/CVE-2099", { body: { note: v }, write: true });
}
await call("Watchlist", "DELETE", "/api/v1/watchlist/CVE-2099-0001"); // räumt auf, falls oben etwas angenommen wurde
// Einstellungen: falsche Typen und unzulässige Zahlen.
for (const v of JSON_ODD.filter((x) => x !== null && x !== 1.5)) {
  for (const f of ["report_retention_days", "stale_after_hours"]) await call(`Settings ${f}`, "PUT", "/api/v1/settings", { body: { [f]: v }, write: true });
  await call("Settings feed_intervals", "PUT", "/api/v1/settings", { body: { feed_intervals: v }, write: true });
  await call("Settings feed_intervals", "PUT", "/api/v1/settings", { body: { feed_intervals: { [typeof v === "string" ? v : "debian"]: typeof v === "string" ? 60 : v } }, write: true });
  await call("Settings bulk", "PUT", "/api/v1/settings", { body: { feed_bulk_intervals: { [typeof v === "string" ? v : "debian"]: typeof v === "string" ? 60 : v } }, write: true });
  await call("Settings schedule", "PUT", "/api/v1/settings", { body: { report_schedule: v }, write: true });
  await call("Settings schedule", "PUT", "/api/v1/settings", { body: { report_schedule: { enabled: true, time: v, timezone: v } }, write: true });
}
for (const b of ["", "{", "null", "[]", "{\"report_retention_days\":\"1\u0000\"}", "{\"x\":1}"]) await call("Settings Body", "PUT", "/api/v1/settings", { raw: b, ctype: "application/json", write: false });
// OIDC-Einstellungen: enabled=true ohne gespeichertes Secret wird immer abgelehnt.
for (const v of JSON_ODD) for (const f of ["issuer", "client_id", "redirect_url", "name", "scopes", "client_secret", "allowed_emails", "allowed_domains"]) {
  await call(`OIDC ${f}`, "PUT", "/api/v1/settings/oidc", { body: { enabled: true, issuer: "https://example.invalid", client_id: "x", redirect_url: "https://example.invalid/cb", allowed_emails: ["a@example.invalid"], [f]: v }, write: true });
}
await call("OIDC enabled", "PUT", "/api/v1/settings/oidc", { body: { enabled: "ja" }, write: true });
// Benachrichtigungskanäle: aktiviert, ohne vollständige Konfiguration (wird abgelehnt).
for (const kind of ["ntfy", "gotify", "matrix", "smtp", "telegram", "webhook"]) {
  for (const v of JSON_ODD) {
    await call(`Kanal ${kind} config`, "PUT", `/api/v1/notifications/${kind}`, { body: { enabled: true, config: { url: v, topic: v, host: v, port: v, to: v, chat_id: v, homeserver: v, room_id: v } }, write: true });
    await call(`Kanal ${kind} secret`, "PUT", `/api/v1/notifications/${kind}`, { body: { enabled: true, secret: v }, write: true });
    await call(`Kanal ${kind} events`, "PUT", `/api/v1/notifications/${kind}`, { body: { enabled: true, events: v, summary_time: v }, write: true });
  }
  await call(`Kanal ${kind}`, "PUT", `/api/v1/notifications/${kind}`, { body: { enabled: "ja" }, write: true });
}
// Quellen: unbekannter Typ, oder gültiger Typ mit ungültigen Feldern (ein 2xx würde eine Quelle anlegen -> HINWEIS).
const REJECT = JSON_ODD.filter((x) => x === null || typeof x !== "string" || /[\u0000-\u001f\u007f]/.test(x) || x.length > 1000);
for (const v of JSON_ODD) {
  await call("Feed type", "POST", "/api/v1/feeds", { body: { type: v }, write: true });
  for (const f of ["label", "base_url", "ecosystem", "secret"]) {
    if (!REJECT.includes(v)) continue;
    const r = await call(`Feed ${f}`, "POST", "/api/v1/feeds", { body: { type: "osv", [f]: v }, write: true });
    // Wurde doch eine Quelle angelegt, wieder löschen (der Hinweis bleibt stehen).
    if (r.status === 201) { try { await call("Aufräumen", "DELETE", `/api/v1/feeds/${encodeURIComponent(JSON.parse(r.text).id ?? JSON.parse(r.text).source)}`); } catch {} }
  }
}
for (const v of ["a\u0000b", "x".repeat(10000), "\x01\x1f", "\u202E", 5, [], {}, true]) {
  for (const f of ["label", "base_url", "ecosystem", "secret", "enabled", "clear_secret", "clear_base_url"]) await call(`Feed PUT ${f}`, "PUT", `/api/v1/feeds/${NOEXIST}`, { body: { [f]: v }, write: true });
  await call("Feed run body", "POST", `/api/v1/feeds/${NOEXIST}/run`, { body: { confirm: v }, write: true });
}
await call("Feeds refresh", "POST", "/api/v1/feeds/refresh?wait=%00", { write: true });
await call("Feeds refresh", "POST", "/api/v1/feeds/refresh?wait=abc", { write: true });
await call("Feeds refresh", "POST", "/api/v1/feeds/refresh?wait=false", { body: { confirm: "x" }, write: true });
// Passwort ändern: das Limit liegt bei 5 Versuchen je 10 Minuten, daher nur fünf, mit falschem aktuellem Passwort.
for (const b of [{ current_password: "a\u0000b", new_password: "x".repeat(10000) }, { current_password: 1, new_password: [] }, { current_password: "", new_password: "" }, { current_password: "falsch", new_password: "😀".repeat(300) }, { current_password: "falsch" }]) {
  await call("Passwort", "POST", "/api/v1/auth/password", { body: b, write: true });
}
// Avatar: kein gültiges Bild
for (const [ctype, raw] of [["image/png", ""], ["image/png", "x".repeat(10000)], ["image/png", Buffer.from([0, 0, 0, 0])], ["text/plain", "a"], ["application/json", "{}"], ["image/svg+xml", "<svg onload=alert(1)/>"], ["image/png", Buffer.alloc(300000, 1)]]) {
  await call("Avatar", "PUT", "/api/v1/auth/avatar", { raw, ctype, write: true });
}
// ---- Ohne Anmeldung: Anmeldung, Report, Check-in -----------------------------------------------------------------------
// Fehlversuche je IP sind begrenzt (Check-in/Report: 20 je 10 Minuten, Anmeldung: 10 je Fenster); 429 zählt als 4xx.
const BAD_BODIES = ["", "{", "null", "[]", "0", "\"x\"", "{\"a\":\"\u0000\"}", "{\"a\":\"\\u0000\"}", "x".repeat(10000), "{\"packages\":\"x\",\"kernel\":5}", "\u0000\u0000", "{\"hostname\":" + "[".repeat(5000) + "}"];
const BAD_TOKENS = ["", "x", "x".repeat(300), "caf\u00e9", "a b", "Bearer", "' OR 1=1", "0".repeat(64)];
let k = 0;
for (const path of ["/api/v1/report", "/api/v1/agent/checkin"]) {
  for (const t of BAD_TOKENS) await call("Token", "POST", path, { auth: false, token: t, body: "{}", ctype: "application/json" });
  await call("Token", "POST", path, { auth: false, body: "{}" });
  for (const b of BAD_BODIES) { await call(`Body ${k++}`, "POST", path, { auth: false, token: "ungueltig", raw: b, ctype: "application/json" }); }
  await call("Content-Type", "POST", path, { auth: false, token: "ungueltig", raw: "a=b", ctype: "application/x-www-form-urlencoded" });
  await call("Content-Type", "POST", path, { auth: false, token: "ungueltig", raw: "a", ctype: "text/plain" });
  await call("GET", "GET", path, { auth: false });
}
await call("Report groß", "POST", "/api/v1/report", { auth: false, token: "ungueltig", raw: "x".repeat(5 * 1024 * 1024), ctype: "application/json" });
// Anmeldung (die echte Anmeldung oben hat 1 von 10 Versuchen verbraucht; hier höchstens 8)
for (const b of [{ username: "a\u0000b", password: "x" }, { username: "x".repeat(10000), password: "x" }, { username: "café日本😀", password: "x" }, { username: 1, password: [] }, { username: "\u202Eadmin", password: "\x01" }, "{", { username: USER }, { username: "", password: "" }]) {
  await call("Login", "POST", "/api/v1/auth/login", { auth: false, body: b, write: true });
}

// ---- Server noch da? ---------------------------------------------------------------------------------------------------
await sleep(300);
const ready = await fetch(API + "/readyz").then((r) => r.status, () => 0);
if (ready !== 200) { fails++; console.log(`FAIL /readyz danach: ${ready}`); } else console.log("OK   /readyz nach dem Lauf erreichbar");
console.log(`${n} Anfragen, Status ${Object.entries(byStatus).map(([k2, v]) => `${k2}xx: ${v}`).join(", ")}, langsamste ${slowest} ms, ${hints} Hinweis(e)`);
console.log(fails ? `${fails} FEHLER` : "OK   keine 5xx, keine Antwort über 5 s");
process.exit(fails ? 1 : 0);
