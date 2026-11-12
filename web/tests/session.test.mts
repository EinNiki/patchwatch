// Sitzungsprüfung und Fehlertexte bei Ausfall: nur 401 führt zur Anmeldung, 5xx/Netzfehler zeigen einen Fehlerzustand.
import assert from "node:assert/strict";
import { test } from "node:test";
import { sessionFailure } from "../src/lib/session.ts";
import { describeApiError } from "../src/lib/apiErrors.ts";

test("nur 401 leitet zur Anmeldung", () => {
  assert.deepEqual(sessionFailure({ status: 401, message: "nicht angemeldet" }), { kind: "login" });
});
test("Datenbank-Ausfall (503), Proxy-Fehler (502), 500 und Netzfehler sind kein Abmelden", () => {
  for (const status of [500, 502, 503, 504, 0]) {
    const r = sessionFailure({ status, message: "interner Fehler" });
    assert.equal(r.kind, "error", `HTTP ${status}`);
  }
  assert.equal(sessionFailure(new TypeError("Failed to fetch")).kind, "error");
  assert.equal(sessionFailure(undefined).kind, "error");
});
test("verständliche deutsche Texte ohne Server-Details", () => {
  const db = sessionFailure({ status: 503, message: "Die Datenbank ist gerade nicht erreichbar." });
  assert.equal(db.kind === "error" && db.message, "Server oder Datenbank gerade nicht erreichbar. Bitte in einigen Sekunden erneut versuchen.");
  assert.match(describeApiError(502), /Server nicht erreichbar/);
  assert.match(describeApiError(504), /Server nicht erreichbar/);
  assert.equal(describeApiError(0), "Server nicht erreichbar.");
  // Andere 5xx bleiben beim Hinweis auf das Server-Log, ohne den Server-Text.
  assert.equal(describeApiError(500, "geheimes Detail"), "Serverfehler (HTTP 500). Details stehen im Server-Log.");
});
