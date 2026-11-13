// Rechtevorschau, Rechtepruefung und Texte der Benutzerverwaltung (reine Logik).
import assert from "node:assert/strict";
import { test } from "node:test";
import { actionLabel, can, createSummary, involvesAdmin, previewRows, type PermGroup, type RoleInfo } from "../src/lib/roles.ts";

const groups: PermGroup[] = [
  { title: "Hosts", permissions: [{ name: "hosts.read", label: "Hosts ansehen" }, { name: "hosts.write", label: "Hosts anlegen und löschen" }] },
  { title: "Benutzer", permissions: [{ name: "users.manage", label: "Benutzer verwalten" }] },
];
const viewer: RoleInfo = { key: "viewer", title: "Nur Lesen", permissions: ["hosts.read"] };

test("ohne Angabe gilt: kein Recht (Standard verweigern)", () => {
  assert.equal(can(undefined, "hosts.read"), false);
  assert.equal(can([], "hosts.read"), false);
  assert.equal(can(["hosts.read"], "hosts.write"), false);
  assert.equal(can(["hosts.read"], "hosts.read"), true);
});

test("Vorschau zeigt je Recht darf / darf nicht", () => {
  const rows = previewRows(viewer, groups);
  assert.deepEqual(rows[0].items.map((i) => i.allowed), [true, false]);
  assert.deepEqual(rows[1].items.map((i) => i.allowed), [false]);
  assert.ok(previewRows(undefined, groups).every((g) => g.items.every((i) => !i.allowed)));
});

test("Zusammenfassung nennt Name und Rolle", () => {
  assert.equal(createSummary(" Anna ", "Betreiber"), "Benutzer Anna wird mit der Rolle Betreiber angelegt.");
  assert.equal(createSummary("", "Nur Lesen"), "Benutzer … wird mit der Rolle Nur Lesen angelegt.");
});

test("Administratorrechte betreffen alte und neue Rolle", () => {
  assert.equal(involvesAdmin("viewer", "admin"), true);
  assert.equal(involvesAdmin("admin", "viewer"), true);
  assert.equal(involvesAdmin("viewer", "operator"), false);
});

test("unbekannte Protokoll-Kennungen bleiben sichtbar", () => {
  assert.equal(actionLabel("user.created"), "Benutzer angelegt");
  assert.equal(actionLabel("neu.ereignis"), "neu.ereignis");
});
