// Abhängigkeitslogik, Zusammenfassung und Texte der Benutzerverwaltung (reine Logik).
import assert from "node:assert/strict";
import { test } from "node:test";
import { actionLabel, can, closeSet, createSummary, dependents, sensitiveChange, templateOf, togglePerm, type PermGroup, type RoleInfo } from "../src/lib/roles.ts";

const p = (name: string, requires: string[] = [], sensitive = false) => ({ name, label: name, description: "", requires, sensitive });
const groups: PermGroup[] = [
  { title: "Hosts", permissions: [p("hosts.read"), p("hosts.write", ["hosts.read"]), p("hosts.delete", ["hosts.write"])] },
  { title: "Benutzer", permissions: [p("users.manage", [], true), p("audit.read", [], true)] },
];
const roles: RoleInfo[] = [
  { key: "viewer", title: "Nur Lesen", permissions: ["hosts.read"] },
  { key: "admin", title: "Administrator", permissions: ["hosts.read", "hosts.write", "hosts.delete", "users.manage", "audit.read"] },
];

test("ohne Angabe gilt: kein Recht (Standard verweigern)", () => {
  assert.equal(can(undefined, "hosts.read"), false);
  assert.equal(can([], "hosts.read"), false);
  assert.equal(can(["hosts.read"], "hosts.write"), false);
  assert.equal(can(["hosts.read"], "hosts.read"), true);
});

test("Einschalten nimmt Voraussetzungen mit, Ausschalten die abhängigen Rechte", () => {
  assert.deepEqual(togglePerm([], "hosts.delete", true, groups).sort(), ["hosts.delete", "hosts.read", "hosts.write"]);
  assert.deepEqual(togglePerm(["hosts.read", "hosts.write", "hosts.delete"], "hosts.read", false, groups), []);
  assert.deepEqual(togglePerm(["hosts.read", "hosts.write", "hosts.delete"], "hosts.write", false, groups), ["hosts.read"]);
  assert.deepEqual(togglePerm(["hosts.read"], "gibt.es.nicht", true, groups), ["hosts.read"]);
});

test("closeSet wirft Rechte ohne Voraussetzung und unbekannte Namen weg", () => {
  assert.deepEqual(closeSet(["hosts.write", "unbekannt", "users.manage"], groups), ["users.manage"]);
  assert.deepEqual(closeSet(["hosts.read", "hosts.read"], groups), ["hosts.read"]);
});

test("dependents nennt, was beim Ausschalten mit wegfällt", () => {
  assert.deepEqual(dependents("hosts.read", ["hosts.read", "hosts.write", "users.manage"], groups), ["hosts.write"]);
  assert.deepEqual(dependents("users.manage", ["users.manage"], groups), []);
});

test("Vorlage wird an der Rechtemenge erkannt, sonst Eigene", () => {
  assert.equal(templateOf(["hosts.read"], roles), "viewer");
  assert.equal(templateOf(["hosts.read", "audit.read"], roles), "custom");
  assert.equal(templateOf([], roles), "custom");
});

test("sensible Rechte: Vergabe und Entzug werden erkannt", () => {
  assert.deepEqual(sensitiveChange(["hosts.read"], ["hosts.read", "audit.read"], groups), ["audit.read"]);
  assert.deepEqual(sensitiveChange(["users.manage"], [], groups), ["users.manage"]);
  assert.deepEqual(sensitiveChange(["hosts.read"], ["hosts.read", "hosts.write"], groups), []);
});

test("Zusammenfassung erscheint erst mit einem Namen", () => {
  assert.equal(createSummary("", "Betreiber", 9), "");
  assert.equal(createSummary("   ", "Betreiber", 9), "");
  assert.equal(createSummary(" Anna ", "Betreiber", 9), "Benutzer Anna wird mit der Vorlage Betreiber (9 Rechte) angelegt.");
  assert.equal(createSummary("Bob", "Eigene", 3), "Benutzer Bob wird mit eigener Auswahl (3 Rechte) angelegt.");
});

test("unbekannte Protokoll-Kennungen bleiben sichtbar", () => {
  assert.equal(actionLabel("user.created"), "Benutzer angelegt");
  assert.equal(actionLabel("user.permissions_changed"), "Rechte geändert");
  assert.equal(actionLabel("neu.ereignis"), "neu.ereignis");
});
