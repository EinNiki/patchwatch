// Reine Logik der Benutzerverwaltung (ohne JSX, damit sie mit `npm test` geprüft werden kann).
// Maßgeblich ist immer der Server; die Oberfläche blendet nur aus und zeigt eine Vorschau.

export interface RoleInfo {
  key: string;
  title: string;
  permissions: string[];
}
export interface PermInfo {
  name: string;
  label: string;
  description: string;
  /** Voraussetzungen (Schreiben setzt Lesen voraus); Spiegel der Server-Tabelle, der Server prüft erneut. */
  requires: string[];
  /** Vergabe verlangt das eigene Passwort bzw. eine frische Anmeldung. */
  sensitive: boolean;
}
export interface PermGroup {
  title: string;
  permissions: PermInfo[];
}
export interface RolesResponse {
  roles: RoleInfo[];
  groups: PermGroup[];
}

/** Hat der Benutzer das benannte Recht (z. B. `hosts.write`)? Ohne Angabe: nein (Standard verweigern). */
export function can(permissions: readonly string[] | undefined, perm: string): boolean {
  return !!permissions && permissions.includes(perm);
}

const allPerms = (groups: readonly PermGroup[]): PermInfo[] => groups.flatMap((g) => g.permissions);

/** Schließt eine Auswahl unter den Voraussetzungen ab: ein Recht ohne seine Voraussetzung fällt weg (kaskadierend). Unbekannte Namen fallen ebenfalls weg. */
export function closeSet(selected: Iterable<string>, groups: readonly PermGroup[]): string[] {
  const info = new Map(allPerms(groups).map((p) => [p.name, p]));
  let cur = [...new Set(selected)].filter((n) => info.has(n));
  for (;;) {
    const keep = cur.filter((n) => info.get(n)!.requires.every((r) => cur.includes(r)));
    if (keep.length === cur.length) break;
    cur = keep;
  }
  return cur;
}

/** Schalter umlegen: Einschalten nimmt die Voraussetzungen mit, Ausschalten nimmt abhängige Rechte mit (Abhängigkeitslogik wie am Server). */
export function togglePerm(current: readonly string[], name: string, on: boolean, groups: readonly PermGroup[]): string[] {
  const info = new Map(allPerms(groups).map((p) => [p.name, p]));
  if (!info.has(name)) return closeSet(current, groups);
  if (!on) return closeSet(current.filter((n) => n !== name), groups);
  const next = new Set(current);
  const add = (n: string) => {
    if (next.has(n)) return;
    next.add(n);
    info.get(n)?.requires.forEach(add);
  };
  add(name);
  return closeSet(next, groups);
}

/** Welche anderen Rechte hängen von diesem ab (werden beim Ausschalten mit ausgeschaltet)? Direkt und indirekt, nur bereits gewährte. */
export function dependents(name: string, current: readonly string[], groups: readonly PermGroup[]): string[] {
  const after = new Set(togglePerm(current, name, false, groups));
  return current.filter((n) => n !== name && !after.has(n));
}

export const sameSet = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((x) => b.includes(x));

/** Vorlage, deren Rechte genau der Auswahl entsprechen; sonst `custom` ("Eigene"). */
export function templateOf(selected: readonly string[], roles: readonly RoleInfo[]): string {
  return roles.find((r) => sameSet(r.permissions, selected))?.key ?? "custom";
}

/** Sensible Rechte, die in `next` neu hinzukommen oder wegfallen (verlangt Passwort bzw. frische Anmeldung). */
export function sensitiveChange(prev: readonly string[], next: readonly string[], groups: readonly PermGroup[]): string[] {
  return allPerms(groups)
    .filter((p) => p.sensitive && prev.includes(p.name) !== next.includes(p.name))
    .map((p) => p.name);
}

/** Zusammenfassung unter dem Formular: erst sichtbar, wenn ein Name eingegeben ist (vorher leer). */
export function createSummary(name: string, templateTitle: string, count: number): string {
  const n = name.trim();
  if (!n) return "";
  return `Benutzer ${n} wird mit ${templateTitle === "Eigene" ? `eigener Auswahl (${count} Rechte)` : `der Vorlage ${templateTitle} (${count} Rechte)`} angelegt.`;
}

export interface GuardUser {
  is_self: boolean;
  auth_kind: string;
  status: string;
  permissions: readonly string[];
}
export interface RowGuard {
  /** Grund, warum Bearbeiten/Freigeben nicht geht (sonst `undefined`). */
  edit?: string;
  lock?: string;
  remove?: string;
}

/**
 * Gründe, warum eine Zeilenaktion gesperrt ist. Spiegel der Serverregeln (der Server prüft immer erneut):
 * eigenes Konto, letzter lokaler Benutzer mit `users.manage`, Konto mit Rechten, die man selbst nicht hat.
 */
export function rowGuard(u: GuardUser, all: readonly GuardUser[], mine: readonly string[] | undefined): RowGuard {
  const g: RowGuard = {};
  const isManager = (x: GuardUser) => x.auth_kind === "local" && x.status === "active" && x.permissions.includes("users.manage");
  if (u.is_self) {
    g.lock = "Das eigene Konto kann nicht gesperrt oder gelöscht werden";
    g.remove = g.lock;
  }
  if (isManager(u) && all.filter(isManager).length <= 1) {
    const why = "Letzter lokaler Benutzer mit dem Recht „Benutzer verwalten“: ohne ihn könnte niemand mehr Benutzer verwalten";
    g.lock ??= why;
    g.remove ??= why;
  }
  if (!u.permissions.every((p) => can(mine, p))) {
    const why = "Dieses Konto hat Rechte, die du selbst nicht hast; du darfst es nicht verwalten";
    g.edit = why;
    g.lock = why;
    g.remove = why;
  }
  return g;
}

export const STATUS_LABEL: Record<string, string> = { active: "aktiv", locked: "gesperrt", pending: "wartet auf Freigabe" };
export const KIND_LABEL: Record<string, string> = { local: "lokal", oidc: "OIDC" };

/** Lesbare Bezeichnung einer Protokoll-Kennung; unbekannte Kennungen bleiben unverändert sichtbar. */
const ACTION_LABEL: Record<string, string> = {
  login: "Anmeldung",
  "login.failed": "Anmeldung fehlgeschlagen",
  "oidc.login": "OIDC-Anmeldung abgelehnt",
  "oidc.test": "OIDC-Verbindungstest",
  "oidc.settings_changed": "OIDC-Einstellungen geändert",
  "user.created": "Benutzer angelegt",
  "user.created_by_oidc": "Konto per OIDC angelegt",
  "user.updated": "Benutzer geändert",
  "user.role_changed": "Rolle geändert",
  "user.permissions_changed": "Rechte geändert",
  "user.role_changed_by_idp": "Rolle durch Anbieter herabgestuft",
  "user.locked": "Benutzer gesperrt",
  "user.unlocked": "Benutzer entsperrt",
  "user.approved": "Benutzer freigegeben",
  "user.deleted": "Benutzer gelöscht",
  "user.password_reset": "Einmalpasswort erzeugt",
  "password.changed": "Passwort geändert",
};
export function actionLabel(action: string): string {
  return ACTION_LABEL[action] ?? action;
}

export const RESULT_LABEL: Record<string, string> = { ok: "erfolgreich", denied: "abgelehnt", failed: "fehlgeschlagen" };
