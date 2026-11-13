// Reine Logik der Benutzerverwaltung (ohne JSX, damit sie mit `npm test` geprüft werden kann).
// Maßgeblich ist immer der Server; die Oberfläche blendet nur aus und zeigt eine Vorschau.

export interface RoleInfo {
  key: string;
  title: string;
  permissions: string[];
}
export interface PermGroup {
  title: string;
  permissions: { name: string; label: string }[];
}
export interface RolesResponse {
  roles: RoleInfo[];
  groups: PermGroup[];
  can_see_secrets: boolean;
}

/** Hat der Benutzer das benannte Recht (z. B. `hosts.write`)? Ohne Angabe: nein (Standard verweigern). */
export function can(permissions: readonly string[] | undefined, perm: string): boolean {
  return !!permissions && permissions.includes(perm);
}

export interface PreviewGroup {
  title: string;
  items: { label: string; allowed: boolean }[];
}

/** Rechtevorschau einer Rolle: je Gruppe alle Rechte mit "darf" oder "darf nicht". */
export function previewRows(role: RoleInfo | undefined, groups: readonly PermGroup[]): PreviewGroup[] {
  const has = new Set(role?.permissions ?? []);
  return groups.map((g) => ({ title: g.title, items: g.permissions.map((p) => ({ label: p.label, allowed: has.has(p.name) })) }));
}

/** Zusammenfassung unter dem Formular, bevor angelegt wird. */
export function createSummary(name: string, roleTitle: string): string {
  return `Benutzer ${name.trim() || "…"} wird mit der Rolle ${roleTitle} angelegt.`;
}

/** Administratorrechte berührt eine Änderung, wenn die alte oder die neue Rolle Administrator ist: dann wird das eigene Passwort verlangt. */
export function involvesAdmin(oldRole: string | null, newRole: string): boolean {
  return oldRole === "admin" || newRole === "admin";
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
