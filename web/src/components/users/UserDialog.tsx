"use client";

import { useState } from "react";
import { createPortal } from "react-dom";
import { api, ApiError } from "@/lib/api";
import { Button, Field, Select, TextInput } from "@/components/Controls";
import { Dialog } from "@/components/Dialog";
import { ErrorNote } from "@/components/States";
import { useAuth } from "@/components/AuthProvider";
import { createSummary, sameSet, sensitiveChange, templateOf, togglePerm, type RolesResponse } from "@/lib/roles";
import type { UserRow } from "@/lib/types";
import { PermissionSwitches } from "./PermissionSwitches";

export type DialogMode = { kind: "create" } | { kind: "edit"; user: UserRow } | { kind: "approve"; user: UserRow };

const FORM_ID = "user-dialog-form";

/** Anlegen, Bearbeiten und Freigeben eines Benutzers: Vorlage wählen, Rechte einzeln schalten. Der Server prüft alles erneut. */
export function UserDialog({
  mode,
  roles,
  onClose,
  onDone,
  onReset,
}: {
  onReset?: (u: UserRow) => void;
  mode: DialogMode | null;
  roles: RolesResponse | undefined;
  onClose: () => void;
  onDone: (r: { password?: string; name: string }) => void;
}) {
  const [footer, setFooter] = useState<HTMLDivElement | null>(null);
  return (
    <Dialog
      open={mode !== null}
      title={mode?.kind === "create" ? "Benutzer anlegen" : mode?.kind === "approve" ? `${mode.user.display_name} freigeben` : `${mode?.user.display_name ?? ""} bearbeiten`}
      onClose={onClose}
      footerRef={setFooter}
    >
      {mode && roles ? <Form key={mode.kind === "create" ? "new" : mode.user.id} mode={mode} roles={roles} footer={footer} onClose={onClose} onDone={onDone} onReset={onReset} /> : null}
    </Dialog>
  );
}

function Form({ mode, roles, footer, onClose, onDone, onReset }: { onReset?: (u: UserRow) => void; mode: DialogMode; roles: RolesResponse; footer: HTMLElement | null; onClose: () => void; onDone: (r: { password?: string; name: string }) => void }) {
  const { me } = useAuth();
  const user = mode.kind === "create" ? null : mode.user;
  const startRole = mode.kind === "approve" ? (user?.requested_role ?? "viewer") : (user?.role ?? "viewer");
  const templateRights = (key: string) => roles.roles.find((r) => r.key === key)?.permissions ?? [];
  const [name, setName] = useState(user?.display_name ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [kind, setKind] = useState<"local" | "oidc">("local");
  const [sub, setSub] = useState("");
  // Vorlage (Rolle) als Ausgangspunkt; die Schalter weichen davon ab ("Eigene").
  const [baseRole, setBaseRole] = useState(startRole);
  const [perms, setPerms] = useState<string[]>(mode.kind === "edit" && user ? user.permissions : templateRights(startRole));
  const [custom, setCustom] = useState(mode.kind === "edit" && !!user?.custom_permissions && templateOf(user.permissions, roles.roles) === "custom");
  const [confirmName, setConfirmName] = useState("");
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selected = custom ? "custom" : templateOf(perms, roles.roles);
  const templateTitle = selected === "custom" ? "Eigene" : (roles.roles.find((r) => r.key === selected)?.title ?? "Eigene");
  const self = user?.is_self === true;
  const oidcMe = me.auth_kind === "oidc" || me.auth_kind === "ldap";
  const grantable = me.permissions ?? [];

  const roleChanged = mode.kind === "edit" && user !== null && baseRole !== user.role;
  const rightsChanged = mode.kind === "edit" && user !== null && (roleChanged || !sameSet(perms, user.permissions));
  // Passwort bzw. frische Anmeldung: neue oder entzogene sensible Rechte, jeder Rollenwechsel, Vergabe beim Anlegen/Freigeben.
  const sens = sensitiveChange(mode.kind === "edit" && user ? user.permissions : [], perms, roles.groups);
  const needsPw = mode.kind === "edit" ? roleChanged || sens.length > 0 : sens.length > 0;
  const needsName = rightsChanged;

  function pick(key: string) {
    if (key === "custom") return setCustom(true);
    setCustom(false);
    setBaseRole(key);
    setPerms(templateRights(key));
  }
  function toggle(perm: string, on: boolean) {
    const next = togglePerm(perms, perm, on, roles.groups);
    setPerms(next);
    setCustom(templateOf(next, roles.roles) === "custom");
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (mode.kind !== "approve" && !name.trim()) return setError("Bitte einen Namen angeben.");
    if (needsName && confirmName.trim() !== user?.display_name) return setError("Zur Bestätigung der Rechteänderung den Namen des Benutzers eingeben.");
    if (needsPw && !oidcMe && !pw) return setError("Zur Bestätigung dein Passwort eingeben.");
    setBusy(true);
    const confirm_password = needsPw && !oidcMe ? pw : undefined;
    // Entspricht die Auswahl genau der Vorlage, folgt der Benutzer der Rolle; sonst werden die Rechte einzeln gespeichert.
    const follows = sameSet(perms, templateRights(baseRole));
    const rights = follows ? {} : { permissions: perms };
    try {
      if (mode.kind === "create") {
        const r = await api.post<{ user: UserRow; initial_password?: string }>(
          "/users",
          { display_name: name.trim(), auth_kind: kind, email: email.trim() || undefined, role: baseRole, ...rights, oidc_subject: kind === "oidc" ? sub.trim() : undefined, confirm_password },
          { silent: true },
        );
        onDone({ password: r.initial_password, name: name.trim() });
      } else if (mode.kind === "approve") {
        await api.post(`/users/${mode.user.id}/approve`, { role: baseRole, ...rights, confirm_password }, { silent: true });
        onDone({ name: mode.user.display_name });
      } else {
        await api.patch(
          `/users/${mode.user.id}`,
          {
            display_name: name.trim(),
            email: email.trim(),
            ...(rightsChanged ? { role: roleChanged ? baseRole : undefined, ...(follows ? { use_template: true } : rights), confirm_name: confirmName.trim() } : {}),
            confirm_password,
          },
          { silent: true },
        );
        onDone({ name: name.trim() });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Speichern fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  const summary = mode.kind === "create" ? createSummary(name, templateTitle, perms.length) : "";

  return (
    <>
      <form id={FORM_ID} onSubmit={(e) => void submit(e)} className="flex flex-col gap-3 pb-1">
        {mode.kind !== "approve" ? (
          <Field label="Name">
            <TextInput value={name} onChange={(e) => setName(e.target.value)} maxLength={60} autoComplete="off" autoFocus />
          </Field>
        ) : null}
        {mode.kind === "create" ? (
          <Field label="Anmeldeart">
            <Select value={kind} onChange={(e) => setKind(e.target.value as "local" | "oidc")}>
              <option value="local">Lokal (Einmalpasswort)</option>
              <option value="oidc">OIDC (Anbieter, Subject bekannt)</option>
            </Select>
          </Field>
        ) : null}
        {mode.kind === "create" && kind === "oidc" ? (
          <Field label="Subject (sub) beim Anbieter">
            <TextInput value={sub} onChange={(e) => setSub(e.target.value)} maxLength={255} autoComplete="off" />
          </Field>
        ) : null}
        {mode.kind !== "approve" ? (
          <Field label="E-Mail (optional, nur Anzeige)">
            <TextInput type="email" value={email} onChange={(e) => setEmail(e.target.value)} maxLength={254} autoComplete="off" />
          </Field>
        ) : null}
        <Field label="Vorlage">
          <Select value={selected} onChange={(e) => pick(e.target.value)} disabled={self}>
            {roles.roles.map((r) => (
              <option key={r.key} value={r.key}>
                {r.title}
              </option>
            ))}
            <option value="custom">Eigene</option>
          </Select>
        </Field>
        <p className="m-0 text-xs text-fg3">{self ? "Die eigenen Rechte ändert ein anderer Benutzer." : "Die Vorlage setzt die Schalter; danach kannst du jedes Recht einzeln ändern."}</p>
        <PermissionSwitches groups={roles.groups} value={perms} grantable={grantable} locked={self} lockedReason="Die eigenen Rechte ändert ein anderer Benutzer." onToggle={toggle} />
        {sens.length > 0 ? (
          <p role="note" className="m-0 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
            Diese Auswahl enthält Rechte zur Benutzerverwaltung, zu OIDC oder zum Aktivitätsprotokoll. Vergib sie sparsam.
          </p>
        ) : null}
        {needsName ? (
          <Field label={`Zur Bestätigung den Namen „${user?.display_name}“ eingeben`}>
            <TextInput value={confirmName} onChange={(e) => setConfirmName(e.target.value)} autoComplete="off" />
          </Field>
        ) : null}
        {needsPw ? (
          oidcMe ? (
            <p className="m-0 text-xs text-fg2">Dafür muss deine OIDC-Anmeldung höchstens 5 Minuten her sein. Melde dich sonst neu an.</p>
          ) : (
            <Field label="Dein Passwort (zur Bestätigung)">
              <TextInput type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" />
            </Field>
          )
        ) : null}
        {summary ? <p className="m-0 text-sm text-fg2">{summary}</p> : null}
      </form>
      {footer
        ? createPortal(
            <div className="flex flex-col gap-2">
              {error ? <ErrorNote message={error} /> : null}
              <div className="flex flex-wrap justify-end gap-2">
                {mode.kind === "edit" && onReset && user && user.auth_kind === "local" && !user.is_self ? (
                  <Button className="mr-auto" onClick={() => onReset(user)}>
                    Passwort zurücksetzen
                  </Button>
                ) : null}
                <Button onClick={onClose}>Abbrechen</Button>
                <Button type="submit" form={FORM_ID} variant="primary" busy={busy}>
                  {mode.kind === "create" ? "Benutzer anlegen" : mode.kind === "approve" ? "Freigeben" : "Speichern"}
                </Button>
              </div>
            </div>,
            footer,
          )
        : null}
    </>
  );
}
