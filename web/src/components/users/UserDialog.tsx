"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { Button, Field, Select, TextInput } from "@/components/Controls";
import { Dialog } from "@/components/Dialog";
import { ErrorNote } from "@/components/States";
import { useAuth } from "@/components/AuthProvider";
import { createSummary, involvesAdmin, type RolesResponse } from "@/lib/roles";
import type { UserRow } from "@/lib/types";
import { RolePreview } from "./RolePreview";

export type DialogMode = { kind: "create" } | { kind: "edit"; user: UserRow } | { kind: "approve"; user: UserRow };

/** Anlegen, Bearbeiten und Freigeben eines Benutzers mit Rechtevorschau. Der Server prüft alles erneut. */
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
  return (
    <Dialog open={mode !== null} title={mode?.kind === "create" ? "Benutzer anlegen" : mode?.kind === "approve" ? `${mode.user.display_name} freigeben` : `${mode?.user.display_name ?? ""} bearbeiten`} onClose={onClose}>
      {mode && roles ? <Form key={mode.kind === "create" ? "new" : mode.user.id} mode={mode} roles={roles} onClose={onClose} onDone={onDone} onReset={onReset} /> : null}
    </Dialog>
  );
}

function Form({ mode, roles, onClose, onDone, onReset }: { onReset?: (u: UserRow) => void; mode: DialogMode; roles: RolesResponse; onClose: () => void; onDone: (r: { password?: string; name: string }) => void }) {
  const { me } = useAuth();
  const user = mode.kind === "create" ? null : mode.user;
  const [name, setName] = useState(user?.display_name ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [kind, setKind] = useState<"local" | "oidc">("local");
  const [sub, setSub] = useState("");
  const [role, setRole] = useState(mode.kind === "approve" ? (user?.requested_role ?? "viewer") : (user?.role ?? "viewer"));
  const [confirmName, setConfirmName] = useState("");
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const roleInfo = roles.roles.find((r) => r.key === role);
  const roleChanged = mode.kind === "edit" && user !== null && role !== user.role;
  const needsPw = mode.kind === "approve" ? role === "admin" : mode.kind === "create" ? role === "admin" : roleChanged && involvesAdmin(user?.role ?? null, role);
  const oidcMe = me.auth_kind === "oidc";
  const self = user?.is_self === true;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!name.trim()) return setError("Bitte einen Namen angeben.");
    if (roleChanged && confirmName.trim() !== user?.display_name) return setError("Zur Bestätigung der Rollenänderung den Namen des Benutzers eingeben.");
    setBusy(true);
    const confirm_password = needsPw && !oidcMe ? pw : undefined;
    try {
      if (mode.kind === "create") {
        const r = await api.post<{ user: UserRow; initial_password?: string }>(
          "/users",
          { display_name: name.trim(), auth_kind: kind, email: email.trim() || undefined, role, oidc_subject: kind === "oidc" ? sub.trim() : undefined, confirm_password },
          { silent: true },
        );
        onDone({ password: r.initial_password, name: name.trim() });
      } else if (mode.kind === "approve") {
        await api.post(`/users/${mode.user.id}/approve`, { role, confirm_password }, { silent: true });
        onDone({ name: mode.user.display_name });
      } else {
        await api.patch(`/users/${mode.user.id}`, { display_name: name.trim(), email: email.trim(), role: roleChanged ? role : undefined, confirm_name: roleChanged ? confirmName.trim() : undefined, confirm_password }, { silent: true });
        onDone({ name: name.trim() });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Speichern fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
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
      <Field label="Rolle">
        <Select value={role} onChange={(e) => setRole(e.target.value)} disabled={self}>
          {roles.roles.map((r) => (
            <option key={r.key} value={r.key}>
              {r.title}
            </option>
          ))}
        </Select>
      </Field>
      {self ? <p className="m-0 text-xs text-fg3">Die eigene Rolle ändert ein anderer Administrator.</p> : null}
      <RolePreview role={roleInfo} groups={roles.groups} />
      {role === "admin" ? (
        <p role="note" className="m-0 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
          Administratoren dürfen Benutzer verwalten, OIDC einrichten und das Aktivitätsprotokoll lesen. Vergib diese Rolle sparsam.
        </p>
      ) : null}
      {roleChanged ? (
        <Field label={`Zur Bestätigung den Namen „${user?.display_name}“ eingeben`}>
          <TextInput value={confirmName} onChange={(e) => setConfirmName(e.target.value)} autoComplete="off" />
        </Field>
      ) : null}
      {needsPw ? (
        oidcMe ? (
          <p className="m-0 text-xs text-fg2">Für Administratorrechte muss deine OIDC-Anmeldung höchstens 5 Minuten her sein. Melde dich sonst neu an.</p>
        ) : (
          <Field label="Dein Passwort (für Administratorrechte)">
            <TextInput type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" />
          </Field>
        )
      ) : null}
      {mode.kind === "create" ? <p className="m-0 text-sm text-fg2">{createSummary(name, roleInfo?.title ?? "")}</p> : null}
      {error ? <ErrorNote message={error} /> : null}
      <div className="flex flex-wrap justify-end gap-2">
        {mode.kind === "edit" && onReset && user && user.auth_kind === "local" && !user.is_self ? (
          <Button className="mr-auto" onClick={() => onReset(user)}>
            Passwort zurücksetzen
          </Button>
        ) : null}
        <Button onClick={onClose}>Abbrechen</Button>
        <Button type="submit" variant="primary" busy={busy}>
          {mode.kind === "create" ? "Benutzer anlegen" : mode.kind === "approve" ? "Freigeben" : "Speichern"}
        </Button>
      </div>
    </form>
  );
}
