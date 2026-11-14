"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { toast } from "@/lib/toastStore";
import { Avatar } from "@/components/Avatar";
import { Button, Field, TextInput } from "@/components/Controls";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Dialog } from "@/components/Dialog";
import { NavIcon } from "@/components/Icons";
import { RelTime } from "@/components/RelTime";
import { ActionCell } from "@/components/ActionCell";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { useAuth } from "@/components/AuthProvider";
import { KIND_LABEL, STATUS_LABEL, rowGuard, type RolesResponse } from "@/lib/roles";
import type { StatusInfo } from "@/lib/status";
import type { UserRow } from "@/lib/types";
import { UserDialog, type DialogMode } from "./UserDialog";
import { OneTimePassword } from "./OneTimePassword";

const STATUS_INFO: Record<string, StatusInfo> = {
  active: { rank: 0, tone: "ok", icon: "ok", label: STATUS_LABEL.active },
  locked: { rank: 0, tone: "crit", icon: "crit", label: STATUS_LABEL.locked },
  pending: { rank: 0, tone: "warn", icon: "clock", label: STATUS_LABEL.pending },
};

/** Löschen mit Namensbestätigung (und eigenem Passwort, wenn das Ziel Administrator ist). */
function DeleteDialog({ user, sensitive, onClose, onDone }: { user: UserRow | null; sensitive: readonly string[]; onClose: () => void; onDone: () => void }) {
  return (
    <Dialog open={user !== null} title={`${user?.display_name ?? ""} löschen?`} onClose={onClose}>
      {user ? <DeleteForm key={user.id} user={user} sensitive={sensitive} onClose={onClose} onDone={onDone} /> : null}
    </Dialog>
  );
}

function DeleteForm({ user, sensitive, onClose, onDone }: { user: UserRow; sensitive: readonly string[]; onClose: () => void; onDone: () => void }) {
  const { me } = useAuth();
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Wie der Server: Passwort, wenn das Konto sensible Rechte hat (Benutzerverwaltung, OIDC, Aktivitätsprotokoll).
  const needsPw = user.permissions.some((p) => sensitive.includes(p)) && me.auth_kind === "local";
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (name.trim() !== user.display_name) return setError("Der eingegebene Name stimmt nicht.");
        setBusy(true);
        api
          .delWithBody(`/users/${user.id}`, { confirm_name: name.trim(), confirm_password: needsPw ? pw : undefined })
          .then(onDone)
          .catch((err: unknown) => setError(err instanceof ApiError ? err.message : "Löschen fehlgeschlagen."))
          .finally(() => setBusy(false));
      }}
      className="flex flex-col gap-3"
    >
      <p className="m-0 text-fg2">
        Das Konto wird gesperrt und anonymisiert, alle Sitzungen enden. Einträge im Aktivitätsprotokoll bleiben erhalten. Das lässt sich nicht rückgängig machen.
      </p>
      <Field label={`Zur Bestätigung den Namen „${user.display_name}“ eingeben`}>
        <TextInput value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" autoFocus />
      </Field>
      {needsPw ? (
        <Field label="Dein Passwort (das Konto hat Verwaltungsrechte)">
          <TextInput type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" />
        </Field>
      ) : null}
      {error ? <ErrorNote message={error} /> : null}
      <div className="flex justify-end gap-2">
        <Button onClick={onClose}>Abbrechen</Button>
        <Button type="submit" variant="danger" busy={busy}>
          Benutzer löschen
        </Button>
      </div>
    </form>
  );
}

export function UsersTab({ roles }: { roles: RolesResponse | undefined }) {
  const users = useApi<{ users: UserRow[]; pending: number }>("/users", 60_000);
  const [mode, setMode] = useState<DialogMode | null>(null);
  const [shown, setShown] = useState<{ name: string; password: string } | null>(null);
  const [del, setDel] = useState<UserRow | null>(null);
  const [lock, setLock] = useState<UserRow | null>(null);
  const [reset, setReset] = useState<UserRow | null>(null);

  const { me } = useAuth();
  const list = users.data?.users;
  const sensitive = roles?.groups.flatMap((g) => g.permissions.filter((p) => p.sensitive).map((p) => p.name)) ?? [];
  const pending = users.data?.pending ?? 0;

  async function act(path: string, ok: string, what: string) {
    try {
      await api.post(path, undefined, { what });
      toast.success(ok);
      await users.reload();
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    }
  }

  async function doReset() {
    const u = reset;
    setReset(null);
    if (!u) return;
    try {
      const r = await api.post<{ initial_password: string }>(`/users/${u.id}/reset-password`, undefined, { what: `Passwort von ${u.display_name} konnte nicht zurückgesetzt werden` });
      setShown({ name: u.display_name, password: r.initial_password });
      await users.reload();
    } catch {
      /* Toast vom API-Client */
    }
  }

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <p className="m-0 text-sm text-fg2">
          {list ? `${list.length} ${list.length === 1 ? "Benutzer" : "Benutzer"}` : ""}
          {pending > 0 ? `, ${pending} ${pending === 1 ? "Konto wartet" : "Konten warten"} auf Freigabe` : ""}
        </p>
        <div className="ml-auto">
          <Button variant="primary" onClick={() => setMode({ kind: "create" })} disabled={!roles}>
            <NavIcon name="plus" />
            Benutzer anlegen
          </Button>
        </div>
      </div>

      {users.error && !list ? (
        <div className="mb-3">
          <ErrorNote message={users.error} />
          <p className="mt-2">
            <Button onClick={() => void users.reload()}>Erneut versuchen</Button>
          </p>
        </div>
      ) : null}

      {!list ? (
        users.error ? null : <Loading what="Benutzer" />
      ) : list.length === 0 ? (
        <Empty title="Noch keine Benutzer">Lege den ersten Benutzer an.</Empty>
      ) : (
        <div className="@container/tbl max-hd:overflow-x-auto">
          <table className="tbl stack-lg dist1024 lg:max-hd:[--col-pad:10px] lg:[--tbl-min:46.5rem] hd:[--tbl-min:61rem]">
            <caption>Benutzer mit Anmeldeart, Rolle, Status, letzter Anmeldung und Aktionen</caption>
            <thead>
              <tr>
                <th scope="col" className="w-[24%] min-w-32"><span className="th-pad">Name</span></th>
                <th scope="col" className="w-[10%] min-w-20"><span className="th-pad">Anmeldeart</span></th>
                <th scope="col" className="w-[16%] min-w-28"><span className="th-pad">Rolle</span></th>
                <th scope="col" className="w-[18%] min-w-32"><span className="th-pad">Status</span></th>
                <th scope="col" className="w-[14%] min-w-24"><span className="th-pad">Zuletzt angemeldet</span></th>
                <th scope="col" className="w-60 min-w-40 hd:w-112 hd:min-w-112"><span className="th-pad">Aktionen</span></th>
              </tr>
            </thead>
            <tbody>
              {list.map((u) => {
                const guard = rowGuard(u, list, me.permissions);
                const reason = guard.remove ?? guard.lock ?? guard.edit;
                return (
                  <tr key={u.id}>
                    <td className="cell-primary">
                      <span className="flex min-w-0 items-center gap-2">
                        <Avatar name={u.display_name} version={u.is_self && u.has_avatar ? 1 : null} size={20} />
                        <span className="min-w-0 truncate font-semibold">{u.display_name}</span>
                        {u.is_self ? <span className="text-xs text-fg3">(du)</span> : null}
                      </span>
                      {u.email ? <span className="block truncate text-xs text-fg3">{u.email}</span> : null}
                      {reason ? <span className="block text-xs text-fg3" data-guard-reason>{reason}.</span> : null}
                    </td>
                    <td data-label="Anmeldeart">{KIND_LABEL[u.auth_kind] ?? u.auth_kind}</td>
                    <td data-label="Rolle">
                      {u.role_title ?? u.role}
                      {u.requested_role ? <span className="block text-xs text-warn">Anbieter wünscht: {roles?.roles.find((r) => r.key === u.requested_role)?.title ?? u.requested_role}</span> : null}
                    </td>
                    <td data-label="Status">
                      <StatusBadge info={STATUS_INFO[u.status] ?? STATUS_INFO.locked} />
                    </td>
                    <td data-label="Zuletzt angemeldet"><RelTime iso={u.last_login_at} /></td>
                    <td className="cell-actions">
                      <ActionCell
                        name={u.display_name}
                        actions={[
                          u.status === "pending" && u.oidc_linked
                            ? { key: "approve", label: "Freigeben", aria: `${u.display_name} freigeben`, icon: "unlock" as const, run: () => setMode({ kind: "approve", user: u }) }
                            : { key: "edit", label: "Bearbeiten", aria: `${u.display_name} bearbeiten`, icon: "edit" as const, run: () => setMode({ kind: "edit", user: u }), disabled: !!guard.edit, why: guard.edit },
                          ...(u.status === "locked"
                            ? [{ key: "unlock", label: "Entsperren", aria: `${u.display_name} entsperren`, icon: "unlock" as const, run: () => void act(`/users/${u.id}/unlock`, `${u.display_name} entsperrt.`, "Entsperren fehlgeschlagen") }]
                            : [{ key: "lock", label: "Sperren", aria: `${u.display_name} sperren`, icon: "lock" as const, run: () => setLock(u), disabled: !!guard.lock || u.status !== "active", why: guard.lock }]),
                          { key: "delete", label: "Löschen", aria: `Benutzer ${u.display_name} löschen`, icon: "trash" as const, run: () => setDel(u), danger: true, disabled: !!guard.remove, why: guard.remove },
                        ]}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <UserDialog
        mode={mode}
        roles={roles}
        onClose={() => setMode(null)}
        onReset={(u) => {
          setMode(null);
          setReset(u);
        }}
        onDone={(r) => {
          setMode(null);
          void users.reload();
          if (r.password) setShown({ name: r.name, password: r.password });
          else toast.success(`${r.name} gespeichert.`);
        }}
      />
      <OneTimePassword name={shown?.name ?? ""} password={shown?.password ?? null} onDone={() => setShown(null)} />
      <DeleteDialog
        user={del}
        sensitive={sensitive}
        onClose={() => setDel(null)}
        onDone={() => {
          toast.success(`${del?.display_name ?? "Benutzer"} gelöscht.`);
          setDel(null);
          void users.reload();
        }}
      />
      <ConfirmDialog
        open={lock !== null}
        danger
        title={`${lock?.display_name ?? ""} sperren?`}
        confirmLabel="Sperren"
        onCancel={() => setLock(null)}
        onConfirm={() => {
          const u = lock;
          setLock(null);
          if (u) void act(`/users/${u.id}/lock`, `${u.display_name} gesperrt.`, "Sperren fehlgeschlagen");
        }}
      >
        Alle Sitzungen des Benutzers enden sofort; eine Anmeldung ist bis zum Entsperren nicht möglich.
      </ConfirmDialog>
      <ConfirmDialog
        open={reset !== null}
        title={`Passwort von ${reset?.display_name ?? ""} zurücksetzen?`}
        confirmLabel="Einmalpasswort erzeugen"
        onCancel={() => setReset(null)}
        onConfirm={() => void doReset()}
      >
        Ein neues Einmalpasswort wird einmalig angezeigt, alle Sitzungen des Benutzers enden. Beim nächsten Anmelden muss er das Passwort ändern.
      </ConfirmDialog>
    </>
  );
}
