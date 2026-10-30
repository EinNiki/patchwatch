"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { Host, NewHost } from "@/lib/types";
import { useAuth } from "@/components/AuthProvider";
import { Button, Field, TextInput } from "@/components/Controls";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CopyButton } from "@/components/CopyButton";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";

const NAME_RE = /^[A-Za-z0-9._-]{1,63}$/;

/** Token wird nur einmal angezeigt; der Server speichert ausschließlich den Hash. */
function TokenDialog({ result, onClose }: { result: { name: string; token: string } | null; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (result && !d.open) d.showModal();
    if (!result && d.open) d.close();
  }, [result]);
  const origin = typeof window === "undefined" ? "https://patchwatch.example.org" : window.location.origin;
  const cmd = result ? `PATCHWATCH_TOKEN='${result.token}' sh install.sh --server-url ${origin}` : "";
  return (
    <dialog ref={ref} onCancel={onClose} aria-labelledby="tok-title" className="w-full">
      <h2 id="tok-title" className="mb-2 text-base font-semibold">
        Agent-Token für {result?.name}
      </h2>
      <p className="mb-3 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
        Dieser Token wird nur jetzt angezeigt. Der Server speichert nur einen Hash und kann ihn nicht erneut anzeigen.
      </p>
      <p className="mb-1 text-[12px] font-semibold text-fg2">Token</p>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <code className="min-w-0 flex-1 break-all border border-line bg-sunk px-2 py-1">{result?.token}</code>
        <CopyButton text={result?.token ?? ""} />
      </div>
      <p className="mb-1 text-[12px] font-semibold text-fg2">Installation auf dem Host (als root, mit install.sh aus dem Release)</p>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <code className="min-w-0 flex-1 break-all border border-line bg-sunk px-2 py-1">{cmd}</code>
        <CopyButton text={cmd} label="Befehl kopieren" />
      </div>
      <div className="flex justify-end">
        <Button variant="primary" onClick={onClose}>
          Fertig, Token gesichert
        </Button>
      </div>
    </dialog>
  );
}

export default function SettingsPage() {
  const { me, logout } = useAuth();
  const hosts = useApi<Host[]>("/hosts", 60_000);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState<{ name: string; token: string } | null>(null);
  const [confirm, setConfirm] = useState<{ kind: "rotate" | "delete"; host: Host } | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    const n = name.trim();
    if (!NAME_RE.test(n)) {
      setError("Name: 1–63 Zeichen aus A–Z, a–z, 0–9, Punkt, Unterstrich und Bindestrich.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<NewHost>("/hosts", { name: n });
      setShown({ name: r.name, token: r.token });
      setName("");
      await hosts.reload();
    } catch (err) {
      setError(err instanceof ApiError && err.status === 409 ? "Ein Host mit diesem Namen existiert bereits." : err instanceof Error ? err.message : "Host konnte nicht angelegt werden.");
    } finally {
      setBusy(false);
    }
  }

  async function runConfirmed() {
    if (!confirm) return;
    const { kind, host } = confirm;
    setConfirm(null);
    setError(null);
    try {
      if (kind === "rotate") {
        const r = await api.post<{ id: number; token: string }>(`/hosts/${host.id}/rotate-token`);
        setShown({ name: host.name, token: r.token });
      } else {
        await api.del(`/hosts/${host.id}`);
      }
      await hosts.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Aktion fehlgeschlagen.");
    }
  }

  return (
    <>
      <h1 className="mb-4 text-xl font-semibold">Einstellungen</h1>

      <section aria-labelledby="hosts-h" className="mb-8">
        <h2 id="hosts-h" className="mb-2 text-base font-semibold">
          Hosts und Agent-Tokens
        </h2>
        <form onSubmit={(e) => void create(e)} className="mb-3 flex flex-wrap items-end gap-3">
          <Field label="Neuer Host (Name)">
            <TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="web1" className="w-56" maxLength={63} autoComplete="off" />
          </Field>
          <Button type="submit" variant="primary" disabled={busy || !name.trim()}>
            Host anlegen
          </Button>
        </form>
        {error ? <ErrorNote message={error} /> : null}

        {hosts.error && !hosts.data ? <ErrorNote message={hosts.error} /> : null}
        {!hosts.data ? (
          <Loading what="Hosts" />
        ) : hosts.data.length === 0 ? (
          <Empty title="Noch keine Hosts">Lege oben einen Host an. Der Token erscheint einmalig und wird bei der Agent-Installation benötigt.</Empty>
        ) : (
          <div className="overflow-x-auto border border-line">
            <table className="tbl stack">
              <caption>Angelegte Hosts mit Token-Verwaltung</caption>
              <thead>
                <tr>
                  <th scope="col"><span className="th-pad">Name</span></th>
                  <th scope="col"><span className="th-pad">Hostname laut Agent</span></th>
                  <th scope="col"><span className="th-pad">Letzter Report</span></th>
                  <th scope="col"><span className="th-pad">Aktionen</span></th>
                </tr>
              </thead>
              <tbody>
                {hosts.data.map((h) => (
                  <tr key={h.id}>
                    <td data-label="Name">
                      <Link href={`/hosts/${h.id}`} className="font-semibold">
                        {h.name}
                      </Link>
                    </td>
                    <td data-label="Hostname">{h.hostname ? <Mono>{h.hostname}</Mono> : <span className="text-fg3">noch kein Report</span>}</td>
                    <td data-label="Letzter Report">
                      <RelTime iso={h.last_report_at} />
                    </td>
                    <td data-label="Aktionen">
                      <div className="flex flex-wrap gap-2">
                        <Button onClick={() => setConfirm({ kind: "rotate", host: h })} aria-label={`Token von ${h.name} erneuern`}>
                          Token erneuern
                        </Button>
                        <Button variant="danger" onClick={() => setConfirm({ kind: "delete", host: h })} aria-label={`Host ${h.name} löschen`}>
                          Löschen
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section aria-labelledby="notify-h" className="mb-8 max-w-prose">
        <h2 id="notify-h" className="mb-2 text-base font-semibold">
          Benachrichtigungen
        </h2>
        <p className="text-fg2">
          ntfy, Tageszusammenfassung, Zeitzone und die 26-Stunden-Schwelle für „Meldet sich nicht“ werden in der Server-Konfiguration gesetzt
          (<Mono>PATCHWATCH_NTFY_URL</Mono>, <Mono>PATCHWATCH_NTFY_TOPIC</Mono>, <Mono>PATCHWATCH_DAILY_SUMMARY_TIME</Mono>,{" "}
          <Mono>PATCHWATCH_STALE_AFTER_HOURS</Mono>). Statuswechsel eines Hosts werden sofort gemeldet. Proxmox-Kernel mit unbekannter
          CVE-Lage lösen bewusst keinen Alarm aus.
        </p>
      </section>

      <section aria-labelledby="acct-h" className="max-w-prose">
        <h2 id="acct-h" className="mb-2 text-base font-semibold">
          Konto
        </h2>
        <p className="mb-3 text-fg2">
          Angemeldet als <Mono>{me.username}</Mono>. Das Passwort ändern Sie auf dem Server mit <Mono>patchwatch-server create-admin {me.username}</Mono>.
        </p>
        <Button onClick={() => void logout()}>Abmelden</Button>
      </section>

      <TokenDialog result={shown} onClose={() => setShown(null)} />
      <ConfirmDialog
        open={confirm !== null}
        danger
        title={confirm?.kind === "delete" ? `Host ${confirm.host.name} löschen?` : `Token von ${confirm?.host.name} erneuern?`}
        confirmLabel={confirm?.kind === "delete" ? "Host löschen" : "Token erneuern"}
        onConfirm={() => void runConfirmed()}
        onCancel={() => setConfirm(null)}
      >
        {confirm?.kind === "delete"
          ? "Der Host mit seinem Verlauf und allen CVE-Bewertungen wird entfernt. Das lässt sich nicht rückgängig machen."
          : "Der bisherige Token wird sofort ungültig. Der Agent muss mit dem neuen Token neu eingerichtet werden."}
      </ConfirmDialog>
    </>
  );
}
