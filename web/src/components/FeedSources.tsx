"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import type { Feed } from "@/lib/types";
import type { StatusInfo } from "@/lib/status";
import { Button, Field, Select, TextInput } from "@/components/Controls";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Dialog } from "@/components/Dialog";
import { NavIcon } from "@/components/Icons";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { Mono } from "@/components/Version";

const FEED_STATE: Record<Feed["state"], StatusInfo> = {
  ok: { label: "Aktuell", tone: "ok", icon: "ok", rank: 0 },
  stale: { label: "Veraltet", tone: "warn", icon: "clock", rank: 1 },
  never: { label: "Noch nie abgerufen", tone: "unknown", icon: "unknown", rank: 2 },
  disabled: { label: "Abgeschaltet", tone: "unknown", icon: "unknown", rank: 3 },
};

/** Typen, die sich hinzufügen lassen (keine freien URLs: Endpunkte sind je Typ fest). */
const ADDABLE: { name: string; title: string; text: string }[] = [
  { name: "osv", title: "OSV", text: "Abfrage je Host-Kernelversion bei osv.dev. Reichert nur bereits bekannte CVEs an." },
  { name: "nvd", title: "NVD", text: "Beschreibung und CVSS-Schwere vom NIST für bekannte CVEs. Ohne Schlüssel 5 Anfragen je 30 s, mit Schlüssel 50." },
  { name: "cisa_kev", title: "CISA KEV", text: "Markiert bekannte CVEs, die aktiv ausgenutzt werden. Der Fix-Stand bleibt davon unberührt." },
];

const BTN = "min-w-28";

function message(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

export function FeedSources() {
  const feeds = useApi<Feed[]>("/feeds", 30_000);
  const [note, setNote] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Feed | null>(null);
  const [removing, setRemoving] = useState<Feed | null>(null);

  async function refresh() {
    setProblem(null);
    try {
      await api.post("/feeds/refresh");
      setNote("Abruf gestartet. Die Anzeige aktualisiert sich in einigen Sekunden.");
      setTimeout(() => void feeds.reload(), 5000);
      setTimeout(() => void feeds.reload(), 20_000);
    } catch (e) {
      setProblem(e instanceof ApiError && e.status === 409 ? "Ein Abruf läuft bereits." : "Abruf konnte nicht gestartet werden.");
    }
  }

  async function toggle(f: Feed) {
    setProblem(null);
    try {
      await api.put(`/feeds/${f.source}`, { enabled: !f.enabled });
      await feeds.reload();
    } catch (e) {
      setProblem(message(e, "Quelle konnte nicht geändert werden."));
    }
  }

  async function remove() {
    if (!removing) return;
    try {
      await api.del(`/feeds/${removing.source}`);
      setRemoving(null);
      await feeds.reload();
    } catch (e) {
      setRemoving(null);
      setProblem(message(e, "Quelle konnte nicht entfernt werden."));
    }
  }

  const present = new Set((feeds.data ?? []).map((f) => f.source));
  const addable = ADDABLE.filter((a) => !present.has(a.name));

  return (
    <section id="feeds" aria-labelledby="feeds-h" className="mb-6 scroll-mt-4">
      <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-2">
        <h2 id="feeds-h" className="mr-1 text-lg font-semibold">
          CVE-Quellen
        </h2>
        <Button className={BTN} onClick={() => void refresh()}>
          Jetzt abrufen
        </Button>
        <Button className={BTN} variant="primary" onClick={() => setAdding(true)} disabled={addable.length === 0} title={addable.length === 0 ? "Alle bekannten Quellen sind schon eingerichtet" : undefined}>
          <NavIcon name="plus" />
          Quelle hinzufügen
        </Button>
        <span role="status" className="text-fg2">
          {note}
        </span>
      </div>
      {problem ? <ErrorNote message={problem} /> : null}
      {feeds.error && !feeds.data ? <ErrorNote message={feeds.error} /> : null}
      {!feeds.data ? null : feeds.data.length === 0 ? (
        <Empty title="Keine CVE-Quelle eingerichtet">Füge eine Quelle hinzu oder setze <Mono>PATCHWATCH_CVE_SOURCES</Mono> in der Server-Konfiguration.</Empty>
      ) : (
        <div className="max-xl:overflow-x-auto">
          <table className="tbl stack">
            <caption>Zustand der CVE-Quellen</caption>
            <thead>
              <tr>
                <th scope="col"><span className="th-pad">Quelle</span></th>
                <th scope="col"><span className="th-pad">Zustand</span></th>
                <th scope="col"><span className="th-pad">Letzter erfolgreicher Abruf</span></th>
                <th scope="col"><span className="th-pad">Intervall</span></th>
                <th scope="col"><span className="th-pad">Fehler</span></th>
                <th scope="col"><span className="th-pad">Aktionen</span></th>
              </tr>
            </thead>
            <tbody>
              {feeds.data.map((f) => (
                <tr key={f.source}>
                  <td className="cell-primary">
                    <Mono>{f.source}</Mono>
                    <div className="text-xs text-fg3">
                      {f.kind === "builtin" ? "eingebaut" : f.enrich_only ? "reichert bekannte CVEs an" : "hinzugefügt"}
                      {f.base_url ? " · eigene URL" : ""}
                      {f.secret_set ? " · Schlüssel gesetzt" : ""}
                    </div>
                  </td>
                  <td className="cell-status lead">
                    <StatusBadge info={FEED_STATE[f.state]} label={f.state === "stale" && f.stale_since ? `Veraltet seit ${absTime(f.stale_since)}` : undefined} />
                  </td>
                  <td data-label="Letzter Erfolg">
                    <RelTime iso={f.last_success_at} />
                    {f.last_success_at ? <div className="text-xs text-fg3 max-md:hidden">{absTime(f.last_success_at)}</div> : null}
                  </td>
                  <td data-label="Intervall" className="whitespace-nowrap">
                    alle {f.interval_minutes} Min.
                  </td>
                  <td className={`max-w-[24rem] max-md:max-w-none ${f.last_error ? "" : "max-md:hidden"}`}>
                    {f.last_error ? (
                      <span className="text-warn">
                        {f.last_error} <span className="text-fg3">({f.consecutive_failures}× in Folge)</span>
                      </span>
                    ) : (
                      <span className="text-fg3">–</span>
                    )}
                  </td>
                  <td>
                    <div className="flex flex-wrap gap-2">
                      <Button className={BTN} onClick={() => void toggle(f)} aria-label={`${f.source} ${f.enabled ? "abschalten" : "einschalten"}`}>
                        {f.enabled ? "Abschalten" : "Einschalten"}
                      </Button>
                      {f.takes_secret || f.takes_base_url ? (
                        <Button className={BTN} onClick={() => setEditing(f)} aria-label={`${f.source} bearbeiten`}>
                          Bearbeiten
                        </Button>
                      ) : null}
                      {f.kind === "managed" ? (
                        <Button className={BTN} variant="danger" onClick={() => setRemoving(f)} aria-label={`${f.source} entfernen`}>
                          Entfernen
                        </Button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-2 max-w-[45rem] text-xs text-fg3">
        Das Abruf-Intervall stellst du unter Einstellungen → Zeitpläne ein. Eine abgeschaltete oder ausgefallene Quelle gilt nie als aktuell.
      </p>

      <AddDialog open={adding} addable={addable} onClose={() => setAdding(false)} onDone={() => { setAdding(false); void feeds.reload(); }} />
      <EditDialog feed={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); void feeds.reload(); }} />
      <ConfirmDialog open={removing !== null} danger title={`Quelle ${removing?.source ?? ""} entfernen?`} confirmLabel="Entfernen" onConfirm={() => void remove()} onCancel={() => setRemoving(null)}>
        Die Quelle und ihre gespeicherten Daten werden entfernt, die Hosts werden neu bewertet. Du kannst sie später wieder hinzufügen.
      </ConfirmDialog>
    </section>
  );
}

function AddDialog({ open, addable, onClose, onDone }: { open: boolean; addable: typeof ADDABLE; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const chosen = addable.find((a) => a.name === name) ?? addable[0];

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!chosen) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/feeds", { name: chosen.name, ...(url.trim() ? { base_url: url.trim() } : {}), ...(secret ? { secret } : {}) });
      setName("");
      setUrl("");
      setSecret("");
      onDone();
    } catch (err) {
      setError(message(err, "Quelle konnte nicht hinzugefügt werden."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} title="Quelle hinzufügen" onClose={onClose}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
        <Field label="Typ">
          <Select value={chosen?.name ?? ""} onChange={(e) => setName(e.target.value)}>
            {addable.map((a) => (
              <option key={a.name} value={a.name}>
                {a.title}
              </option>
            ))}
          </Select>
        </Field>
        {chosen ? <p className="text-fg2">{chosen.text}</p> : null}
        {chosen?.name === "nvd" ? (
          <Field label="API-Schlüssel (optional, wird nur geschrieben und verschlüsselt gespeichert)">
            <TextInput type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} maxLength={512} />
          </Field>
        ) : null}
        <Field label="Eigene Basis-URL, z. B. ein Spiegel (optional)">
          <TextInput type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://" maxLength={300} />
        </Field>
        <p className="text-xs text-fg3">Interne Ziele sind nur erlaubt, wenn der Host exakt in der Server-Konfiguration freigegeben ist. Loopback und Link-Local bleiben immer gesperrt.</p>
        {error ? <ErrorNote message={error} /> : null}
        <div className="flex justify-end gap-2">
          <Button className={BTN} onClick={onClose}>
            Abbrechen
          </Button>
          <Button className={BTN} type="submit" variant="primary" disabled={busy || !chosen}>
            {busy ? "Füge hinzu …" : "Hinzufügen"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function EditDialog({ feed, onClose, onDone }: { feed: Feed | null; onClose: () => void; onDone: () => void }) {
  const [url, setUrl] = useState<string | null>(null);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save(body: Record<string, unknown>) {
    if (!feed) return;
    setBusy(true);
    setError(null);
    try {
      await api.put(`/feeds/${feed.source}`, body);
      setUrl(null);
      setSecret("");
      onDone();
    } catch (err) {
      setError(message(err, "Änderung konnte nicht gespeichert werden."));
    } finally {
      setBusy(false);
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const body: Record<string, unknown> = {};
    if (url !== null && url.trim() !== (feed?.base_url ?? "")) {
      if (url.trim()) body.base_url = url.trim();
      else body.clear_base_url = true;
    }
    if (secret) body.secret = secret;
    if (Object.keys(body).length === 0) return onClose();
    void save(body);
  }

  return (
    <Dialog open={feed !== null} title={`Quelle ${feed?.source ?? ""} bearbeiten`} onClose={onClose}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        {feed?.takes_base_url ? (
          <Field label="Eigene Basis-URL (leer = Standard)">
            <TextInput type="url" value={url ?? feed.base_url ?? ""} onChange={(e) => setUrl(e.target.value)} placeholder="https://" maxLength={300} />
          </Field>
        ) : null}
        {feed?.takes_secret ? (
          <>
            <Field label={feed.secret_set ? "API-Schlüssel ersetzen (der alte wird nie angezeigt)" : "API-Schlüssel (wird nur geschrieben)"}>
              <TextInput type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} maxLength={512} />
            </Field>
            {feed.secret_set ? (
              <div>
                <Button className={BTN} variant="danger" onClick={() => void save({ clear_secret: true })} disabled={busy}>
                  Schlüssel entfernen
                </Button>
              </div>
            ) : null}
          </>
        ) : null}
        {error ? <ErrorNote message={error} /> : null}
        <div className="flex justify-end gap-2">
          <Button className={BTN} onClick={onClose}>
            Abbrechen
          </Button>
          <Button className={BTN} type="submit" variant="primary" busy={busy}>
            Speichern
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
