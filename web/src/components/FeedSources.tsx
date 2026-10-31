"use client";

import { useRef, useState } from "react";
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
const ADDABLE: { name: Feed["type"]; title: string; text: string }[] = [
  { name: "debian", title: "Debian", text: "Security-Tracker von Debian (Standardquelle). Bestimmt den Fix-Stand der Debian-Hosts." },
  { name: "ubuntu", title: "Ubuntu", text: "Ubuntu CVE Tracker (Standardquelle). Bestimmt den Fix-Stand der Ubuntu-Hosts." },
  { name: "osv", title: "OSV", text: "Abfrage je Host-Kernelversion bei osv.dev. Reichert nur bereits bekannte CVEs an." },
  { name: "nvd", title: "NVD", text: "Beschreibung und CVSS-Schwere vom NIST für bekannte CVEs. Ohne Schlüssel 5 Anfragen je 30 s, mit Schlüssel 50." },
  { name: "cisa_kev", title: "CISA KEV", text: "Markiert bekannte CVEs, die aktiv ausgenutzt werden. Der Fix-Stand bleibt davon unberührt." },
];

const BTN = "min-w-28";

const TYPE_TITLE: Record<Feed["type"], string> = { debian: "Debian", ubuntu: "Ubuntu", osv: "OSV", nvd: "NVD", cisa_kev: "CISA KEV" };

/** Bekannte Webseiten: die Eingabe gehört zu diesem Typ (nur ein Vorschlag, der Server prüft erneut). */
function suggestType(url: string): Feed["type"] | null {
  let host = "";
  try {
    host = new URL(url.trim()).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (host === "ubuntu.com" || host.endsWith(".ubuntu.com") || host === "people.canonical.com") return "ubuntu";
  if (host === "security-tracker.debian.org") return "debian";
  if (host === "nvd.nist.gov" || host === "services.nvd.nist.gov") return "nvd";
  if (host === "osv.dev" || host === "api.osv.dev") return "osv";
  if (host === "www.cisa.gov" || host === "cisa.gov") return "cisa_kev";
  return null;
}

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
  const deleting = useRef(false);

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
    if (!removing || deleting.current) return;
    deleting.current = true;
    try {
      await api.del(`/feeds/${removing.source}`);
      setRemoving(null);
      await feeds.reload();
    } catch (e) {
      setRemoving(null);
      setProblem(message(e, "Quelle konnte nicht gelöscht werden."));
    } finally {
      deleting.current = false;
    }
  }

  
  return (
    <section id="feeds" aria-labelledby="feeds-h" className="mb-6 scroll-mt-4">
      <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-2">
        <h2 id="feeds-h" className="mr-1 text-lg font-semibold">
          CVE-Quellen
        </h2>
        <Button className={BTN} onClick={() => void refresh()}>
          Jetzt abrufen
        </Button>
        <Button className={BTN} variant="primary" onClick={() => setAdding(true)} >
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
                    <span className="font-semibold">{f.label}</span>
                    <div className="text-xs text-fg3">
                      {TYPE_TITLE[f.type]}
                      {f.ecosystem ? ` ${f.ecosystem}` : ""}
                      {f.kind === "builtin" ? " · Standardquelle" : f.enrich_only ? " · reichert bekannte CVEs an" : ""}
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
                      <Button className={BTN} onClick={() => void toggle(f)} aria-label={`${f.label} ${f.enabled ? "abschalten" : "einschalten"}`}>
                        {f.enabled ? "Abschalten" : "Einschalten"}
                      </Button>
                      <Button className={BTN} onClick={() => setEditing(f)} aria-label={`${f.label} bearbeiten`}>
                        Bearbeiten
                      </Button>
                      <Button className={BTN} variant="danger" onClick={() => setRemoving(f)} aria-label={`${f.label} löschen`}>
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
      <p className="mt-2 max-w-[45rem] text-xs text-fg3">
        Das Abruf-Intervall stellst du unter Einstellungen → Zeitpläne ein. Eine abgeschaltete oder ausgefallene Quelle gilt nie als aktuell.
      </p>

      <AddDialog open={adding} onClose={() => setAdding(false)} onDone={() => { setAdding(false); void feeds.reload(); }} />
      <EditDialog feed={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); void feeds.reload(); }} />
      <ConfirmDialog open={removing !== null} danger title={`Quelle „${removing?.label ?? ""}“ löschen?`} confirmLabel="Löschen" onConfirm={() => void remove()} onCancel={() => setRemoving(null)}>
        Hosts, die auf diese Quelle angewiesen sind, werden auf „unbekannt“ gesetzt. Die gespeicherten Daten der Quelle zählen nicht mehr und werden nach 30 Tagen gelöscht. Du kannst die Quelle jederzeit wieder hinzufügen.
      </ConfirmDialog>
    </section>
  );
}

function AddDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [type, setType] = useState<Feed["type"]>("osv");
  const [label, setLabel] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Synchroner Schutz gegen Doppelklick: setBusy wirkt erst nach dem Rendern.
  const inflight = useRef(false);
  const chosen = ADDABLE.find((a) => a.name === type) ?? ADDABLE[0]!;
  const suggested = url.trim() ? suggestType(url) : null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (inflight.current) return;
    inflight.current = true;
    setBusy(true);
    setError(null);
    try {
      await api.post("/feeds", {
        type,
        label: label.trim() || TYPE_TITLE[type],
        ...(url.trim() ? { base_url: url.trim() } : {}),
        ...(type === "osv" && ecosystem.trim() ? { ecosystem: ecosystem.trim() } : {}),
        ...(type === "nvd" && secret ? { secret } : {}),
      });
      // Erst nach der Serverantwort: Erfolg zeigt die neue Quelle, Fehler legt nichts an.
      setLabel("");
      setEcosystem("");
      setUrl("");
      setSecret("");
      onDone();
    } catch (err) {
      setError(message(err, "Quelle konnte nicht hinzugefügt werden."));
    } finally {
      inflight.current = false;
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} title="Quelle hinzufügen" onClose={onClose}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
        <Field label="Name (1–40 Zeichen, eindeutig)">
          <TextInput value={label} onChange={(e) => setLabel(e.target.value)} placeholder={TYPE_TITLE[type]} maxLength={40} />
        </Field>
        <Field label="Typ">
          <Select value={type} onChange={(e) => setType(e.target.value as Feed["type"])}>
            {ADDABLE.map((a) => (
              <option key={a.name} value={a.name}>
                {a.title}
              </option>
            ))}
          </Select>
        </Field>
        <p className="text-fg2">{chosen.text}</p>
        {type === "osv" ? (
          <Field label="Ökosystem (optional, z. B. Debian:13 oder Ubuntu:24.04)">
            <TextInput value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} maxLength={40} />
          </Field>
        ) : null}
        {type === "nvd" ? (
          <Field label="API-Schlüssel (optional, wird nur geschrieben und verschlüsselt gespeichert)">
            <TextInput type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} maxLength={512} />
          </Field>
        ) : null}
        <Field label="Eigene Basis-URL, z. B. ein Spiegel (optional)">
          <TextInput type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://" maxLength={300} />
        </Field>
        {suggested && suggested !== type ? (
          <p role="status" className="text-warn">
            Diese Adresse gehört zum Typ „{TYPE_TITLE[suggested]}“.{" "}
            <button type="button" className="underline" onClick={() => setType(suggested)}>
              Typ „{TYPE_TITLE[suggested]}“ wählen
            </button>
          </p>
        ) : null}
        <p className="text-xs text-fg3">Interne Ziele sind nur erlaubt, wenn der Host exakt in der Server-Konfiguration freigegeben ist. Loopback und Link-Local bleiben immer gesperrt.</p>
        {error ? <ErrorNote message={error} /> : null}
        <div className="flex justify-end gap-2">
          <Button className={BTN} onClick={onClose}>
            Abbrechen
          </Button>
          <Button className={BTN} type="submit" variant="primary" busy={busy} disabled={busy}>
            Hinzufügen
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function EditDialog({ feed, onClose, onDone }: { feed: Feed | null; onClose: () => void; onDone: () => void }) {
  const [url, setUrl] = useState<string | null>(null);
  const [label, setLabel] = useState<string | null>(null);
  const [eco, setEco] = useState<string | null>(null);
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
      setLabel(null);
      setEco(null);
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
    if (label !== null && label.trim() !== feed?.label) body.label = label.trim();
    if (eco !== null && eco.trim() !== (feed?.ecosystem ?? "")) {
      if (eco.trim()) body.ecosystem = eco.trim();
      else body.clear_ecosystem = true;
    }
    if (url !== null && url.trim() !== (feed?.base_url ?? "")) {
      if (url.trim()) body.base_url = url.trim();
      else body.clear_base_url = true;
    }
    if (secret) body.secret = secret;
    if (Object.keys(body).length === 0) return onClose();
    void save(body);
  }

  return (
    <Dialog open={feed !== null} title={`Quelle „${feed?.label ?? ""}“ bearbeiten`} onClose={onClose}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Name (1–40 Zeichen, eindeutig)">
          <TextInput value={label ?? feed?.label ?? ""} onChange={(e) => setLabel(e.target.value)} maxLength={40} />
        </Field>
        {feed?.takes_ecosystem ? (
          <Field label="Ökosystem (leer = Standard)">
            <TextInput value={eco ?? feed.ecosystem ?? ""} onChange={(e) => setEco(e.target.value)} maxLength={40} />
          </Field>
        ) : null}
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
