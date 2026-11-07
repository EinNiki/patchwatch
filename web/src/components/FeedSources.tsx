"use client";

import { Fragment, useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import type { Feed, FeedBulk } from "@/lib/types";
import type { StatusInfo } from "@/lib/status";
import { Button, Field, Select, TextInput } from "@/components/Controls";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Dialog } from "@/components/Dialog";
import { NavIcon } from "@/components/Icons";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote } from "@/components/States";
import { writeFailure } from "@/lib/apiErrors";
import { toast } from "@/lib/toastStore";
import { useFeedRuns } from "@/lib/useFeedRuns";
import { isActive, isFailure, latestBySource, summary, type FeedRun } from "@/lib/feedRuns";
import { MiniStepper, RunStepper } from "@/components/RunStepper";
import { StatusBadge } from "@/components/StatusBadge";
import { Mono } from "@/components/Version";

const FEED_STATE: Record<Feed["state"], StatusInfo> = {
  ok: { label: "Aktuell", tone: "ok", icon: "ok", rank: 0 },
  stale: { label: "Veraltet", tone: "warn", icon: "clock", rank: 1 },
  incomplete: { label: "Unvollständig", tone: "warn", icon: "clock", rank: 1 },
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

function size(bytes: number | null): string {
  if (bytes === null) return "";
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

/** Ubuntu im Hybridmodus: je Release der Stand der Massendatei, dazu der stündliche Abruf der API. */
function BulkDetails({ bulk }: { bulk: FeedBulk }) {
  const h = bulk.hourly;
  return (
    <div className="mt-1 flex flex-col gap-1 text-xs">
      {bulk.releases.map((r) => (
        <div key={r.release} className={r.state === "ok" ? "text-fg2" : "text-warn"}>
          <Mono>{r.release}</Mono>: {r.result_text}
          {r.verified_at ? <> · geprüft {absTime(r.verified_at)}</> : null}
          {r.imported_at ? <> · Import {absTime(r.imported_at)}</> : null}
          {r.bytes !== null ? <> · {size(r.bytes)}</> : null}
          {r.status !== null ? <> · Status {r.status}</> : null}
          {r.retry_after_secs ? <> · Retry-After {r.retry_after_secs} s</> : null}
          {r.state === "error" && r.next_attempt_at ? <> · nächster Versuch {absTime(r.next_attempt_at)}</> : null}
        </div>
      ))}
      <div className={h.failures > 0 ? "text-warn" : "text-fg2"}>
        Stündlicher Abruf: {h.last_ok_at ? `zuletzt erfolgreich ${absTime(h.last_ok_at)}` : "noch nicht erfolgreich"} · Seitengröße {h.page_size || "Standard"}
        {h.max_page ? ` (Maximum ${h.max_page})` : ""}
        {h.status !== null ? ` · Status ${h.status}` : ""}
        {h.retry_after_secs ? ` · Retry-After ${h.retry_after_secs} s` : ""}
        {h.next_attempt_at ? ` · nächster Versuch ${absTime(h.next_attempt_at)}` : ""}
      </div>
      {h.error_text ? <div className="text-warn">{h.error_text}</div> : null}
      {h.hint ? <div className="text-warn">{h.hint}</div> : null}
      {!bulk.complete ? <div className="text-warn">Nicht vollständig: nicht für jedes relevante Release liegt ein gültiger, frischer Import vor.</div> : null}
    </div>
  );
}

function message(e: unknown, fallback: string): string {
  return e instanceof ApiError ? e.message : fallback;
}

export function FeedSources() {
  const feeds = useApi<Feed[]>("/feeds", 30_000);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Feed | null>(null);
  const [removing, setRemoving] = useState<Feed | null>(null);
  const deleting = useRef(false);

  const runs = useFeedRuns();
  const latest = latestBySource(runs.runs);
  // Läufe, die in dieser Ansicht aktiv gesehen wurden (nur für diese gibt es Zusammenfassung und Einklappen).
  const [seen, setSeen] = useState<ReadonlySet<number>>(new Set());
  // Eingeklappt (Erfolg nach 5 s oder per Hand) bzw. von Hand aufgeklappt.
  const [closed, setClosed] = useState<ReadonlySet<number>>(new Set());
  const [opened, setOpened] = useState<ReadonlySet<number>>(new Set());
  const [backoff, setBackoff] = useState<{ feed: Feed; failures: number; next: string | null } | null>(null);
  const [starting, setStarting] = useState<ReadonlySet<string>>(new Set());
  const [allBusy, setAllBusy] = useState(false);
  const done = useRef(new Set<number>());
  const labels = useRef(new Map<string, string>());
  useEffect(() => {
    for (const f of feeds.data ?? []) labels.current.set(f.source, f.label);
  }, [feeds.data]);
  const reloadFeeds = feeds.reload;
  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = [];
    const newlySeen: number[] = [];
    let finished = false;
    for (const r of runs.runs) {
      if (isActive(r)) {
        if (!seen.has(r.id)) newlySeen.push(r.id);
        continue;
      }
      if (!seen.has(r.id) || done.current.has(r.id)) continue;
      done.current.add(r.id);
      finished = true;
      const name = labels.current.get(r.source) ?? r.source;
      if (r.status === "ok" || r.status === "not_modified") {
        toast.success(summary(name, r));
        timers.push(setTimeout(() => setClosed((c) => new Set(c).add(r.id)), 5000));
      } else if (r.status === "incomplete") {
        toast.warning(`${name}: nur teilweise abgerufen.`);
      } else if (isFailure(r)) {
        toast.error(`${name}: Abruf fehlgeschlagen${r.error ? `: ${r.error}` : "."}`);
      }
    }
    // Asynchron gesetzt (kein setState direkt im Effekt).
    if (newlySeen.length) timers.push(setTimeout(() => setSeen((s) => new Set([...s, ...newlySeen])), 0));
    if (finished) void reloadFeeds();
    // Nur der 0-ms-Timer wird aufgeräumt; die 5-s-Timer laufen weiter, auch wenn sich die Läufe ändern.
    return undefined;
  }, [runs.runs, seen, reloadFeeds]);

  /** Sichtbar: aktiv, Fehlschlag bis zum Schließen, Erfolg bis 5 s nach Ende; per Hand umschaltbar. */
  function expanded(r: FeedRun | undefined): boolean {
    if (!r) return false;
    if (opened.has(r.id)) return !closed.has(r.id);
    if (isActive(r)) return true;
    if (closed.has(r.id)) return false;
    return isFailure(r) || r.status === "incomplete" || seen.has(r.id);
  }
  function toggleRun(r: FeedRun) {
    if (expanded(r)) setClosed((c) => new Set(c).add(r.id));
    else {
      setClosed((c) => {
        const n = new Set(c);
        n.delete(r.id);
        return n;
      });
      setOpened((o) => new Set(o).add(r.id));
    }
  }

  async function runOne(f: Feed, confirm = false) {
    if (starting.has(f.source)) return;
    setStarting((s) => new Set(s).add(f.source));
    try {
      const r = await api.post<{ run: FeedRun }>(`/feeds/${f.source}/run`, confirm ? { confirm: true } : undefined, { silent: true });
      // Gleich als gesehen markieren: auch ein sehr schneller Lauf zeigt dann Zusammenfassung.
      if (r?.run) setSeen((s) => new Set(s).add(r.run.id));
      await runs.reload();
    } catch (e) {
      if (!(e instanceof ApiError)) return;
      const code = typeof e.data?.code === "string" ? e.data.code : "";
      if (e.status === 409 && code === "running") {
        // Es läuft schon einer: an ihn anhängen statt Fehler zu zeigen.
        const id = typeof e.data?.run_id === "number" ? e.data.run_id : null;
        if (id !== null) setSeen((s) => new Set(s).add(id));
        toast.info(`${f.label}: Ein Abruf läuft bereits. Der Fortschritt wird angezeigt.`);
        await runs.reload();
      } else if (e.status === 428 && code === "backoff") {
        setBackoff({ feed: f, failures: Number(e.data?.failures ?? 0), next: typeof e.data?.next_attempt_at === "string" ? e.data.next_attempt_at : null });
      } else if (e.status === 429) {
        toast.warning(e.retryAfter ? `${f.label}: ${e.message} Nächster Versuch in ${e.retryAfter} s möglich.` : `${f.label}: ${e.message}`);
      } else {
        toast.error(writeFailure(`${f.label}: Abruf konnte nicht gestartet werden`, e.status, e.message, e.retryAfter));
      }
    } finally {
      setStarting((s) => {
        const n = new Set(s);
        n.delete(f.source);
        return n;
      });
    }
  }

  async function refreshAll() {
    if (allBusy) return;
    setAllBusy(true);
    try {
      const r = await api.post<{ runs?: { run_id: number }[]; running?: { run_id: number }[]; skipped?: { source: string }[] }>("/feeds/refresh", undefined, { silent: true });
      const ids = [...(r?.runs ?? []), ...(r?.running ?? [])].map((x) => x.run_id);
      setSeen((s) => new Set([...s, ...ids]));
      const n = r?.runs?.length ?? 0;
      if (n > 0) toast.info(`${n} ${n === 1 ? "Quelle wird" : "Quellen werden"} nacheinander abgerufen.`);
      if ((r?.running?.length ?? 0) > 0) toast.info("Ein Teil der Abrufe läuft bereits; der Fortschritt wird angezeigt.");
      const sk = r?.skipped?.length ?? 0;
      if (sk > 0) toast.warning(`${sk} ${sk === 1 ? "Quelle wurde" : "Quellen wurden"} übersprungen (zu kurz nach dem letzten Abruf oder im Wartezustand nach Fehlern).`);
      await runs.reload();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        const ids = Array.isArray(e.data?.running) ? (e.data.running as { run_id?: number }[]).map((x) => x.run_id).filter((x): x is number => typeof x === "number") : [];
        setSeen((s) => new Set([...s, ...ids]));
        toast.info("Ein Abruf läuft bereits. Der Fortschritt wird angezeigt.");
        await runs.reload();
      } else if (e instanceof ApiError) toast.error(writeFailure("Abruf konnte nicht gestartet werden", e.status, e.message, e.retryAfter));
    } finally {
      setAllBusy(false);
    }
  }

  async function toggle(f: Feed) {
    try {
      await api.put(`/feeds/${f.source}`, { enabled: !f.enabled }, { what: `${f.label} konnte nicht geändert werden` });
      toast.success(`${f.label} ${f.enabled ? "deaktiviert" : "aktiviert"}.`);
      await feeds.reload();
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    }
  }

  async function remove() {
    if (!removing || deleting.current) return;
    deleting.current = true;
    try {
      await api.del(`/feeds/${removing.source}`, { what: `${removing.label} konnte nicht gelöscht werden` });
      toast.success(`${removing.label} gelöscht.`);
      setRemoving(null);
      await feeds.reload();
    } catch {
      setRemoving(null);
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
        <Button className={BTN} onClick={() => void refreshAll()} busy={allBusy} disabled={runs.runs.some(isActive)}>
          Alle abrufen
        </Button>
        <Button className={BTN} variant="primary" onClick={() => setAdding(true)} >
          <NavIcon name="plus" />
          Quelle hinzufügen
        </Button>
      </div>
      {feeds.error && !feeds.data ? <ErrorNote message={feeds.error} /> : null}
      {!feeds.data ? null : feeds.data.length === 0 ? (
        <Empty title="Keine CVE-Quelle eingerichtet">Füge eine Quelle hinzu oder setze <Mono>PATCHWATCH_CVE_SOURCES</Mono> in der Server-Konfiguration.</Empty>
      ) : (
        <div className="max-lg:overflow-x-auto">
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
                <Fragment key={f.source}>
                <tr>
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
                    <StatusBadge info={FEED_STATE[f.state]} label={(f.state === "stale" || f.state === "incomplete") && f.stale_since ? `${f.state === "stale" ? "Veraltet" : "Unvollständig"} seit ${absTime(f.stale_since)}` : undefined} />
                    {latest.get(f.source) ? <MiniStepper run={latest.get(f.source)!} open={expanded(latest.get(f.source))} onToggle={() => toggleRun(latest.get(f.source)!)} /> : null}
                  </td>
                  <td data-label="Letzter Erfolg">
                    <RelTime iso={f.last_success_at} />
                    {f.last_success_at ? <div className="text-xs text-fg3 max-md:hidden">{absTime(f.last_success_at)}</div> : null}
                  </td>
                  <td data-label="Intervall" className="whitespace-nowrap">
                    alle {f.interval_minutes} Min.
                  </td>
                  <td className={`max-w-[24rem] max-md:max-w-none ${f.last_error || f.backfill || f.bulk ? "" : "max-md:hidden"}`}>
                    {f.backfill ? <div className="text-warn">{f.backfill.progress}</div> : null}
                    {f.bulk ? <BulkDetails bulk={f.bulk} /> : null}
                    {f.enabled && f.next_attempt_at ? <div className="text-xs text-fg3">Nächster Versuch: {absTime(f.next_attempt_at)}</div> : null}
                    {f.last_error ? (
                      <span className="text-warn">
                        {f.error_text ?? f.last_error}
                        {(f.failed_runs ?? f.consecutive_failures) > 0 ? <span className="text-fg3"> ({f.failed_runs ?? f.consecutive_failures}× in Folge)</span> : null}
                      </span>
                    ) : f.backfill || f.bulk ? null : (
                      <span className="text-fg3">–</span>
                    )}
                  </td>
                  <td>
                    <div className="flex flex-wrap gap-2">
                      <Button className={BTN} onClick={() => void runOne(f)} busy={starting.has(f.source) || isActive(latest.get(f.source) ?? { status: "ok" })} disabled={!f.enabled} aria-label={`${f.label} jetzt abrufen`}>
                        Jetzt abrufen
                      </Button>
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
                {expanded(latest.get(f.source)) ? (
                  <tr className="run-row">
                    <td colSpan={6}>
                      <RunStepper run={latest.get(f.source)!} label={f.label} onRetry={() => void runOne(f)} onClose={() => toggleRun(latest.get(f.source)!)} />
                    </td>
                  </tr>
                ) : null}
                </Fragment>
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
      <ConfirmDialog
        open={backoff !== null}
        title={`${backoff?.feed.label ?? "Quelle"} trotzdem abrufen?`}
        confirmLabel="Trotzdem abrufen"
        onConfirm={() => {
          const b = backoff;
          setBackoff(null);
          if (b) void runOne(b.feed, true);
        }}
        onCancel={() => setBackoff(null)}
      >
        Die Quelle ist nach {backoff?.failures ?? 0} Fehlversuchen in Wartezeit{backoff?.next ? ` (nächster automatischer Versuch ${absTime(backoff.next)})` : ""}. Ein zusätzlicher Abruf belastet den Server der Quelle und kann das Limit verlängern. Von Hand ist nur ein Versuch alle 5 Minuten erlaubt.
      </ConfirmDialog>
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
      }, { silent: true });
      toast.success(`${label.trim() || TYPE_TITLE[type]} hinzugefügt.`);
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
      await api.put(`/feeds/${feed.source}`, body, { silent: true });
      toast.success("Änderung gespeichert.");
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
