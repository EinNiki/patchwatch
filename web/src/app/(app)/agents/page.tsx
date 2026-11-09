"use client";

import { ACTIVE_LABEL, ACTIVE_TIP, DATA_LABEL, DATA_TIP, FETCH_ACTION, FETCH_ALL_ACTION } from "@/lib/terms";
import { useState, useId } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { patchHostRows } from "@/lib/hostsLive";
import { useNow } from "@/lib/useNow";
import type { Host, NewHost, Settings } from "@/lib/types";
import { absTime, relTime } from "@/lib/format";
import { Button, Field, TextInput } from "@/components/Controls";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CodeField } from "@/components/CopyButton";
import { Dialog } from "@/components/Dialog";
import { SET_TOKEN_COMMAND, installCommand } from "@/lib/agentCommands";
import { writeFailure } from "@/lib/apiErrors";
import { toast } from "@/lib/toastStore";
import { Icon, NavIcon } from "@/components/Icons";
import { PageHeader } from "@/components/PageHeader";
import { Popover } from "@/components/Popover";
import { RowMenu } from "@/components/RowMenu";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Mono } from "@/components/Version";

const NAME_RE = /^[A-Za-z0-9._-]{1,63}$/;
/// Der Server vergibt eine Anforderung erneut, wenn nach 10 Minuten kein Report kam.
const NO_ANSWER_MS = 10 * 60 * 1000;
const RELEASE_BASE = "https://github.com/EinNiki/patchwatch/releases/latest/download";
const LIVE_TYPES = ["report_received", "report_requested", "checkin", "host_status"] as const;

function installCmd(): string {
  const origin = typeof window === "undefined" ? "https://patchwatch.example.org" : window.location.origin;
  return installCommand(origin, RELEASE_BASE);
}

function TokenStep({ name, token, rotated, onDone }: { name: string; token: string; rotated?: boolean; onDone: () => void }) {
  const cmd = rotated ? SET_TOKEN_COMMAND : installCmd();
  return (
    <>
      <p className="mb-3 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
        Der Token für <strong>{name}</strong> wird nur jetzt angezeigt. Der Server speichert nur einen Hash und kann ihn nicht erneut anzeigen.
      </p>
      <p className="mb-1 text-xs font-semibold text-fg2">1. Token kopieren</p>
      <CodeField className="mb-4" text={token} label="Token kopieren" />
      <p className="mb-1 text-xs font-semibold text-fg2">2. Auf dem Host ausführen</p>
      <CodeField className="mb-1" text={cmd} label="Befehl kopieren" />
      {rotated ? (
        <p className="mb-4 text-xs text-fg2">
          Der Befehl fragt den neuen Token ohne Anzeige ab (<Mono>--stdin</Mono> oder <Mono>--token-file /pfad</Mono> gehen auch), prüft ihn mit
          einer Testmeldung und schreibt ihn atomar nach <Mono>/etc/patchwatch/token</Mono> (root, 0600). Danach:{" "}
          <Mono>sudo systemctl start patchwatch-agent</Mono>.
        </p>
      ) : (
        <p className="mb-4 text-xs text-fg2">
          Der Installer prüft die SHA256-Summe des Binarys und fragt den Token ab (Eingabe wird nicht angezeigt). Alternativ liest{" "}
          <Mono>--token-file /pfad</Mono> ihn aus einer Datei. Der Token steht danach nur in <Mono>/etc/patchwatch/token</Mono> (root, 0600).
          Später ändern: <Mono>{SET_TOKEN_COMMAND}</Mono>.
        </p>
      )}
      <div className="flex justify-end">
        <Button variant="primary" onClick={onDone}>
          Fertig, Token gesichert
        </Button>
      </div>
    </>
  );
}

function AddDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<NewHost | null>(null);

  function close() {
    setName("");
    setError(null);
    setCreated(null);
    onClose();
  }

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
      setCreated(await api.post<NewHost>("/hosts", { name: n }, { silent: true }));
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError && err.status === 409 ? "Ein Agent mit diesem Namen existiert bereits." : "Agent konnte nicht angelegt werden.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} title={created ? `Agent ${created.name} eingerichtet` : "Agent hinzufügen"} onClose={close} dismissible={!created}>
      {created ? (
        <TokenStep name={created.name} token={created.token} onDone={close} />
      ) : (
        <form onSubmit={(e) => void create(e)}>
          <Field label="Name des Hosts">
            <TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="web1" maxLength={63} autoComplete="off" autoFocus />
          </Field>
          <p className="mb-3 mt-1 text-xs text-fg3">Erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich. Der Name lässt sich später nicht ändern.</p>
          {error ? <div className="mb-3"><ErrorNote message={error} /></div> : null}
          <div className="flex justify-end gap-2">
            <Button onClick={close}>Abbrechen</Button>
            <Button type="submit" variant="primary" disabled={busy || !name.trim()}>
              {busy ? "Lege an …" : "Agent anlegen"}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

/** Zustand einer offenen Anforderung unter „Zuletzt gemeldet“: „wartet auf Agent …“, nach 10 Min. ein Hinweis statt endlosem Warten. */
function WaitState({ h, now }: { h: Host; now: number }) {
  if (!h.report_requested_at) return null;
  const waitedMs = now - new Date(h.report_requested_at).getTime();
  if (waitedMs > NO_ANSWER_MS) {
    return (
      <span className="flex items-center gap-1 text-xs text-warn" title="Läuft der Timer des Agents?">
        <Icon name="warn" />
        Keine Antwort seit <RelTime iso={h.report_requested_at} />
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1 text-xs text-fg2" role="status">
      <Icon name="clock" />
      wartet auf Agent …
    </span>
  );
}

/** Eine ruhige Zeile über der Tabelle: wann melden sich die Agents? Server-Zeitplan, sonst der tägliche Timer des Agents. */
function ScheduleLine({ schedule, now }: { schedule: Settings["report_schedule"] | undefined; now: number }) {
  const link = (
    <Link href="/settings#sched-h" className="underline">
      Einstellungen → Zeitpläne
    </Link>
  );
  if (!schedule) return null;
  if (schedule.mode === "off") {
    return (
      <p className="m-0 mb-2 text-sm text-fg2" data-testid="schedule-line">
        Der Agent meldet täglich um ca. 12:00 (Uhrzeit des Hosts). Der Server-Zeitplan ist unter {link} einstellbar.
      </p>
    );
  }
  const plan = schedule.mode === "interval" ? `alle ${schedule.every_hours} Std.` : `täglich ${schedule.at} (${schedule.tz})`;
  const next = schedule.next_run ? (new Date(schedule.next_run).getTime() <= now + 60_000 ? ", nächster Lauf gleich" : `, nächster Lauf ${relTime(schedule.next_run, now)}`) : "";
  return (
    <p className="m-0 mb-2 text-sm text-fg2" data-testid="schedule-line">
      Server-Zeitplan: {plan}
      {schedule.next_run ? <time dateTime={schedule.next_run} title={absTime(schedule.next_run)}>{next}</time> : null}. Zusätzlich meldet der Agent täglich um ca. 12:00 (Uhrzeit des Hosts). Einstellbar unter {link}.
    </p>
  );
}

/** Info-Symbol neben den Abruf-Knöpfen: die frühere Erklärung unter der Tabelle, jetzt bei Bedarf (Maus, Tastatur, Touch). */
function FetchInfo() {
  return (
    <Popover
      label="Erklärung zu „Daten jetzt abrufen“"
      width={320}
      align="end"
      sheet={false}
      trigger={(t) => (
        <button
          type="button"
          ref={t.ref}
          aria-haspopup={t["aria-haspopup"]}
          aria-expanded={t["aria-expanded"]}
          aria-controls={t["aria-controls"]}
          aria-label="Erklärung zu „Daten jetzt abrufen“"
          title="„Daten jetzt abrufen“ bittet den Agent, beim nächsten Kontakt neue Daten zu senden."
          onClick={t.toggle}
          className="inline-flex size-8 items-center justify-center rounded-full text-fg3 hover:text-fg max-md:size-11"
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
            <circle cx="8" cy="8" r="6.2" />
            <path d="M8 7.2v4M8 4.8v.1" />
          </svg>
        </button>
      )}
    >
      <p className="m-0 text-xs text-fg2">
        „Daten jetzt abrufen“ bittet den Agent, beim nächsten Kontakt (standardmäßig alle 5 Minuten) neue Daten zu senden. Der Server startet nichts auf dem Host:
        Der Agent fragt nur an und bekommt „Daten senden: ja/nein“ zurück.
      </p>
    </Popover>
  );
}

export default function AgentsPage() {
  const hosts = useApi<Host[]>("/hosts", 60_000, LIVE_TYPES, patchHostRows);
  const now = useNow();
  const settings = useApi<Settings>("/settings", 60_000);
  const [adding, setAdding] = useState(false);
  const [shown, setShown] = useState<{ name: string; token: string } | null>(null);
  const [confirm, setConfirm] = useState<{ kind: "rotate" | "delete"; host: Host } | null>(null);
  const [limited, setLimited] = useState<Record<number, number>>({});
  const [busyAll, setBusyAll] = useState(false);
  const [more, setMore] = useState(false);
  const moreId = useId();

  async function request(h: Host) {
    try {
      await api.post(`/hosts/${h.id}/request-report`, undefined, { silent: true });
      setLimited((l) => ({ ...l, [h.id]: 0 }));
      toast.success(`${h.name}: Daten angefordert. Sie treffen innerhalb weniger Minuten ein.`);
      await hosts.reload();
    } catch (e) {
      if (e instanceof ApiError && e.status === 429) {
        setLimited((l) => ({ ...l, [h.id]: Date.now() + (e.retryAfter ?? 60) * 1000 }));
        toast.warning(`Für ${h.name} wurden gerade erst abgerufen. Erneut möglich in ${e.retryAfter ?? 60} Sek.`);
      } else if (e instanceof ApiError) {
        toast.error(writeFailure(`Daten von ${h.name} konnten nicht angefordert werden`, e.status, e.message, e.retryAfter));
      }
    }
  }

  async function requestAll() {
    setBusyAll(true);
    try {
      const r = await api.post<{ requested: number; skipped: number }>("/hosts/request-report", undefined, { what: "Daten konnten nicht angefordert werden" });
      if (r.requested === 0) toast.info("Kein Agent angefragt: alle wurden in der letzten Minute schon angefragt.");
      else toast.success(`${r.requested} ${r.requested === 1 ? "Agent" : "Agents"} angefragt${r.skipped > 0 ? `, ${r.skipped} übersprungen (Wartezeit 1 Min.)` : ""}. Die Daten treffen innerhalb weniger Minuten ein.`);
      await hosts.reload();
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    } finally {
      setBusyAll(false);
    }
  }

  async function runConfirmed() {
    if (!confirm) return;
    const { kind, host } = confirm;
    setConfirm(null);
    try {
      if (kind === "rotate") {
        const r = await api.post<{ id: number; token: string }>(`/hosts/${host.id}/rotate-token`, undefined, { what: `Token von ${host.name} konnte nicht erneuert werden` });
        setShown({ name: host.name, token: r.token });
      } else {
        await api.del(`/hosts/${host.id}`, { what: `${host.name} konnte nicht gelöscht werden` });
        toast.success(`${host.name} gelöscht.`);
      }
      await hosts.reload();
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    }
  }

  const list = hosts.data;
  return (
    <>
      <PageHeader title="Agents" count={list ? `${list.length} ${list.length === 1 ? "Agent" : "Agents"}` : undefined}>
        <Button onClick={() => void requestAll()} disabled={busyAll || !list || list.length === 0}>
          <NavIcon name="refresh" />
          {FETCH_ALL_ACTION}
        </Button>
        <FetchInfo />
        <Button variant="primary" onClick={() => setAdding(true)}>
          <NavIcon name="plus" />
          Agent hinzufügen
        </Button>
      </PageHeader>

      <section aria-labelledby="agent-update" className="mb-3">
        <h2 id="agent-update" className="sr-only">Agent aktualisieren</h2>
        <ScheduleLine schedule={settings.data?.report_schedule} now={now} />
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-fg2">
          <span>Agent aktualisieren:</span>
          <CodeField inline text="sudo patchwatch-agent-update" label="Befehl kopieren" />
        </div>
        <p className="m-0 mt-1 flex flex-wrap items-center gap-x-2 text-sm text-fg3">
          <span>Ältere Agents aktualisierst du einmalig mit dem Installationsbefehl aus „Agent hinzufügen“.</span>
          <button type="button" aria-expanded={more} aria-controls={moreId} onClick={() => setMore(!more)} className="inline-flex min-h-6 items-center px-1 text-accent underline max-md:min-h-11 max-md:min-w-11 max-md:justify-center">
            {more ? "Weniger" : "Mehr"}
          </button>
        </p>
        <p id={moreId} hidden={!more} className="m-0 mt-1 max-w-prose text-xs text-fg3">
          Der Befehl läuft ohne neuen Token; vorhandene Einstellungen bleiben erhalten. Mit <code className="mono">--auto-update</code> prüft der Host danach wöchentlich selbst, ob eine neue Version vorliegt. Server-URL und Token bleiben beim Befehl <code className="mono">sudo patchwatch-agent-update</code> erhalten.
        </p>
      </section>

      {hosts.error && !list ? (
        <div className="mb-3">
          <ErrorNote message={hosts.error} />
          <p className="mt-2"><Button onClick={() => void hosts.reload()}>Erneut versuchen</Button></p>
        </div>
      ) : null}

      {!list ? (
        hosts.error ? null : <Loading what="Agents" />
      ) : list.length === 0 ? (
        <Empty title="Noch kein Agent eingerichtet">
          Lege einen Agent an, kopiere den einmalig angezeigten Token und führe den Installationsbefehl auf dem Host aus.
          <div className="mt-3">
            <Button variant="primary" onClick={() => setAdding(true)}>
              <NavIcon name="plus" />
              Agent hinzufügen
            </Button>
          </div>
        </Empty>
      ) : (
        <div className="max-hd:overflow-x-auto">
          <table className="tbl stack dist md:[--tbl-min:35.5rem] lg:[--tbl-min:45rem] hd:[--tbl-min:55.5rem]">
            <caption>Agents mit Version, Zeitpunkt der letzten Daten und letzter Aktivität</caption>
            <thead>
              <tr>
                <th scope="col" className="w-[13%] min-w-30"><span className="th-pad">Name</span></th>
                <th scope="col" className="w-[17%] min-w-38 md:max-lg:hidden"><span className="th-pad">Hostname laut Agent</span></th>
                <th scope="col" className="w-[21%] min-w-40"><span className="th-pad">Distribution</span></th>
                <th scope="col" className="w-[8%] min-w-18 md:max-hd:hidden"><span className="th-pad">Agent-Version</span></th>
                <th scope="col" className="w-[10%] min-w-24"><span className="th-pad" title={DATA_TIP}>{DATA_LABEL}</span></th>
                <th scope="col" className="w-[10%] min-w-24 md:max-hd:hidden"><span className="th-pad" title={ACTIVE_TIP}>{ACTIVE_LABEL}</span></th>
                <th scope="col" className="num w-[21%] min-w-48"><span className="th-pad">Aktionen</span></th>
              </tr>
            </thead>
            <tbody>
              {list.map((h) => {
                const waiting = h.report_requested_at !== null;
                const coolingDown = (limited[h.id] ?? 0) > now;
                return (
                  <tr key={h.id}>
                    <td className="cell-primary">
                      <Link href={`/hosts/${h.id}`} className="whitespace-nowrap font-semibold">
                        {h.name}
                      </Link>
                    </td>
                    <td data-label="Hostname" className="md:max-lg:hidden">{h.hostname ? <Mono>{h.hostname}</Mono> : <span className="text-fg3">noch keine Daten</span>}</td>
                    <td data-label="Distribution">{h.pretty_name ?? <span className="text-fg3">–</span>}</td>
                    <td data-label="Agent-Version" className="md:max-hd:hidden">{h.agent_version ? <Mono>{h.agent_version}</Mono> : <span className="text-fg3">–</span>}</td>
                    <td data-label={DATA_LABEL}>
                      <RelTime iso={h.last_report_at} />
                      <WaitState h={h} now={now} />
                    </td>
                    <td data-label={ACTIVE_LABEL} className="md:max-hd:hidden"><RelTime iso={h.last_checkin_at} /></td>
                    <td data-label="Aktionen" className="num">
                      <div className="flex items-center justify-end gap-2 max-md:justify-start">
                        <Button className="min-w-0" onClick={() => void request(h)} disabled={waiting || coolingDown} aria-label={`${h.name}: ${FETCH_ACTION}`}>
                          {FETCH_ACTION}
                        </Button>
                        <RowMenu
                          label={`Weitere Aktionen für ${h.name}`}
                          items={[
                            { label: "Token erneuern", aria: `Token erneuern für ${h.name}`, run: () => setConfirm({ kind: "rotate", host: h }) },
                            { label: "Löschen", aria: `Agent ${h.name} löschen`, run: () => setConfirm({ kind: "delete", host: h }), danger: true },
                          ]}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <AddDialog open={adding} onClose={() => setAdding(false)} onCreated={() => void hosts.reload()} />
      <Dialog open={shown !== null} title={`Neuer Token für ${shown?.name ?? ""}`} onClose={() => setShown(null)} dismissible={false}>
        {shown ? <TokenStep name={shown.name} token={shown.token} rotated onDone={() => setShown(null)} /> : null}
      </Dialog>
      <ConfirmDialog
        open={confirm !== null}
        danger
        title={confirm?.kind === "delete" ? `Agent ${confirm.host.name} löschen?` : `Token von ${confirm?.host.name} erneuern?`}
        confirmLabel={confirm?.kind === "delete" ? `${confirm.host.name} löschen` : "Token erneuern"}
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
