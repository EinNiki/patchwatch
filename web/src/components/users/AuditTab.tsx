"use client";

import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { Button, Field, Select, TextInput } from "@/components/Controls";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { absTime } from "@/lib/format";
import { actionLabel, RESULT_LABEL } from "@/lib/roles";
import type { StatusInfo } from "@/lib/status";
import type { AuditEntry } from "@/lib/types";

const PAGE = 50;
const RESULT_INFO: Record<string, StatusInfo> = {
  ok: { rank: 0, tone: "ok", icon: "ok", label: RESULT_LABEL.ok },
  denied: { rank: 0, tone: "warn", icon: "warn", label: RESULT_LABEL.denied },
  failed: { rank: 0, tone: "crit", icon: "crit", label: RESULT_LABEL.failed },
};

/** Aktivitätsprotokoll: Zeit (Europe/Berlin), Benutzer, Ereignis, Ziel, Ergebnis, gekürzte IP. Enthält nie Geheimnisse. */
export function AuditTab() {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [result, setResult] = useState("");
  const [offset, setOffset] = useState(0);
  const qs = new URLSearchParams({ limit: String(PAGE), offset: String(offset) });
  if (action.trim()) qs.set("action", action.trim());
  if (actor.trim()) qs.set("actor", actor.trim());
  if (result) qs.set("result", result);
  const q = useApi<{ entries: AuditEntry[]; total: number }>(`/audit?${qs}`, 30_000, [], undefined, { keepPrevious: true });
  const rows = q.data?.entries;
  const total = q.data?.total ?? 0;
  const reset = () => setOffset(0);

  return (
    <>
      <div className="mb-3 flex flex-wrap items-end gap-2">
        <Field label="Ereignis">
          <TextInput value={action} onChange={(e) => { setAction(e.target.value); reset(); }} placeholder="z. B. user" />
        </Field>
        <Field label="Benutzer">
          <TextInput value={actor} onChange={(e) => { setActor(e.target.value); reset(); }} />
        </Field>
        <Field label="Ergebnis">
          <Select value={result} onChange={(e) => { setResult(e.target.value); reset(); }}>
            <option value="">alle</option>
            <option value="ok">erfolgreich</option>
            <option value="denied">abgelehnt</option>
            <option value="failed">fehlgeschlagen</option>
          </Select>
        </Field>
      </div>
      {q.error && !rows ? <ErrorNote message={q.error} /> : null}
      {!rows ? (
        q.error ? null : <Loading what="Aktivitäten" />
      ) : rows.length === 0 ? (
        <Empty title="Keine Einträge">Für diese Filter gibt es keine Aktivitäten.</Empty>
      ) : (
        <div className="@container/tbl max-hd:overflow-x-auto">
          <table className="tbl stack-lg dist1024 lg:max-hd:[--col-pad:10px] lg:[--tbl-min:46.5rem] hd:[--tbl-min:61rem]">
            <caption>Aktivitätsprotokoll, neueste zuerst (Zeiten in Europe/Berlin, IP-Adressen gekürzt)</caption>
            <thead>
              <tr>
                <th scope="col" className="w-[17%] min-w-32"><span className="th-pad">Zeit</span></th>
                <th scope="col" className="w-[16%] min-w-24"><span className="th-pad">Benutzer</span></th>
                <th scope="col" className="w-[25%] min-w-32"><span className="th-pad">Ereignis</span></th>
                <th scope="col" className="w-[17%] min-w-24"><span className="th-pad">Ziel oder Grund</span></th>
                <th scope="col" className="w-[13%] min-w-28"><span className="th-pad">Ergebnis</span></th>
                <th scope="col" className="w-[12%] min-w-24"><span className="th-pad">IP (gekürzt)</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="cell-primary"><time dateTime={r.at}>{absTime(r.at)}</time></td>
                  <td data-label="Benutzer" className="truncate">{r.actor_name}</td>
                  <td data-label="Ereignis">{actionLabel(r.action)}</td>
                  <td data-label="Ziel oder Grund" className="truncate">{r.target ?? "–"}</td>
                  <td data-label="Ergebnis"><StatusBadge info={RESULT_INFO[r.result] ?? RESULT_INFO.failed} /></td>
                  <td data-label="IP (gekürzt)" className="text-fg3">{r.ip || "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rows && total > PAGE ? (
        <nav aria-label="Seiten des Protokolls" className="mt-3 flex items-center gap-2">
          <Button onClick={() => setOffset(Math.max(0, offset - PAGE))} disabled={offset === 0}>Zurück</Button>
          <span className="text-sm text-fg2">{offset + 1}–{Math.min(offset + PAGE, total)} von {total}</span>
          <Button onClick={() => setOffset(offset + PAGE)} disabled={offset + PAGE >= total}>Weiter</Button>
        </nav>
      ) : null}
    </>
  );
}
