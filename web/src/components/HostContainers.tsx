"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { toast } from "@/lib/toastStore";
import { can } from "@/lib/roles";
import { useAuth } from "@/components/AuthProvider";
import { Button } from "@/components/Controls";
import { ContainerVerdict } from "@/components/ContainerVerdict";
import { FilterGroup } from "@/components/FilterGroup";
import { NavIcon, Icon } from "@/components/Icons";
import { SectionHeader } from "@/components/PageHeader";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { FILTER_OPTIONS, dockerNotice, matchesFilter, type ContainerFilter } from "@/lib/containers";
import type { HostContainersResponse } from "@/lib/types";

/** Reiter „Container“ der Host-Seite: Container mit Image, Status und der Bewertung gegen die Registry. Nur Anzeige. */
export function HostContainers({ hostId }: { hostId: number }) {
  const { me } = useAuth();
  const canCheck = can(me.permissions, "containers.check");
  const [filter, setFilter] = useState<ContainerFilter>("all");
  const [busy, setBusy] = useState(false);
  const list = useApi<HostContainersResponse>(`/hosts/${hostId}/containers`, 0, ["report_received"], undefined, { keepPrevious: true });
  const data = list.data;
  const notice = data ? dockerNotice(data.docker) : null;
  const rows = (data?.items ?? []).filter((c) => matchesFilter(c.verdict, filter));

  async function check() {
    setBusy(true);
    try {
      const r = await api.post<{ started: number; skipped_recent: number }>("/containers/check", { host_id: hostId }, { what: "Prüfung konnte nicht angestoßen werden" });
      if (r.started > 0) toast.success("Prüfung angestoßen. Das Ergebnis erscheint in wenigen Minuten.");
      else toast.info("Nichts angestoßen: alle Images wurden in den letzten 5 Minuten geprüft oder sind nicht prüfbar.");
      await list.reload();
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="ctr-h" className="min-w-0">
      <SectionHeader
        id="ctr-h"
        title="Container"
        actions={
          canCheck && data?.docker?.state === "ok" ? (
            <Button onClick={() => void check()} busy={busy} title="Image-Versionen jetzt bei der Registry prüfen">
              {busy ? null : <NavIcon name="refresh" />}
              Jetzt prüfen
            </Button>
          ) : null
        }
      />
      {list.error && !data ? <ErrorNote message={list.error} /> : null}
      {!data ? (
        list.error ? null : <Loading what="Container" />
      ) : notice ? (
        <Empty title={notice.title}>{notice.text}</Empty>
      ) : (
        <>
          <dl className="mb-3 flex flex-wrap gap-x-6 gap-y-1 text-sm" aria-label="Zusammenfassung der Container">
            <div className="flex items-baseline gap-1.5">
              <dt className="text-fg3">Container</dt>
              <dd className="tabular-nums">{data.items.length}</dd>
            </div>
            <div className="flex items-baseline gap-1.5">
              <dt className="text-fg3">mit neuerem Image</dt>
              <dd className="tabular-nums">
                <span className={`inline-flex items-center gap-1 ${data.outdated > 0 ? "font-semibold text-warn" : ""}`}>
                  {data.outdated > 0 ? <Icon name="warn" size={14} /> : null}{data.outdated}
                </span>
              </dd>
            </div>
            {data.docker?.checked_at ? (
              <div className="flex items-baseline gap-1.5">
                <dt className="text-fg3">Gemeldet</dt>
                <dd>
                  <RelTime iso={data.docker.checked_at} />
                </dd>
              </div>
            ) : null}
          </dl>
          <div className="mb-2">
            <FilterGroup label="Containerfilter" options={FILTER_OPTIONS} value={filter} onChange={setFilter} />
          </div>
          {data.items.length === 0 ? (
            <Empty title="Keine Container gemeldet">Docker läuft, hat aber in der letzten Meldung keine Container geliefert.</Empty>
          ) : rows.length === 0 ? (
            <Empty title="Keine Treffer">Für diesen Filter gibt es keine Container.</Empty>
          ) : (
            <div className="@container/tbl max-lg:overflow-x-auto">
              <table className="tbl stack">
                <caption>Container dieses Hosts ({rows.length} von {data.items.length})</caption>
                <thead>
                  <tr>
                    <th scope="col"><span className="th-pad">Container</span></th>
                    <th scope="col"><span className="th-pad">Image</span></th>
                    <th scope="col"><span className="th-pad">Status</span></th>
                    <th scope="col"><span className="th-pad">Prüfung</span></th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((c) => (
                    <tr key={c.name}>
                      <td className="cell-primary">
                        <Mono>{c.name}</Mono>
                        {c.compose_project || c.compose_service ? (
                          <span className="block text-xs text-fg3">
                            Compose: {c.compose_project ?? "–"} / {c.compose_service ?? "–"}
                          </span>
                        ) : null}
                      </td>
                      <td data-label="Image" className="stacked:flex-[1_0_100%]">
                        <Mono>{c.image}</Mono>
                      </td>
                      <td data-label="Status">
                        {c.state}
                        {c.status_text ? <span className="block text-xs text-fg3">{c.status_text}</span> : null}
                      </td>
                      <td data-label="Prüfung" className="stacked:flex-[1_0_100%]">
                        <ContainerVerdict verdict={c.verdict} checkedAt={c.checked_at} command={c.command} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}
