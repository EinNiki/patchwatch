"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import { HostDetails } from "@/components/HostDetails";
import { HOST_STATUS } from "@/lib/status";
import type { Feed, HistoryRow, Host, UpdateItem } from "@/lib/types";
import { HostCves, parseCveFilter } from "@/components/HostCves";
import { StatusBadge } from "@/components/StatusBadge";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { feedNotice } from "@/lib/hostCves";

const LIVE = ["report_received", "host_status", "host_cve_status"] as const;

export default function HostDetailPage() {
  const { id } = useParams<{ id: string }>();
  const host = useApi<Host>(`/hosts/${id}`, 30_000, LIVE);
  const initialFilter = parseCveFilter(useSearchParams().get("cve"));
  const history = useApi<HistoryRow[]>(`/hosts/${id}/history?limit=30`, 60_000, LIVE);
  const feeds = useApi<Feed[]>("/feeds", 60_000);

  if (host.error && !host.data) {
    return (
      <>
        <p className="mb-3">
          <Link href="/">← Alle Hosts</Link>
        </p>
        <ErrorNote message={host.error === "nicht gefunden" ? "Dieser Host existiert nicht (mehr)." : host.error} />
      </>
    );
  }
  const h = host.data;
  if (!h) return <Loading what="Hostdaten" />;

  const info = HOST_STATUS[h.status];
  const notice = feedNotice(feeds.data, h.os_id, h.os_codename, h.cve_source_issue ?? null);

  return (
    <>
      <p className="mb-2">
        <Link href="/">← Alle Hosts</Link>
      </p>
      <div className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-2">
        <h1 className="text-xl font-semibold">{h.name}</h1>
        <StatusBadge info={info} />
        {h.status_changed_at ? (
          <span className="text-xs text-fg3">
            Status geändert <RelTime iso={h.status_changed_at} />
          </span>
        ) : null}
      </div>

      {/* Ab 1280 px: CVE-Lage links, Host-Details rechts (mitlaufend). Darunter stehen die Details aufklappbar unter den Kacheln. */}
      <div className="hd:grid hd:grid-cols-[minmax(0,1fr)_20rem] hd:items-start hd:gap-x-6">
      <div className="min-w-0">
      <HostCves
        host={h}
        initialFilter={initialFilter}
        notice={notice}
        details={
          <details className="mb-2 rounded-xs border border-line bg-surface hd:hidden">
            <summary className="flex min-h-8 cursor-pointer items-center px-3 text-sm font-semibold max-md:min-h-11">Host-Details</summary>
            <div className="border-t border-line px-3 py-2">
              <HostDetails host={h} feeds={feeds.data} notice={notice} />
            </div>
          </details>
        }
      />
      <div>
      <UpdatesSection hostId={h.id} pending={h.updates_pending ?? 0} />

      <section aria-labelledby="hist" className="mt-6">
        <h2 id="hist" className="mb-2 text-lg font-semibold">
          Verlauf
        </h2>
        {history.error && !history.data ? <ErrorNote message={history.error} /> : null}
        {!history.data ? null : history.data.length === 0 ? (
          <Empty title="Noch keine Daten gemeldet">Der Verlauf füllt sich, sobald der Agent Daten gemeldet hat (täglich um 12:00).</Empty>
        ) : (
          <div className="max-lg:overflow-x-auto">
            <table className="tbl stack">
              <caption>Verlauf der letzten Datenmeldungen</caption>
              <thead>
                <tr>
                  <th scope="col"><span className="th-pad">Zeitpunkt</span></th>
                  <th scope="col"><span className="th-pad">Laufender Kernel</span></th>
                  <th scope="col" className="num"><span className="th-pad">Updates</span></th>
                  <th scope="col"><span className="th-pad">Neustart</span></th>
                  <th scope="col"><span className="th-pad">Status</span></th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((r) => (
                  <tr key={r.id}>
                    <td className="cell-primary">
                      <time dateTime={r.received_at}>{absTime(r.received_at)}</time>
                    </td>
                    <td data-label="Kernel">
                      <Mono>{r.running_kernel ?? "–"}</Mono>
                    </td>
                    <td data-label="Updates" className="num">
                      {r.updates_pending ?? "–"}
                      {r.updates_security ? <span className="text-crit"> ({r.updates_security} Sicherheit)</span> : null}
                    </td>
                    <td data-label="Neustart">{r.reboot_needed ? "nötig" : <span className="text-fg3">nein</span>}</td>
                    <td className="cell-status lead">
                      <StatusBadge info={HOST_STATUS[r.status]} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      </div>
      </div>
      <aside aria-labelledby="facts" className="max-hd:hidden hd:sticky hd:top-4 hd:max-h-[calc(100dvh-2rem)] hd:overflow-y-auto rounded-xs border border-line bg-surface p-3">
        <h2 id="facts" className="mb-2 text-base font-semibold">
          Host-Details
        </h2>
        <HostDetails host={h} feeds={feeds.data} notice={notice} />
      </aside>
      </div>
    </>
  );
}

/** Liste der offenen Paket-Updates (vom Agent mitgeschickt; Sicherheitsupdates zuerst). */
function UpdatesSection({ hostId, pending }: { hostId: number; pending: number }) {
  const updates = useApi<{ items: UpdateItem[] | null }>(`/hosts/${hostId}/updates`, 0, ["report_received"]);
  const items = updates.data?.items;
  if (pending === 0 && !items?.length) return null;
  return (
    <section id="updates" aria-labelledby="updates-h" className="mt-6 scroll-mt-4">
      <h2 id="updates-h" className="mb-2 text-lg font-semibold">
        Offene Updates
      </h2>
      {updates.error && !updates.data ? <ErrorNote message={updates.error} /> : null}
      {updates.loading ? <Loading what="Updates" /> : null}
      {items === undefined ? null : items === null ? (
        <Empty title="Liste nicht verfügbar">Dieser Agent schickt noch keine Paketliste. Mit dem neuesten Agent (erneut install.sh ausführen) erscheint sie nach der nächsten Datenmeldung.</Empty>
      ) : items.length === 0 ? (
        <Empty title="Keine offenen Updates">Die zuletzt gemeldeten Daten enthalten keine Paket-Updates.</Empty>
      ) : (
        <div className="max-lg:overflow-x-auto">
          <table className="tbl">
            <caption>Pakete mit verfügbarem Update{items.length < pending ? ` (die ersten ${items.length} von ${pending})` : ""}</caption>
            <thead>
              <tr>
                <th scope="col"><span className="th-pad">Paket</span></th>
                <th scope="col"><span className="th-pad">Installiert</span></th>
                <th scope="col"><span className="th-pad">Neu</span></th>
                <th scope="col"><span className="th-pad">Quelle</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((u) => (
                <tr key={u.name}>
                  <td className="cell-primary">
                    <Mono>{u.name}</Mono>
                    {u.security ? <span className="ml-2 text-xs font-semibold text-crit">Sicherheit</span> : null}
                  </td>
                  <td><Mono className="text-fg2">{u.from ?? "neu"}</Mono></td>
                  <td><Mono>{u.to}</Mono></td>
                  <td className="text-fg2">{u.origin}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
