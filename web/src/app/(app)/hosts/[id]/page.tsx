"use client";

import { PageHeader } from "@/components/PageHeader";
import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import { HostDetails } from "@/components/HostDetails";
import { HOST_STATUS } from "@/lib/status";
import type { Feed, HistoryRow, Host } from "@/lib/types";
import { HostCves, parseCveFilter } from "@/components/HostCves";
import { StatusBadge } from "@/components/StatusBadge";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Tabs } from "@/components/Tabs";
import { HostPackages } from "@/components/HostPackages";
import { HostContainers } from "@/components/HostContainers";
import { useAuth } from "@/components/AuthProvider";
import { can } from "@/lib/roles";
import { parsePackageFilter } from "@/lib/packages";
import { feedNotice } from "@/lib/hostCves";

const LIVE = ["report_received", "host_status", "host_cve_status"] as const;

const BASE_TABS = [
  { id: "cves", label: "CVEs" },
  { id: "pakete", label: "Pakete" },
] as const;
const CONTAINER_TAB = { id: "container", label: "Container" } as const;
type TabId = (typeof BASE_TABS)[number]["id"] | typeof CONTAINER_TAB.id;

export default function HostDetailPage() {
  const { id } = useParams<{ id: string }>();
  const host = useApi<Host>(`/hosts/${id}`, 30_000, LIVE);
  const params = useSearchParams();
  const initialFilter = parseCveFilter(params.get("cve"));
  // Deep-Link: ?tab=pakete&filter=updates|security|all
  const { me } = useAuth();
  const canContainers = can(me.permissions, "containers.read");
  const wanted = params.get("tab");
  const [tab, setTab] = useState<TabId>(wanted === "pakete" ? "pakete" : wanted === "container" && canContainers ? "container" : "cves");
  const tabs: readonly { id: TabId; label: string }[] = canContainers ? [...BASE_TABS, CONTAINER_TAB] : BASE_TABS;
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
      <PageHeader
        title={h.name}
        badge={<StatusBadge info={info} />}
        count={
          h.status_changed_at ? (
            <span className="text-xs">
              Status geändert <RelTime iso={h.status_changed_at} />
            </span>
          ) : undefined
        }
      />

      {/* Ab 1280 px (Variante side, bei großer Schrift erst ab 60 rem Inhaltsbreite): CVE-Lage links, Host-Details rechts
          (mitlaufend). Sonst stehen die Details aufklappbar unter den Kacheln. */}
      <div className="@container/hd">
      <div className="side:grid side:grid-cols-[minmax(0,1fr)_20rem] side:items-start side:gap-x-6">
      <div className="min-w-0">
      <Tabs label="Bereiche des Hosts" tabs={tabs} value={tab} onChange={setTab}>
        {tab === "cves" ? (
          <HostCves
            host={h}
            initialFilter={initialFilter}
            notice={notice}
            details={
              <details className="mb-2 rounded-xs border border-line bg-surface side:hidden">
                <summary className="flex min-h-8 cursor-pointer items-center px-3 text-sm font-semibold max-md:min-h-11">Host-Details</summary>
                <div className="border-t border-line px-3 py-2">
                  <HostDetails host={h} feeds={feeds.data} notice={notice} />
                </div>
              </details>
            }
          />
        ) : tab === "container" ? (
          <HostContainers hostId={h.id} />
        ) : (
          <HostPackages hostId={h.id} initialFilter={parsePackageFilter(params.get("filter"))} />
        )}
      </Tabs>
      <div>
      <section aria-labelledby="hist" className="mt-6">
        <h2 id="hist" className="mb-2 text-lg font-semibold">
          Verlauf
        </h2>
        {history.error && !history.data ? <ErrorNote message={history.error} /> : null}
        {!history.data ? null : history.data.length === 0 ? (
          <Empty title="Noch keine Daten gemeldet">Der Verlauf füllt sich, sobald der Agent Daten gemeldet hat (täglich um 12:00).</Empty>
        ) : (
          <div className="@container/tbl max-lg:overflow-x-auto">
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
      <aside aria-labelledby="facts" className="no-side:hidden side:sticky side:top-4 side:max-h-[calc(100dvh-2rem)] side:overflow-y-auto rounded-xs border border-line bg-surface p-3">
        <h2 id="facts" className="mb-2 text-base font-semibold">
          Host-Details
        </h2>
        <HostDetails host={h} feeds={feeds.data} notice={notice} />
      </aside>
      </div>
      </div>
    </>
  );
}
