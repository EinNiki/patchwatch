"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useApi } from "@/lib/useApi";
import { absTime, kernelBase, uptime } from "@/lib/format";
import { HOST_STATUS } from "@/lib/status";
import type { Feed, HistoryRow, Host, UpdateItem } from "@/lib/types";
import { HostCves, parseCveFilter } from "@/components/HostCves";
import { StatusBadge } from "@/components/StatusBadge";
import { Icon } from "@/components/Icons";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { feedNotice } from "@/lib/hostCves";

const LIVE = ["report_received", "host_status", "host_cve_status"] as const;

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-fg3">{label}</dt>
      <dd className="m-0 min-w-0">{children}</dd>
    </>
  );
}

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
  const newer = h.newest_kernel && h.running_kernel && h.newest_kernel !== h.running_kernel;
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

      {/* Die CVE-Lage steht oben und über die volle Breite (zwei Spalten ab 1280 px), damit sie ohne Seitenscroll sichtbar ist. */}
      <HostCves host={h} initialFilter={initialFilter} notice={notice} />

      {/* Ab 1600 px: Updates und Verlauf links, Stand rechts (DOM-Reihenfolge bleibt Stand zuerst). */}
      <div className="wide:grid wide:grid-cols-[minmax(0,1fr)_26rem] wide:gap-x-8">
      <section aria-labelledby="facts" className="mb-6 wide:col-start-2 wide:row-start-1">
        <h2 id="facts" className="mb-2 text-lg font-semibold">
          Stand
        </h2>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 border-y border-line py-3 md:grid-cols-[max-content_1fr_max-content_1fr] wide:grid-cols-[max-content_1fr]">
          <Fact label="Distribution">
            {h.pretty_name ?? "–"} {h.os_codename ? <span className="text-fg3">({h.os_codename})</span> : null}
          </Fact>
          <Fact label="Letzter Report">
            <RelTime iso={h.last_report_at} /> <span className="text-fg3">· {absTime(h.last_report_at)}</span>
          </Fact>
          <Fact label="Laufender Kernel">
            <Mono>{h.running_kernel ?? "–"}</Mono>
          </Fact>
          <Fact label="Uptime">{uptime(h.uptime_seconds)}</Fact>
          <Fact label="Kernel-Paket">
            {h.kernel_package ? (
              <>
                <Mono>{h.kernel_package}</Mono> <Mono className="text-fg2">{h.kernel_package_version}</Mono>
              </>
            ) : (
              <span className="text-fg3">nicht ermittelt</span>
            )}
          </Fact>
          <Fact label="Offene Updates">
            {h.updates_pending == null ? (
              <span className="text-fg3">unbekannt</span>
            ) : (
              <>
                {h.updates_pending ? (
                  <a href="#updates" className="underline">
                    {h.updates_pending} anzeigen
                  </a>
                ) : (
                  h.updates_pending
                )}
                {h.updates_security ? <span className="font-semibold text-crit"> · davon {h.updates_security} Sicherheit</span> : null}
              </>
            )}
          </Fact>
          <Fact label="Neuester Kernel">
            {h.newest_kernel ? (
              <>
                <Mono>{h.newest_kernel}</Mono> <Mono className="text-fg2">{h.newest_kernel_version}</Mono>
              </>
            ) : (
              "–"
            )}
          </Fact>
          <Fact label="Neustart nötig">
            {h.reboot_needed ? (
              <span className="inline-flex flex-wrap items-center gap-x-2 text-warn">
                <Icon name="reboot" /> Ja
                <span className="text-fg2">
                  {newer ? `Kernel ${kernelBase(h.running_kernel)} → ${kernelBase(h.newest_kernel)}` : null}
                  {newer && h.reboot_required_file ? " · " : null}
                  {h.reboot_required_file ? "/var/run/reboot-required vorhanden" : null}
                </span>
              </span>
            ) : (
              "Nein"
            )}
          </Fact>
          {h.is_proxmox ? (
            <Fact label="Proxmox VE">
              <Mono>{h.proxmox_version}</Mono>
            </Fact>
          ) : null}
        </dl>
      </section>

      <div className="min-w-0 wide:col-start-1 wide:row-start-1">
      <UpdatesSection hostId={h.id} pending={h.updates_pending ?? 0} />

      <section aria-labelledby="hist" className="mt-6">
        <h2 id="hist" className="mb-2 text-lg font-semibold">
          Verlauf
        </h2>
        {history.error && !history.data ? <ErrorNote message={history.error} /> : null}
        {!history.data ? null : history.data.length === 0 ? (
          <Empty title="Noch keine Reports">Der Verlauf füllt sich mit dem ersten Report des Agents (täglich um 12:00).</Empty>
        ) : (
          <div className="max-lg:overflow-x-auto">
            <table className="tbl stack">
              <caption>Verlauf der letzten Reports</caption>
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
        <Empty title="Liste nicht verfügbar">Dieser Agent schickt noch keine Paketliste. Mit dem neuesten Agent (erneut install.sh ausführen) erscheint sie nach dem nächsten Report.</Empty>
      ) : items.length === 0 ? (
        <Empty title="Keine offenen Updates">Der letzte Report meldet keine Paket-Updates.</Empty>
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
