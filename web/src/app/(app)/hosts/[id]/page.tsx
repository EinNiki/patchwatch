"use client";

import { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { api } from "@/lib/api";
import { prefetchApi, useApi } from "@/lib/useApi";
import { absTime, kernelBase, uptime } from "@/lib/format";
import { CVE_STATUS, HOST_STATUS } from "@/lib/status";
import type { Feed, HistoryRow, Host, HostCve, UpdateItem } from "@/lib/types";
import { Marker } from "@/components/DistroChip";
import { StatusBadge } from "@/components/StatusBadge";
import { Icon } from "@/components/Icons";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Button } from "@/components/Controls";
import { Linkified } from "@/components/Linkified";
import { feedSummary } from "@/components/FeedStatus";

const PROXMOX_ADVISORIES = "https://forum.proxmox.com/forums/security-advisories.26/";
const CVE_PAGE = 200;
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
  const [cveLimit, setCveLimit] = useState(CVE_PAGE);
  const cves = useApi<HostCve[]>(`/hosts/${id}/cves?limit=${cveLimit}`, 60_000, LIVE);
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
  const feed = feedSummary(feeds.data);

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

      {/* Ab 1600 px: CVE-Bewertung und Verlauf links, Stand rechts (DOM-Reihenfolge bleibt Stand zuerst). */}
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
      <CveSection host={h} cves={cves} limit={cveLimit} onMore={() => setCveLimit(cveLimit + CVE_PAGE * 5)} feedWarning={feed && !feed.ok ? feed.label : null} />

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

function CveSection({
  host,
  cves,
  limit,
  onMore,
  feedWarning,
}: {
  host: Host;
  cves: ReturnType<typeof useApi<HostCve[]>>;
  limit: number;
  onMore: () => void;
  feedWarning: string | null;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  async function toggleReview(c: HostCve, checked: boolean) {
    setBusy(c.cve_id);
    setProblem(null);
    try {
      const path = `/hosts/${host.id}/cves/${c.cve_id}/review`;
      if (checked) await api.put(path);
      else await api.del(path);
      await cves.reload();
    } catch (e) {
      setProblem(e instanceof Error ? e.message : "Speichern fehlgeschlagen");
    } finally {
      setBusy(null);
    }
  }

  // Der Server liefert bereits nach Dringlichkeit sortiert und begrenzt; hier nur noch darstellen.
  const list = cves.data ?? [];
  const total = host.cve_vulnerable + host.cve_fix_pending + host.cve_unknown;
  const more = list.length >= limit;

  return (
    <section aria-labelledby="cve">
      <h2 id="cve" className="mb-2 text-lg font-semibold">
        CVE-Bewertung für den laufenden Kernel
      </h2>
      {host.is_proxmox ? (
        <p role="note" className="mb-3 border-l-4 border-unknown bg-unknown-soft px-3 py-2 text-unknown">
          <strong className="font-semibold">Proxmox-Kernel:</strong> Für -pve-Kernel gibt es keine belastbare CVE-Quelle. Jede Bewertung ist
          unbekannt und muss manuell geprüft werden:{" "}
          <a href={PROXMOX_ADVISORIES} target="_blank" rel="noopener noreferrer">
            Proxmox Security Advisories
          </a>
          . Eine Prüfung gilt nur für den Kernel, bei dem sie gesetzt wurde.
        </p>
      ) : null}
      {feedWarning ? (
        <p role="note" className="mb-3 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
          <strong className="font-semibold">{feedWarning}.</strong> Die Bewertung kann veraltet sein.
        </p>
      ) : null}
      {problem ? <ErrorNote message={problem} /> : null}
      {cves.error && !cves.data ? <ErrorNote message={cves.error} /> : null}
      {!cves.data ? (
        <Loading what="CVE-Bewertungen" />
      ) : list.length === 0 ? (
        <Empty title={host.is_proxmox ? "Keine CVEs zur manuellen Prüfung" : "Keine offenen CVE-Bewertungen"}>
          {host.is_proxmox ? (
            <>
              Setze CVEs auf die <Link href="/cves">Watchlist</Link>, dann erscheinen sie hier als „manuell prüfen“.
            </>
          ) : (
            <>
              Für den laufenden Kernel ist keine CVE verwundbar, angekündigt oder unklar.
              {feedWarning ? " Beachte den Hinweis zum veralteten Feed." : ""}
            </>
          )}
        </Empty>
      ) : (
        <>
          <div className="max-lg:overflow-x-auto">
            <table className="tbl stack">
              <caption>CVE-Bewertungen dieses Hosts mit Status, Begründung und manueller Prüfung</caption>
              <thead>
                <tr>
                  <th scope="col"><span className="th-pad">CVE</span></th>
                  <th scope="col"><span className="th-pad">Status</span></th>
                  <th scope="col"><span className="th-pad">Begründung und Quellen</span></th>
                  <th scope="col"><span className="th-pad">Manuelle Prüfung</span></th>
                </tr>
              </thead>
              <tbody>
                {list.map((c) => (
                  <tr key={c.cve_id}>
                    <td className="cell-primary">
                      <Link href={`/cves/${c.cve_id}`} className="mono font-medium" onPointerEnter={() => prefetchApi(`/cves/${c.cve_id}`)} onFocus={() => prefetchApi(`/cves/${c.cve_id}`)}>
                        {c.cve_id}
                      </Link>
                      {c.watched ? <span className="ml-2 inline-flex align-middle"><Marker>Watchlist</Marker></span> : null}
                      {c.priority ? <div className="text-xs text-fg3">Priorität {c.priority}</div> : null}
                    </td>
                    <td className="cell-status lead">
                      <StatusBadge info={CVE_STATUS[c.status]} label={host.is_proxmox && c.status === "unknown" ? "Unbekannt: manuell prüfen" : undefined} />
                    </td>
                    <td data-label="Begründung" className="max-w-[44rem]">
                      <details>
                        <summary className="cursor-pointer text-fg2">{c.reason.split(/(?<=\.)\s/)[0]}</summary>
                        <div className="mt-2 space-y-2">
                          <p className="break-words">
                            <Linkified text={c.reason} />
                          </p>
                          {c.description ? <p className="text-fg3">{c.description}</p> : null}
                          {c.sources.length > 0 ? (
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="text-left text-fg3">
                                  <th className="pr-3 font-semibold">Quelle</th>
                                  <th className="pr-3 font-semibold">Release</th>
                                  <th className="pr-3 font-semibold">Paket</th>
                                  <th className="pr-3 font-semibold">Status</th>
                                  <th className="font-semibold">Fix-Version</th>
                                </tr>
                              </thead>
                              <tbody>
                                {c.sources.map((s) => (
                                  <tr key={`${s.source}${s.release}${s.package}`}>
                                    <td className="pr-3">{s.source}</td>
                                    <td className="pr-3">{s.release}</td>
                                    <td className="pr-3"><Mono>{s.package}</Mono></td>
                                    <td className="pr-3">{s.status}</td>
                                    <td><Mono>{s.fix_version ?? "–"}</Mono></td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          ) : null}
                          <p className="text-xs text-fg3">Berechnet {absTime(c.computed_at)}</p>
                        </div>
                      </details>
                    </td>
                    <td data-label="Prüfung">
                      {c.status === "unknown" ? (
                        <label className="flex min-h-8 items-start gap-2 py-1 max-md:min-h-11 max-md:items-center">
                          <input
                            type="checkbox"
                            className="mt-0.5 size-4 accent-[var(--accent)] max-md:mt-0 max-md:size-5"
                            checked={Boolean(c.reviewed_at)}
                            disabled={busy === c.cve_id}
                            onChange={(e) => void toggleReview(c, e.target.checked)}
                            aria-label={`${c.cve_id} manuell geprüft`}
                          />
                          <span>
                            {c.reviewed_at ? (
                              <>
                                geprüft am {absTime(c.reviewed_at)}
                                {c.reviewed_by ? <span className="text-fg3"> von {c.reviewed_by}</span> : null}
                              </>
                            ) : (
                              "Manuell geprüft"
                            )}
                          </span>
                        </label>
                      ) : (
                        <span className="text-fg3">–</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 flex flex-wrap items-center gap-3 text-fg2">
            <span aria-live="polite">
              {more ? `Die ${list.length} dringlichsten von mindestens ${Math.max(total, list.length)} Bewertungen` : `${list.length} Bewertungen`}, dringlichste zuerst.
            </span>
            {more ? <Button onClick={onMore}>Weitere laden</Button> : null}
          </p>
        </>
      )}
    </section>
  );
}

/** Liste der offenen Paket-Updates (vom Agent mitgeschickt; Sicherheitsupdates zuerst). */
function UpdatesSection({ hostId, pending }: { hostId: number; pending: number }) {
  const updates = useApi<UpdateItem[] | null>(`/hosts/${hostId}/updates`, 0, ["report_received"]);
  const items = updates.data;
  if (pending === 0 && !items?.length) return null;
  return (
    <section id="updates" aria-labelledby="updates-h" className="mt-6 scroll-mt-4">
      <h2 id="updates-h" className="mb-2 text-lg font-semibold">
        Offene Updates
      </h2>
      {updates.error && !updates.data ? <ErrorNote message={updates.error} /> : null}
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
