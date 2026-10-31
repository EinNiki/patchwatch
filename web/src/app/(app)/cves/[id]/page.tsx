"use client";

import { use } from "react";
import Link from "next/link";
import { useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import { CVE_STATUS } from "@/lib/status";
import type { CveDetail } from "@/lib/types";
import { distroName, DistroChip, Marker } from "@/components/DistroChip";
import { NavIcon } from "@/components/Icons";
import { PageHeader } from "@/components/PageHeader";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { Mono } from "@/components/Version";

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

export default function CveDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const valid = CVE_RE.test(id);
  const d = useApi<CveDetail>(valid ? `/cves/${id}` : null, 60_000, ["host_cve_status", "report_received"]);

  if (!valid) return <ErrorNote message="Ungültige CVE-ID." />;
  if (d.error && !d.data) {
    return (
      <>
        <Back />
        <Empty title="CVE nicht gefunden">
          {d.error}. Prüfe die ID oder beobachte sie über die <Link href="/cves">CVE-Liste</Link>, damit sie abgerufen wird.
        </Empty>
      </>
    );
  }
  if (!d.data) return <Loading what="CVE-Daten" />;

  const { cve, distros, links, sources, hosts, last_change_at } = d.data;
  const mine = distros.filter((x) => x.mine);
  const other = distros.filter((x) => !x.mine);
  return (
    <>
      <Back />
      <PageHeader title={cve.id}>{cve.watched ? <Marker>Watchlist</Marker> : null}</PageHeader>
      <p className="mb-2 max-w-prose text-fg2">{cve.description ?? "Noch nicht in den Feeds. Sobald ein Feed die CVE kennt, erscheinen Beschreibung und Status."}</p>
      {cve.note ? <p className="mb-2 text-accent">Notiz: {cve.note}</p> : null}
      <dl className="mb-6 flex flex-wrap gap-x-8 gap-y-1 text-sm">
        {cve.priority ? (
          <div>
            <dt className="inline text-fg3">Priorität </dt>
            <dd className="inline font-semibold">{cve.priority}</dd>
          </div>
        ) : null}
        <div>
          <dt className="inline text-fg3">Letzte Änderung </dt>
          <dd className="inline">
            <RelTime iso={last_change_at} /> <span className="text-fg3">({absTime(last_change_at)})</span>
          </dd>
        </div>
        {cve.published_at ? (
          <div>
            <dt className="inline text-fg3">Veröffentlicht </dt>
            <dd className="inline">{absTime(cve.published_at)}</dd>
          </div>
        ) : null}
      </dl>

      <section aria-labelledby="dist-h" className="mb-8">
        <h2 id="dist-h" className="mb-2 text-lg font-semibold">
          Distributionen
        </h2>
        {distros.length === 0 ? (
          <Empty title="Keine Quellendaten">Die aktiven Feeds kennen diese CVE (noch) nicht.</Empty>
        ) : (
          <>
            <p className="mb-1 text-xs font-semibold text-fg2">Releases auf deinen Hosts</p>
            <div className="mb-3 flex flex-wrap gap-2">
              {mine.length === 0 ? <span className="text-fg3">Keines der Releases läuft auf einem Host.</span> : mine.map((x) => <DistroChip key={`${x.source}/${x.release}`} d={x} />)}
            </div>
            {other.length > 0 ? (
              <details className="mb-2">
                <summary className="cursor-pointer font-semibold text-fg2">Alle Releases ({other.length} weitere)</summary>
                <div className="mt-2 flex flex-wrap gap-2">
                  {other.map((x) => (
                    <DistroChip key={`${x.source}/${x.release}`} d={x} />
                  ))}
                </div>
              </details>
            ) : null}
          </>
        )}
        {links.length > 0 ? (
          <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1">
            {links.map((l) => (
              <li key={l.source}>
                <a href={l.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
                  Quelle: {distroName(l.source)}
                  <NavIcon name="external" size={13} />
                  <span className="sr-only"> (öffnet in neuem Tab)</span>
                </a>
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <section aria-labelledby="hosts-h" className="mb-8">
        <h2 id="hosts-h" className="mb-2 text-lg font-semibold">
          Betroffene Hosts
        </h2>
        {hosts.length === 0 ? (
          <Empty title="Kein Host betroffen oder bewertet">Für diese CVE liegt keine Bewertung eines Hosts vor.</Empty>
        ) : (
          <div className="overflow-x-auto border border-line">
            <table className="tbl stack">
              <caption>Bewertung der Hosts für {cve.id}</caption>
              <thead>
                <tr>
                  <th scope="col"><span className="th-pad">Host</span></th>
                  <th scope="col"><span className="th-pad">Release</span></th>
                  <th scope="col"><span className="th-pad">Status</span></th>
                  <th scope="col"><span className="th-pad">Begründung</span></th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => (
                  <tr key={h.id}>
                    <td data-label="Host">
                      <Link href={`/hosts/${h.id}`} className="font-semibold">
                        {h.name}
                      </Link>
                    </td>
                    <td data-label="Release">{h.os_codename ? <Mono>{h.os_codename}</Mono> : <span className="text-fg3">–</span>}</td>
                    <td data-label="Status">
                      <StatusBadge info={CVE_STATUS[h.status] ?? CVE_STATUS.unknown} />
                    </td>
                    <td data-label="Begründung" className="max-w-[40rem] text-fg2">
                      {h.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section aria-labelledby="src-h">
        <h2 id="src-h" className="mb-2 text-lg font-semibold">
          Quellenzeilen
        </h2>
        {sources.length === 0 ? (
          <p className="text-fg3">Keine.</p>
        ) : (
          <div className="overflow-x-auto border border-line">
            <table className="tbl stack">
              <caption>Status je Quelle, Release und Paket</caption>
              <thead>
                <tr>
                  <th scope="col"><span className="th-pad">Quelle</span></th>
                  <th scope="col"><span className="th-pad">Release</span></th>
                  <th scope="col"><span className="th-pad">Paket</span></th>
                  <th scope="col"><span className="th-pad">Status</span></th>
                  <th scope="col"><span className="th-pad">Fix-Version</span></th>
                  <th scope="col"><span className="th-pad">Geändert</span></th>
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => {
                  const info = CVE_STATUS[s.status as keyof typeof CVE_STATUS] ?? CVE_STATUS.unknown;
                  return (
                    <tr key={`${s.source}/${s.release}/${s.package}`}>
                      <td data-label="Quelle">{distroName(s.source)}</td>
                      <td data-label="Release"><Mono>{s.release}</Mono></td>
                      <td data-label="Paket"><Mono>{s.package}</Mono></td>
                      <td data-label="Status"><StatusBadge info={info} /></td>
                      <td data-label="Fix-Version">{s.fix_version ? <Mono>{s.fix_version}</Mono> : <span className="text-fg3">–</span>}</td>
                      <td data-label="Geändert"><RelTime iso={s.updated_at} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function Back() {
  return (
    <p className="mb-3">
      <Link href="/cves" className="inline-flex items-center gap-1">
        <span aria-hidden="true">←</span>
        Zurück zu den CVEs
      </Link>
    </p>
  );
}
