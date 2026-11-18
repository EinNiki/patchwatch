"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Button, TextInput } from "@/components/Controls";
import { PageHeader } from "@/components/PageHeader";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { RelTime } from "@/components/RelTime";
import { useApi } from "@/lib/useApi";
import { softwareStatus, type SoftwareResponse } from "@/lib/software";
import { SoftwareInventories } from "@/components/SoftwareInventories";

const LIVE = ["report_received", "host_cve_status", "feed_run", "software_inventory"] as const;

export default function SoftwarePage() {
  const params = useSearchParams();
  const router = useRouter();
  const query = new URLSearchParams();
  for (const key of ["q", "host_id", "kind", "offset"]) {
    const value = params.get(key);
    if (value) query.set(key, value);
  }
  const inventory = useApi<SoftwareResponse>(`/software?${query}`, 60_000, LIVE);
  const data = inventory.data;
  const missingHosts = (data?.hosts ?? []).filter((host) =>
    (!params.get("kind") || params.get("kind") === "system") &&
    (!params.get("host_id") || String(host.id) === params.get("host_id")) &&
    (!host.packages_reported_at || host.packages_reported_at !== host.last_report_at));
  function go(offset: number) {
    const next = new URLSearchParams(params.toString());
    if (offset) next.set("offset", String(offset)); else next.delete("offset");
    router.replace(`/software?${next}`, { scroll: false });
  }

  return (
    <>
      <PageHeader title="Software" count={data ? `${data.total} ${data.total === 1 ? "Komponente" : "Komponenten"}` : undefined} />
      <p className="mb-4 max-w-prose text-sm text-fg2">
        Gemeldete Software aus Systempaketen, Anwendungen und Container-Images mit Herkunft, Version und bekannten Sicherheitsmeldungen.
      </p>
      <SoftwareInventories hosts={data?.hosts ?? []} hostFilter={params.get("host_id")} onChanged={inventory.reload} />
      <form className="mb-4 flex flex-wrap items-end gap-2" onSubmit={(event) => {
        event.preventDefault();
        const values = new FormData(event.currentTarget);
        const next = new URLSearchParams();
        for (const key of ["q", "host_id", "kind"]) {
          const value = String(values.get(key) ?? "").trim();
          if (value) next.set(key, value);
        }
        router.replace(`/software?${next}`, { scroll: false });
      }}>
        <label className="flex min-w-0 flex-1 flex-col gap-1 text-sm font-semibold max-md:basis-full">
          Software suchen
          <TextInput key={params.get("q")} name="q" type="search" maxLength={200} defaultValue={params.get("q") ?? ""} placeholder="Paket, Quellpaket oder Host" />
        </label>
        <label className="flex max-w-full flex-col gap-1 text-sm font-semibold">
          Host
          <select key={`${params.get("host_id")}:${data ? "ready" : "loading"}`} name="host_id" disabled={!data} defaultValue={params.get("host_id") ?? ""} className="min-h-8 max-w-full rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm max-md:min-h-11">
            <option value="">Alle Hosts</option>
            {data?.hosts.map((host) => <option key={host.id} value={host.id}>{host.name}</option>)}
          </select>
        </label>
        <label className="flex max-w-full flex-col gap-1 text-sm font-semibold">Art
          <select key={params.get("kind")} name="kind" defaultValue={params.get("kind") ?? ""} className="min-h-8 rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm max-md:min-h-11">
            <option value="">Alle Arten</option><option value="system">Systempakete</option><option value="application">Anwendungen / Projekte</option><option value="container">Container-Images</option><option value="manual">Manuelle Installationen</option>
          </select>
        </label>
        <Button type="submit">Anwenden</Button>
        {query.size > 0 ? <Link className="inline-flex min-h-11 items-center px-2 text-sm" href="/software">Zurücksetzen</Link> : null}
      </form>
      {inventory.error ? <ErrorNote message={inventory.error} /> : null}
      {!data && !inventory.error ? <Loading what="Softwarekomponenten" /> : null}
      {data ? <>
        {missingHosts.length > 0 ? (
          <details className="mb-4 border-l-2 border-unknown bg-sunk px-3 py-2 text-sm">
            <summary className="min-h-8 cursor-pointer font-semibold max-md:min-h-11">Paketdaten fehlen für mindestens einen Host</summary>
            <p className="mt-1 max-w-prose text-fg2">Aktiviere <code>include_packages = true</code> in <code>/etc/patchwatch/agent.toml</code> und fordere unter Agents neue Daten an. Ältere Paketlisten sind als veraltet markiert.</p>
            <ul className="mt-2 list-inside list-disc">
              {missingHosts.map((h) => <li key={h.id}><Link href={`/hosts/${h.id}`}>{h.name}</Link></li>)}
            </ul>
          </details>
        ) : null}
        <p className="mb-3 text-xs text-fg3">Die Bewertung gilt für die gemeldeten Paketlisten und importierten Software-Stücklisten. Laufende Prozesse werden nicht geprüft; Kernel werden auf der Host-Seite bewertet. Fehlende Meldungen bedeuten keine bestätigte Sicherheit.</p>
        {data.items.length === 0 ? <Empty title={data.total > 0 ? "Keine Pakete auf dieser Seite" : "Keine passenden Softwarepakete"}>
          {data.total > 0 ? <Button onClick={() => go(0)}>Erste Seite</Button> : "Prüfe die Filter und die Paketmeldung der Agents."}
        </Empty> : <div className="@container/tbl overflow-x-auto">
          <table className="tbl stack">
            <caption>Software-Inventar mit Paketversionen und Sicherheitsbewertungen</caption>
            <thead><tr>
              <th scope="col"><span className="th-pad">Software</span></th>
              <th scope="col"><span className="th-pad">Host</span></th>
              <th scope="col"><span className="th-pad">Version</span></th>
              <th scope="col"><span className="th-pad">Update</span></th>
              <th scope="col"><span className="th-pad">Sicherheitslage</span></th>
            </tr></thead>
            <tbody>{data.items.map((item) => <tr key={item.id}>
              <td data-label="Software">
                <span className="mono font-semibold [overflow-wrap:anywhere]">{item.name}</span>
                <span className="mt-0.5 block text-xs text-fg3">{item.context_label ? `${item.ecosystem === "unknown" ? "Ohne Paketkennung" : item.ecosystem} · ${item.context_label}` : `Systempaket · Quelle: ${item.source_name ?? "nicht ermittelt"}`}</span>
                {item.identity ? <span className="mono mt-0.5 block text-xs text-fg3 [overflow-wrap:anywhere]">{item.identity}</span> : null}
                {item.location && item.location !== item.identity ? <span className="mono mt-0.5 block text-xs text-fg3 [overflow-wrap:anywhere]">{item.location}</span> : null}
                {item.purl ? <span className="mono mt-0.5 block text-xs text-fg3 [overflow-wrap:anywhere]">{item.purl}</span> : null}
              </td>
              <td data-label="Host"><Link href={`/hosts/${item.host_id}`}>{item.host_name}</Link><span className="block text-xs text-fg3">Erfasst <RelTime iso={item.last_seen} /></span>{item.stale ? <span className="block text-xs font-semibold text-warn">Paketliste veraltet</span> : null}</td>
              <td data-label="Version" className="min-w-24"><span className="mono [overflow-wrap:anywhere]">{item.version ?? "nicht ermittelt"}</span>{item.source_version && item.source_version !== item.version ? <span className="block text-xs text-fg3">Quellversion <span className="mono">{item.source_version}</span></span> : null}</td>
              <td data-label="Update">{item.candidate ? <><span className="mono [overflow-wrap:anywhere]">{item.candidate}</span>{item.security_update ? <span className="block text-xs font-semibold text-crit">Sicherheitsupdate</span> : null}</> : <span className="text-fg3">Kein Kandidat gemeldet</span>}</td>
              <td data-label="Sicherheitslage">
                <StatusBadge info={softwareStatus(item.status)} />
                {item.findings.length ? <details className="mt-1 text-sm">
                  <summary className="min-h-8 cursor-pointer max-md:min-h-11">{item.findings.length} {item.findings.length === 1 ? "Meldung" : "Meldungen"}</summary>
                  <ul className="mt-2 space-y-3">{item.findings.map((finding) => <li key={`${finding.source}:${finding.id}`}>
                    {finding.url ? <a className="mono" href={finding.url} target="_blank" rel="noopener noreferrer">{finding.id} <span className="sr-only">(OSV, öffnet in neuem Tab)</span></a> : <Link className="mono" href={`/cves/${encodeURIComponent(finding.id)}`}>{finding.id}</Link>}
                    <span className="ml-2 text-xs text-fg3">{finding.source}</span>
                    <p className="mt-1"><StatusBadge info={softwareStatus(finding.status)} /></p>
                    <p className="mt-1 max-w-prose text-xs text-fg2">{finding.reason}</p>
                  </li>)}</ul>
                </details> : <p className="mt-1 max-w-prose text-xs text-fg3">{item.reason}</p>}
              </td>
            </tr>)}</tbody>
          </table>
        </div>}
        <nav aria-label="Software-Seiten" className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm text-fg3" aria-live="polite">{data.items.length ? `${data.offset + 1}–${data.offset + data.items.length} von ${data.total}` : `0 von ${data.total}`}</span>
          <div className="flex gap-2"><Button disabled={data.offset === 0} onClick={() => go(Math.max(0, data.offset - data.limit))}>Zurück</Button><Button disabled={data.offset + data.limit >= data.total} onClick={() => go(data.offset + data.limit)}>Weiter</Button></div>
        </nav>
      </> : null}
    </>
  );
}
