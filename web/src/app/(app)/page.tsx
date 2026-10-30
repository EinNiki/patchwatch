"use client";

import { Suspense, useMemo } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useApi } from "@/lib/useApi";
import type { Feed, Host, HostStatus } from "@/lib/types";
import { HOST_STATUS, HOST_STATUS_ORDER } from "@/lib/status";
import { kernelBase } from "@/lib/format";
import { StatusBadge } from "@/components/StatusBadge";
import { Icon } from "@/components/Icons";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote, Loading } from "@/components/States";
import { Button, TextInput } from "@/components/Controls";
import { feedSummary } from "@/components/FeedStatus";

type SortKey = "name" | "status" | "kernel" | "report" | "updates" | "cve";

const COLUMNS: { key: SortKey; label: string; num?: boolean }[] = [
  { key: "name", label: "Host" },
  { key: "kernel", label: "Distribution / Kernel" },
  { key: "report", label: "Letzter Report" },
  { key: "updates", label: "Updates", num: true },
  { key: "cve", label: "CVE" },
  { key: "status", label: "Status" },
];

function cveWeight(h: Host) {
  return h.cve_vulnerable * 10_000 + h.cve_fix_pending * 100 + h.cve_unknown;
}

const SORTERS: Record<SortKey, (a: Host, b: Host) => number> = {
  name: (a, b) => a.name.localeCompare(b.name, "de", { numeric: true }),
  status: (a, b) => HOST_STATUS[a.status].rank - HOST_STATUS[b.status].rank,
  kernel: (a, b) => (a.running_kernel ?? "").localeCompare(b.running_kernel ?? "", "de", { numeric: true }),
  report: (a, b) => (a.last_report_at ?? "").localeCompare(b.last_report_at ?? ""),
  updates: (a, b) => (a.updates_security ?? 0) * 1000 + (a.updates_pending ?? 0) - ((b.updates_security ?? 0) * 1000 + (b.updates_pending ?? 0)),
  cve: (a, b) => cveWeight(a) - cveWeight(b),
};

function haystack(h: Host) {
  return [h.name, h.hostname, h.pretty_name, h.os_codename, h.running_kernel, h.kernel_package_version].filter(Boolean).join(" ").toLowerCase();
}

function HostsView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const hosts = useApi<Host[]>("/hosts", 30_000);
  const feeds = useApi<Feed[]>("/feeds", 60_000);

  const q = params.get("q") ?? "";
  const status = (params.get("status") ?? "") as HostStatus | "";
  const rebootOnly = params.get("reboot") === "1";
  const sort = (params.get("sort") ?? "status") as SortKey;
  const dir = params.get("dir") === "desc" ? "desc" : "asc";

  function setParam(next: Record<string, string | null>) {
    const p = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(next)) {
      if (v === null || v === "") p.delete(k);
      else p.set(k, v);
    }
    const qs = p.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }

  const all = hosts.data;
  const rows = useMemo(() => {
    if (!all) return [];
    const needle = q.trim().toLowerCase();
    const filtered = all.filter(
      (h) => (!needle || haystack(h).includes(needle)) && (!status || h.status === status) && (!rebootOnly || h.reboot_needed),
    );
    const cmp = SORTERS[sort] ?? SORTERS.status;
    const sorted = [...filtered].sort((a, b) => cmp(a, b) || a.name.localeCompare(b.name, "de", { numeric: true }));
    return dir === "desc" ? sorted.reverse() : sorted;
  }, [all, q, status, rebootOnly, sort, dir]);

  const counts = useMemo(() => {
    const c = new Map<HostStatus, number>();
    for (const h of all ?? []) c.set(h.status, (c.get(h.status) ?? 0) + 1);
    return c;
  }, [all]);

  const feedOk = feedSummary(feeds.data)?.ok ?? false;
  const filtering = Boolean(q || status || rebootOnly);

  if (hosts.error && !all) return <ErrorNote message={hosts.error} />;
  if (!all) return <Loading what="Hosts" />;

  return (
    <>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h1 className="text-xl font-semibold">Hosts</h1>
        <p className="text-fg2" aria-live="polite">
          {filtering ? `${rows.length} von ${all.length}` : all.length} {all.length === 1 ? "Host" : "Hosts"}
        </p>
      </div>

      {all.length === 0 ? (
        <Empty title="Noch keine Hosts angelegt">
          Lege unter <Link href="/settings">Einstellungen</Link> einen Host an und installiere den Agent mit dem angezeigten Token.
          Nach dem ersten Report erscheint der Host hier.
        </Empty>
      ) : (
        <>
          <section aria-label="Verteilung nach Status" className="mb-3 flex flex-wrap gap-2">
            {HOST_STATUS_ORDER.filter((s) => counts.get(s)).map((s) => {
              const active = status === s;
              return (
                <button
                  key={s}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setParam({ status: active ? null : s })}
                  className={`rounded-[2px] border p-0.5 ${active ? "border-accent" : "border-transparent"} max-md:min-h-11`}
                  title={active ? "Filter aufheben" : "Nach diesem Status filtern"}
                >
                  <StatusBadge info={HOST_STATUS[s]} label={`${counts.get(s)} ${HOST_STATUS[s].label}`} />
                </button>
              );
            })}
          </section>

          <form role="search" aria-label="Hosts filtern" onSubmit={(e) => e.preventDefault()} className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2">
            <label className="flex items-center gap-2 text-[12px] font-semibold text-fg2">
              Suche
              <TextInput
                type="search"
                value={q}
                onChange={(e) => setParam({ q: e.target.value })}
                placeholder="Name, Distribution, Kernel"
                className="w-64 max-w-full font-normal"
              />
            </label>
            <label className="flex items-center gap-2 text-[12px] font-semibold text-fg2">
              Status
              <select
                value={status}
                onChange={(e) => setParam({ status: e.target.value })}
                className="min-h-8 rounded-[3px] border border-control bg-sunk px-1.5 text-[13px] font-normal text-fg max-md:min-h-11"
              >
                <option value="">alle</option>
                {HOST_STATUS_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {HOST_STATUS[s].label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" checked={rebootOnly} onChange={(e) => setParam({ reboot: e.target.checked ? "1" : null })} className="size-4 accent-[var(--accent)]" />
              nur Neustart nötig
            </label>
            {filtering ? (
              <Button onClick={() => router.replace(pathname, { scroll: false })}>Filter zurücksetzen</Button>
            ) : null}
          </form>

          {rows.length === 0 ? (
            <Empty title="Kein Host entspricht dem Filter">Passe die Suche an oder setze den Filter zurück.</Empty>
          ) : (
            <div className="overflow-x-auto border border-line">
              <table className="tbl stack">
                <caption>Hosts mit Distribution, Kernel, letztem Report, offenen Updates, CVE-Lage und Status</caption>
                <thead>
                  <tr>
                    {COLUMNS.map((c) => {
                      const active = sort === c.key;
                      return (
                        <th key={c.key} scope="col" className={c.num ? "num" : ""} aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : "none"}>
                          <button type="button" onClick={() => setParam({ sort: c.key, dir: active && dir === "asc" ? "desc" : "asc" })}>
                            {c.label}
                            <span aria-hidden="true" className={active ? "text-accent" : "text-fg3"}>
                              {active ? (dir === "asc" ? "▲" : "▼") : "↕"}
                            </span>
                          </button>
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((h) => (
                    <HostRow key={h.id} h={h} feedOk={feedOk} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </>
  );
}

function HostRow({ h, feedOk }: { h: Host; feedOk: boolean }) {
  const newer = h.newest_kernel && h.running_kernel && h.newest_kernel !== h.running_kernel;
  const stale = h.status === "stale";
  return (
    <tr>
      <td data-label="Host">
        <Link href={`/hosts/${h.id}`} className="font-semibold">
          {h.name}
        </Link>
        {h.is_proxmox ? <span className="ml-2 rounded-[2px] border border-line px-1 text-[11px] text-fg2">Proxmox {h.proxmox_version}</span> : null}
        {h.hostname && h.hostname !== h.name ? <div className="text-[12px] text-fg3">{h.hostname}</div> : null}
      </td>
      <td data-label="Distribution / Kernel">
        <div>{h.pretty_name ?? (h.os_id ? `${h.os_id} ${h.os_version ?? ""}` : "–")}</div>
        <div className="text-[12px]">
          <Mono>{h.running_kernel ? kernelBase(h.running_kernel) : "–"}</Mono>
          {newer ? (
            <span className="ml-1.5 inline-flex items-center gap-1 text-warn" title="Ein neuerer Kernel ist installiert, aber noch nicht gebootet">
              <Icon name="reboot" size={12} />
              <Mono>{kernelBase(h.newest_kernel)}</Mono>
              <span className="sr-only">installiert, Neustart nötig</span>
            </span>
          ) : null}
        </div>
      </td>
      <td data-label="Letzter Report" className={stale ? "text-warn" : ""}>
        <span className="inline-flex items-center gap-1">
          {stale ? <Icon name="clock" size={12} /> : null}
          <RelTime iso={h.last_report_at} />
          {stale ? <span className="sr-only">: meldet sich nicht mehr</span> : null}
        </span>
      </td>
      <td data-label="Updates" className="num">
        {h.updates_pending == null ? (
          <span className="text-fg3">unbekannt</span>
        ) : (
          <>
            <span className={h.updates_pending === 0 ? "text-fg3" : ""}>{h.updates_pending} offen</span>
            {h.updates_security ? <div className="font-semibold text-crit">{h.updates_security} Sicherheit</div> : null}
          </>
        )}
      </td>
      <td data-label="CVE">
        <CveCell h={h} feedOk={feedOk} />
      </td>
      <td data-label="Status">
        <StatusBadge info={HOST_STATUS[h.status]} />
        {h.reboot_needed && h.status !== "reboot_required" ? (
          <div className="mt-1 inline-flex items-center gap-1 text-[12px] text-warn">
            <Icon name="reboot" size={12} /> Neustart nötig
          </div>
        ) : null}
      </td>
    </tr>
  );
}

/** CVE-Lage: nie "grün" bei fehlender Datenlage (Proxmox, Feed veraltet). */
function CveCell({ h, feedOk }: { h: Host; feedOk: boolean }) {
  const parts: React.ReactNode[] = [];
  if (h.cve_vulnerable > 0)
    parts.push(
      <span key="v" className="inline-flex items-center gap-1 font-semibold text-crit">
        <Icon name="crit" size={12} /> {h.cve_vulnerable} verwundbar
      </span>,
    );
  if (h.cve_fix_pending > 0)
    parts.push(
      <span key="p" className="inline-flex items-center gap-1 text-warn">
        <Icon name="warn" size={12} /> {h.cve_fix_pending} Fix angekündigt
      </span>,
    );
  if (h.is_proxmox || h.cve_unknown > 0)
    parts.push(
      <span key="u" className="inline-flex items-center gap-1 text-unknown">
        <Icon name="unknown" size={12} /> {h.is_proxmox ? "manuell prüfen" : `${h.cve_unknown} unbekannt`}
      </span>,
    );
  if (parts.length === 0) {
    if (h.status === "pending") return <span className="text-fg3">–</span>;
    return feedOk ? (
      <span className="inline-flex items-center gap-1 text-fg2">
        <Icon name="ok" size={12} /> keine offenen
      </span>
    ) : (
      <span className="inline-flex items-center gap-1 text-unknown">
        <Icon name="unknown" size={12} /> Feed prüfen
      </span>
    );
  }
  return <div className="flex flex-col gap-0.5">{parts}</div>;
}

export default function HostsPage() {
  return (
    <Suspense fallback={<Loading what="Hosts" />}>
      <HostsView />
    </Suspense>
  );
}
