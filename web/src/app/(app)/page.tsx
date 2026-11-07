"use client";

import { Suspense, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { prefetchApi, useApi } from "@/lib/useApi";
import { patchHostRows } from "@/lib/hostsLive";
import type { Feed, Host, HostStatus } from "@/lib/types";
import { HOST_STATUS, HOST_STATUS_ORDER } from "@/lib/status";
import { kernelBase } from "@/lib/format";
import { Uptime } from "@/components/Uptime";
import { StatusBadge } from "@/components/StatusBadge";
import { Marker } from "@/components/DistroChip";
import { Icon, NavIcon } from "@/components/Icons";
import { SortHead } from "@/components/SortHead";
import { TableSkeleton } from "@/components/Skeleton";
import { useFlash } from "@/lib/useFlash";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote } from "@/components/States";
import { Button, TextInput } from "@/components/Controls";
import { feedSummary } from "@/components/FeedStatus";

type SortKey = "name" | "status" | "kernel" | "report" | "updates" | "cve";

/** `cls`: Sichtbarkeit je Breite. Der letzte Report rutscht zwischen 768 und 1439 px unter den Hostnamen, Agent und Uptime kommen ab 1600 px dazu. */
const COLUMNS: { key: SortKey; label: string; num?: boolean; cls?: string }[] = [
  { key: "name", label: "Host" },
  { key: "kernel", label: "Distribution / Kernel" },
  { key: "report", label: "Letzter Report", cls: "md:max-xl:hidden" },
  { key: "updates", label: "Updates", num: true },
  { key: "cve", label: "CVE" },
  { key: "status", label: "Status" },
];

const SORT_LABEL: Record<SortKey, string> = { name: "Host", kernel: "Kernel", report: "Letzter Report", updates: "Updates", cve: "CVE", status: "Status" };

/** Rein clientseitige Kennzahlen aus /hosts; jede ist zugleich ein Filter (URL-Parameter). */
type Kpi = { id: string; label: string; icon: "crit" | "warn" | "reboot" | "unknown" | "clock"; tone: string; count: number; param: Record<string, string> };

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
  const hosts = useApi<Host[]>("/hosts", 30_000, ["report_received", "host_status", "host_cve_status"], patchHostRows);
  const feeds = useApi<Feed[]>("/feeds", 60_000);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const q = params.get("q") ?? "";
  const status = (params.get("status") ?? "") as HostStatus | "";
  const rebootOnly = params.get("reboot") === "1";
  const updatesOnly = params.get("updates") === "1";
  const unknownOnly = params.get("cve") === "unknown";
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
      (h) =>
        (!needle || haystack(h).includes(needle)) &&
        (!status || h.status === status) &&
        (!rebootOnly || h.reboot_needed) &&
        (!updatesOnly || (h.updates_pending ?? 0) > 0) &&
        (!unknownOnly || h.is_proxmox || h.status === "cve_unknown" || h.cve_unknown > 0),
    );
    const cmp = SORTERS[sort] ?? SORTERS.status;
    const sorted = [...filtered].sort((a, b) => cmp(a, b) || a.name.localeCompare(b.name, "de", { numeric: true }));
    return dir === "desc" ? sorted.reverse() : sorted;
  }, [all, q, status, rebootOnly, updatesOnly, unknownOnly, sort, dir]);

  const flashed = useFlash(
    all,
    (h) => h.id,
    (h) => `${h.status}|${h.updates_pending}|${h.updates_security}|${h.cve_vulnerable}|${h.cve_fix_pending}|${h.cve_unknown}|${h.cve_reboot}|${h.cve_fixed}|${h.last_report_at}|${h.running_kernel}`,
  );

  const kpis = useMemo<Kpi[]>(() => {
    const n = (f: (h: Host) => boolean) => (all ?? []).filter(f).length;
    const list: Kpi[] = [
      { id: "vuln", label: "Verwundbar (CVE)", icon: "crit", tone: "text-crit", count: n((h) => h.status === "cve_vulnerable"), param: { status: "cve_vulnerable" } },
      { id: "sec", label: "Sicherheitsupdates", icon: "crit", tone: "text-crit", count: n((h) => h.status === "security_updates"), param: { status: "security_updates" } },
      { id: "updates", label: "Updates offen", icon: "warn", tone: "text-warn", count: n((h) => (h.updates_pending ?? 0) > 0), param: { updates: "1" } },
      { id: "reboot", label: "Neustart nötig", icon: "reboot", tone: "text-warn", count: n((h) => h.reboot_needed), param: { reboot: "1" } },
      { id: "unknown", label: "CVE-Lage unbekannt", icon: "unknown", tone: "text-unknown", count: n((h) => h.is_proxmox || h.status === "cve_unknown" || h.cve_unknown > 0), param: { cve: "unknown" } },
      { id: "stale", label: "Meldet sich nicht", icon: "clock", tone: "text-unknown", count: n((h) => h.status === "stale"), param: { status: "stale" } },
    ];
    return list;
  }, [all]);

  const lastReport = useMemo(() => (all ?? []).reduce<string | null>((m, h) => (h.last_report_at && (!m || h.last_report_at > m) ? h.last_report_at : m), null), [all]);

  const feedOk = feedSummary(feeds.data)?.ok ?? false;
  const activeFilters = [q.trim(), status, rebootOnly, updatesOnly, unknownOnly].filter(Boolean).length;
  const filtering = activeFilters > 0;

  if (hosts.error && !all) return <ErrorNote message={hosts.error} />;
  if (!all) return <TableSkeleton what="Hosts" />;

  const kpiActive = (k: Kpi) => Object.entries(k.param).every(([key, v]) => params.get(key) === v);

  return (
    <>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h1 className="text-xl font-semibold">Hosts</h1>
        <p className="text-sm text-fg3" aria-live="polite">
          {filtering ? `${rows.length} von ${all.length}` : all.length} {all.length === 1 ? "Host" : "Hosts"}
        </p>
      </div>

      {all.length === 0 ? (
        <Empty title="Noch keine Hosts">
          Lege unter <Link href="/agents">Agents</Link> einen Agent an. Nach dem ersten Report erscheint der Host hier.
        </Empty>
      ) : (
        <>
          <section aria-label="Kennzahlen" className="mb-3 grid grid-cols-2 border-y border-line md:grid-cols-3 xl:grid-cols-7">
            {kpis.map((k) => {
              const active = kpiActive(k);
              return (
                <button
                  key={k.id}
                  type="button"
                  aria-pressed={active}
                  disabled={k.count === 0 && !active}
                  onClick={() => setParam(active ? Object.fromEntries(Object.keys(k.param).map((key) => [key, null])) : k.param)}
                  title={active ? "Filter aufheben" : `Nur ${k.label} anzeigen`}
                  className={`flex min-h-11 flex-col items-start gap-0.5 border-l-2 px-3 py-2 text-left first:border-l-0 hover:bg-sunk disabled:cursor-default disabled:opacity-60 disabled:hover:bg-transparent ${
                    active ? "border-accent bg-sunk" : "border-transparent"
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <span className={k.count > 0 ? k.tone : "text-fg3"}>
                      <Icon name={k.icon} size={16} />
                    </span>
                    <span className="mono text-xl font-semibold leading-none">{k.count}</span>
                  </span>
                  <span className="text-xs text-fg2">{k.label}</span>
                </button>
              );
            })}
            <div className="flex min-h-11 flex-col items-start gap-0.5 px-3 py-2">
              <span className="mono text-sm font-semibold leading-[1.25rem]">
                <RelTime iso={lastReport} />
              </span>
              <span className="text-xs text-fg2">zuletzt gemeldet</span>
            </div>
          </section>

          <div className="mb-3 md:hidden">
            <Button aria-expanded={filtersOpen} aria-controls="host-filters" onClick={() => setFiltersOpen((o) => !o)}>
              <NavIcon name="filter" />
              Filter{activeFilters ? ` (${activeFilters})` : ""}
            </Button>
          </div>
          <form
            id="host-filters"
            role="search"
            aria-label="Hosts filtern"
            onSubmit={(e) => e.preventDefault()}
            className={`mb-3 flex-wrap items-center gap-x-4 gap-y-2 max-md:flex-col max-md:items-stretch ${filtersOpen ? "flex" : "max-md:hidden md:flex"}`}
          >
            <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
              Suche
              <TextInput
                type="search"
                value={q}
                onChange={(e) => setParam({ q: e.target.value })}
                placeholder="Name, Distribution, Kernel"
                className="w-64 max-w-full font-normal max-md:w-full"
              />
            </label>
            <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1">
              Status
              <select
                value={status}
                onChange={(e) => setParam({ status: e.target.value })}
                className="min-h-8 rounded-sm border border-control bg-sunk px-1.5 text-sm font-normal text-fg max-md:min-h-11"
              >
                <option value="">alle</option>
                {HOST_STATUS_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {HOST_STATUS[s].label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex min-h-8 items-center gap-2 text-sm max-md:min-h-11">
              <input type="checkbox" checked={rebootOnly} onChange={(e) => setParam({ reboot: e.target.checked ? "1" : null })} className="size-4 accent-(--accent) max-md:size-5" />
              nur Neustart nötig
            </label>
            {/* Mobil sind die Spaltenköpfe ausgeblendet: Sortierung steht hier. */}
            <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1 md:hidden">
              Sortierung
              <select
                value={`${sort}:${dir}`}
                onChange={(e) => {
                  const [k, d] = e.target.value.split(":");
                  setParam({ sort: k ?? null, dir: d ?? null });
                }}
                className="min-h-11 rounded-sm border border-control bg-sunk px-1.5 text-sm font-normal text-fg"
              >
                {(Object.keys(SORT_LABEL) as SortKey[]).flatMap((k) => [
                  <option key={`${k}:asc`} value={`${k}:asc`}>
                    {SORT_LABEL[k]} aufsteigend
                  </option>,
                  <option key={`${k}:desc`} value={`${k}:desc`}>
                    {SORT_LABEL[k]} absteigend
                  </option>,
                ])}
              </select>
            </label>
            {filtering ? <Button onClick={() => router.replace(pathname, { scroll: false })}>Filter zurücksetzen</Button> : null}
          </form>

          {rows.length === 0 ? (
            <Empty title="Kein Host entspricht dem Filter">Passe die Suche an oder setze den Filter zurück.</Empty>
          ) : (
            <div className="max-lg:overflow-x-auto">
              <table className="tbl stack">
                <caption>Hosts mit Distribution, Kernel, letztem Report, offenen Updates, CVE-Lage und Status</caption>
                <thead>
                  <tr>
                    {COLUMNS.map((c) => (
                      <SortHead
                        key={c.key}
                        label={c.label}
                        num={c.num}
                        className={c.cls}
                        active={sort === c.key}
                        dir={dir}
                        onSort={() => setParam({ sort: c.key, dir: sort === c.key && dir === "asc" ? "desc" : "asc" })}
                      />
                    ))}
                    <th scope="col" className="max-wide:hidden">
                      <span className="th-pad">Uptime</span>
                    </th>
                    <th scope="col" className="max-wide:hidden">
                      <span className="th-pad">Agent</span>
                    </th>
                  </tr>
                </thead>
                <tbody key={`${sort}|${dir}|${status}|${rebootOnly}|${updatesOnly}|${unknownOnly}|${q}`}>
                  {rows.map((h) => (
                    <HostRow key={h.id} h={h} feedOk={feedOk} flash={flashed.has(h.id)} />
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

function HostRow({ h, feedOk, flash }: { h: Host; feedOk: boolean; flash: boolean }) {
  const newer = h.newest_kernel && h.running_kernel && h.newest_kernel !== h.running_kernel;
  const stale = h.status === "stale";
  return (
    <tr data-flash={flash ? "" : undefined}>
      <td className="cell-primary">
        <Link href={`/hosts/${h.id}`} className="font-semibold" onPointerEnter={() => prefetchHost(h.id)} onFocus={() => prefetchHost(h.id)}>
          {h.name}
        </Link>
        {h.is_proxmox ? <span className="mt-1 flex xl:ml-2 xl:mt-0 xl:inline-flex xl:align-middle"><Marker>Proxmox {h.proxmox_version}</Marker></span> : null}
        {h.hostname && h.hostname !== h.name ? <div className="text-xs text-fg3">{h.hostname}</div> : null}
        <div className="hidden text-xs text-fg3 md:max-xl:block">
          zuletzt <RelTime iso={h.last_report_at} />
        </div>
      </td>
      <td>
        <span className="block max-md:inline">{h.pretty_name ?? (h.os_id ? `${h.os_id} ${h.os_version ?? ""}` : "–")}</span>{" "}
        <span className="block text-xs max-md:inline">
          <Mono>{h.running_kernel ? kernelBase(h.running_kernel) : "–"}</Mono>
          {newer ? (
            <span className="ml-1.5 inline-flex items-center gap-1 text-warn" title="Ein neuerer Kernel ist installiert, aber noch nicht gebootet">
              <Icon name="reboot" />
              <Mono>{kernelBase(h.newest_kernel)}</Mono>
              <span className="sr-only">installiert, Neustart nötig</span>
            </span>
          ) : null}
        </span>
      </td>
      <td data-label="Report" className={`md:max-xl:hidden ${stale ? "text-warn" : ""}`}>
        <span className="inline-flex items-center gap-1">
          {stale ? <Icon name="clock" /> : null}
          <RelTime iso={h.last_report_at} />
          {stale ? <span className="sr-only">: meldet sich nicht mehr</span> : null}
        </span>
      </td>
      <td data-label="Updates" className="num">
        {h.updates_pending == null ? (
          <span className="text-fg3">unbekannt</span>
        ) : (
          <>
            <span className={h.updates_pending === 0 ? "text-fg3" : "mono"}>{h.updates_pending} offen</span>
            {h.updates_security ? <div className="mono font-semibold text-crit max-md:ml-1.5 max-md:inline">{h.updates_security} Sicherheit</div> : null}
          </>
        )}
      </td>
      <td className="cell-status">
        <CveCell h={h} feedOk={feedOk} />
      </td>
      <td className="cell-status lead">
        <StatusBadge key={h.status} info={HOST_STATUS[h.status]} />
        {h.reboot_needed && h.status !== "reboot_required" ? (
          <div className="mt-1 inline-flex items-center gap-1 text-xs text-warn max-md:mt-0">
            <Icon name="reboot" /> Neustart nötig
          </div>
        ) : null}
      </td>
      <td className="mono max-wide:hidden"><Uptime lastReportAt={h.last_report_at} seconds={h.uptime_seconds} /></td>
      <td className="mono max-wide:hidden">{h.agent_version ? `v${h.agent_version}` : "–"}</td>
    </tr>
  );
}

/** CVE-Lage: nie "grün" bei fehlender Datenlage (Proxmox, Feed veraltet). Jede Zahl führt gefiltert zur Host-Seite. */
function CveCell({ h, feedOk }: { h: Host; feedOk: boolean }) {
  const to = (f: string) => `/hosts/${h.id}?cve=${f}`;
  const parts: React.ReactNode[] = [];
  if (h.cve_vulnerable > 0)
    parts.push(
      <Link key="v" href={to("open")} className="inline-flex items-center gap-1 font-semibold text-crit no-underline hover:underline min-h-6 items-center max-md:min-h-11">
        <Icon name="crit" /> {h.cve_vulnerable} offen
      </Link>,
    );
  if (h.cve_fix_pending > 0)
    parts.push(
      <Link key="p" href={to("open")} className="inline-flex items-center gap-1 text-warn no-underline hover:underline min-h-6 items-center max-md:min-h-11">
        <Icon name="warn" /> {h.cve_fix_pending} Fix angekündigt
      </Link>,
    );
  if (h.cve_reboot > 0)
    parts.push(
      <Link key="r" href={to("reboot")} className="inline-flex items-center gap-1 text-warn no-underline hover:underline min-h-6 items-center max-md:min-h-11">
        <Icon name="reboot" /> {h.cve_reboot} Neustart
      </Link>,
    );
  if (h.is_proxmox || h.cve_unknown > 0)
    parts.push(
      <Link key="u" href={to("unknown")} className="inline-flex items-center gap-1 text-unknown no-underline hover:underline min-h-6 items-center max-md:min-h-11">
        <Icon name="unknown" /> {h.is_proxmox ? "manuell prüfen" : `${h.cve_unknown} unbekannt`}
      </Link>,
    );
  // Gefixt zählt nie als Entwarnung für Proxmox oder bei fehlender Quelle; es steht nur als ruhige Information dabei.
  const fixed =
    h.cve_fixed > 0 && !h.is_proxmox ? (
      <Link key="f" href={to("fixed")} className="inline-flex items-center gap-1 text-fg2 no-underline hover:underline min-h-6 items-center max-md:min-h-11">
        <Icon name="ok" /> {h.cve_fixed} gefixt
      </Link>
    ) : null;
  if (parts.length === 0) {
    if (h.status === "pending") return <span className="text-fg3">–</span>;
    // Quelle unvollständig/veraltet/fehlerhaft: nie "keine offenen", sondern die Begründung zeigen.
    if (h.cve_source_issue)
      return (
        <span className="inline-flex items-center gap-1 text-unknown">
          <Icon name="unknown" /> {h.cve_source_issue}
        </span>
      );
    return (
      <div className="flex flex-col gap-0.5 max-md:flex-row max-md:flex-wrap max-md:gap-x-2">
        {feedOk ? (
          <span className="inline-flex items-center gap-1 text-fg2">
            <Icon name="ok" /> keine offenen
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-unknown">
            <Icon name="unknown" /> Feed prüfen
          </span>
        )}
        {fixed}
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-0.5 max-md:flex-row max-md:flex-wrap max-md:gap-x-2">
      {parts}
      {fixed}
    </div>
  );
}

export default function HostsPage() {
  return (
    <Suspense fallback={<TableSkeleton what="Hosts" />}>
      <HostsView />
    </Suspense>
  );
}

/** Host-Detail lädt drei Abrufe; Hover/Fokus wärmt sie vor, damit die Seite ohne Skeleton erscheint. */
const prefetchHost = (id: number) => prefetchApi(`/hosts/${id}`, `/hosts/${id}/cves?group=open&limit=200`, `/hosts/${id}/cves?group=fixed&limit=200`, `/hosts/${id}/history?limit=30`);
