"use client";

import { DATA_LABEL, DATA_TIP } from "@/lib/terms";
import { useRowLink } from "@/lib/rowLink";
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
import { PageHeader } from "@/components/PageHeader";
import { SortHead } from "@/components/SortHead";
import { TableSkeleton } from "@/components/Skeleton";
import { useFlash } from "@/lib/useFlash";
import { Mono } from "@/components/Version";
import { RelTime } from "@/components/RelTime";
import { Empty, ErrorNote } from "@/components/States";
import { Button, Select, TextInput } from "@/components/Controls";
import { Popover } from "@/components/Popover";
import { feedSummary } from "@/components/FeedStatus";

type SortKey = "name" | "status" | "kernel" | "report" | "updates" | "cve";

/** `cls`: Sichtbarkeit je Breite. Spaltenanteile (Summe 100 % bei 8 Spalten) und Mindestbreiten (Summe 59 rem). Zwischen 768 und
 *  1279 px entfallen Zuletzt gemeldet (Meldezeit steht dann im Host-Feld) und Updates: Bei 1024 px brauchen CVE (zwei feste
 *  Spalten) und Status (längster Chip „Sicherheitsupdates offen“) ihre volle Breite, mit Updates wäre die Tabelle 30 px zu breit.
 *  Uptime kommt ab 1440 px, Agent ab 1600 px dazu. */
const COLUMNS: { key: SortKey; label: string; num?: boolean; cls: string; tip?: string }[] = [
  { key: "name", label: "Host", cls: "w-[13%] min-w-28 hd:w-[7.2rem] hd:min-w-[7.2rem] xl:w-[8.1rem] xl:min-w-[8.1rem]" },
  { key: "kernel", label: "Distribution / Kernel", cls: "w-[17%] min-w-28 hd:w-[10.9rem] hd:min-w-[10.9rem]" },
  { key: "report", label: DATA_LABEL, cls: "w-[10%] min-w-32 md:max-hd:hidden hd:w-[8rem] hd:min-w-[8rem]", tip: DATA_TIP },
  { key: "updates", label: "Updates", cls: "w-[9%] min-w-28 md:max-hd:hidden hd:w-[7.5rem] hd:min-w-[7.5rem]" },
  { key: "cve", label: "CVE", cls: "w-[20%] min-w-52 hd:w-[12.6rem] hd:min-w-[12.6rem]" },
  { key: "status", label: "Status", cls: "w-[12%] min-w-26 hd:w-[12.1rem] hd:min-w-[12.1rem]" },
];

const SORT_LABEL: Record<SortKey, string> = { name: "Host", kernel: "Kernel", report: DATA_LABEL, updates: "Updates", cve: "CVE", status: "Status" };

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
        (!updatesOnly || (h.updates_pending ?? 0) > 0),
    );
    const cmp = SORTERS[sort] ?? SORTERS.status;
    const sorted = [...filtered].sort((a, b) => cmp(a, b) || a.name.localeCompare(b.name, "de", { numeric: true }));
    return dir === "desc" ? sorted.reverse() : sorted;
  }, [all, q, status, rebootOnly, updatesOnly, sort, dir]);

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
      { id: "stale", label: "Meldet sich nicht", icon: "clock", tone: "text-unknown", count: n((h) => h.status === "stale"), param: { status: "stale" } },
    ];
    return list;
  }, [all]);

  const lastReport = useMemo(() => (all ?? []).reduce<string | null>((m, h) => (h.last_report_at && (!m || h.last_report_at > m) ? h.last_report_at : m), null), [all]);

  const feedOk = feedSummary(feeds.data)?.ok ?? false;
  const activeFilters = [q.trim(), status, rebootOnly, updatesOnly].filter(Boolean).length;
  const filtering = activeFilters > 0;

  if (hosts.error && !all) return <ErrorNote message={hosts.error} />;
  if (!all) return <TableSkeleton what="Hosts" />;

  const kpiActive = (k: Kpi) => Object.entries(k.param).every(([key, v]) => params.get(key) === v);

  return (
    <>
      <PageHeader
        title="Hosts"
        count={<span aria-live="polite">{filtering ? `${rows.length} von ${all.length}` : all.length} {all.length === 1 ? "Host" : "Hosts"}</span>}
      />

      {all.length === 0 ? (
        <Empty title="Noch keine Hosts">
          Lege unter <Link href="/agents">Agents</Link> einen Agent an. Sobald der Agent erstmals Daten gemeldet hat, erscheint der Host hier.
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
                  className={`flex min-h-11 min-w-0 flex-col items-start gap-0.5 border-l-2 px-3 py-2 text-left first:border-l-0 hover:bg-sunk disabled:cursor-default disabled:opacity-60 disabled:hover:bg-transparent ${
                    active ? "border-accent bg-sunk" : "border-transparent"
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <span className={k.count > 0 ? k.tone : "text-fg3"}>
                      <Icon name={k.icon} size={16} />
                    </span>
                    <span className="mono text-xl font-semibold leading-none">{k.count}</span>
                  </span>
                  <span className="text-xs text-fg2 [overflow-wrap:anywhere]">{k.label}</span>
                </button>
              );
            })}
            <div className="flex min-h-11 min-w-0 flex-col items-start gap-0.5 px-3 py-2">
              <span className="mono text-sm font-semibold leading-[1.25rem]">
                <RelTime iso={lastReport} />
              </span>
              <span className="text-xs text-fg2 [overflow-wrap:anywhere]" title={DATA_TIP}>{DATA_LABEL}</span>
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
              <Select value={status} onChange={(e) => setParam({ status: e.target.value })} className="w-auto min-w-36">
                <option value="">alle</option>
                {HOST_STATUS_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {HOST_STATUS[s].label}
                  </option>
                ))}
              </Select>
            </label>
            <label className="flex min-h-8 items-center gap-2 text-sm max-md:min-h-11">
              <input type="checkbox" checked={rebootOnly} onChange={(e) => setParam({ reboot: e.target.checked ? "1" : null })} className="size-4 accent-(--accent) max-md:size-5" />
              nur Neustart nötig
            </label>
            {/* Mobil sind die Spaltenköpfe ausgeblendet: Sortierung steht hier. */}
            <label className="flex items-center gap-2 text-xs font-semibold text-fg2 max-md:flex-col max-md:items-stretch max-md:gap-1 md:hidden">
              Sortierung
              <Select
                value={`${sort}:${dir}`}
                onChange={(e) => {
                  const [k, d] = e.target.value.split(":");
                  setParam({ sort: k ?? null, dir: d ?? null });
                }}
              >
                {(Object.keys(SORT_LABEL) as SortKey[]).flatMap((k) => [
                  <option key={`${k}:asc`} value={`${k}:asc`}>
                    {SORT_LABEL[k]} aufsteigend
                  </option>,
                  <option key={`${k}:desc`} value={`${k}:desc`}>
                    {SORT_LABEL[k]} absteigend
                  </option>,
                ])}
              </Select>
            </label>
            {filtering ? <Button onClick={() => router.replace(pathname, { scroll: false })}>Filter zurücksetzen</Button> : null}
          </form>

          {rows.length === 0 ? (
            <Empty title="Kein Host entspricht dem Filter">Passe die Suche an oder setze den Filter zurück.</Empty>
          ) : (
            <div className="@container/tbl max-hd:overflow-x-auto">
              <table className="tbl stack dist [&_td]:py-1.5 hd:[--col-pad:16px] md:[--tbl-min:34.5rem] hd:[--tbl-min:58rem]">
                <caption>Hosts mit Distribution, Kernel, Zeitpunkt der letzten Daten, offenen Updates, CVE-Lage und Status</caption>
                <thead>
                  <tr>
                    {COLUMNS.map((c) => (
                      <SortHead
                        key={c.key}
                        label={c.label}
                        num={c.num}
                        className={c.cls}
                        tip={c.tip}
                        active={sort === c.key}
                        dir={dir}
                        onSort={() => setParam({ sort: c.key, dir: sort === c.key && dir === "asc" ? "desc" : "asc" })}
                      />
                    ))}
                    <th scope="col" className="w-[10%] min-w-32 max-xl:hidden hd:w-[8.3rem] hd:min-w-[8.3rem]">
                      <span className="th-pad">Uptime</span>
                    </th>
                    <th scope="col" className="w-[9%] min-w-22 max-wide:hidden hd:w-[4.7rem] hd:min-w-[4.7rem]">
                      <span className="th-pad">Agent</span>
                    </th>
                  </tr>
                </thead>
                <tbody key={`${sort}|${dir}|${status}|${rebootOnly}|${updatesOnly}|${q}`}>
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
  const rowLink = useRowLink(`/hosts/${h.id}`);
  return (
    <tr data-flash={flash ? "" : undefined} {...rowLink}>
      <td className="cell-primary">
        <Link href={`/hosts/${h.id}`} className="font-semibold" onPointerEnter={() => prefetchHost(h.id)} onFocus={() => prefetchHost(h.id)}>
          {h.name}
        </Link>
        {h.is_proxmox ? <span className="mt-1 flex xl:ml-2 xl:mt-0 xl:inline-flex xl:align-middle"><Marker>Proxmox {h.proxmox_version}</Marker></span> : null}
        {h.hostname && h.hostname !== h.name ? <div className="text-xs text-fg3">{h.hostname}</div> : null}
        <div className="hidden text-xs text-fg3 md:max-hd:block">
          {DATA_LABEL} <RelTime iso={h.last_report_at} />
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
      <td data-label={DATA_LABEL} className={`whitespace-nowrap md:max-hd:hidden ${stale ? "text-warn" : ""}`}>
        <span className="inline-flex items-center gap-1">
          {stale ? <Icon name="clock" /> : null}
          <RelTime iso={h.last_report_at} />
          {stale ? <span className="sr-only">: meldet sich nicht mehr</span> : null}
        </span>
      </td>
      <td data-label="Updates" className="whitespace-nowrap md:max-hd:hidden">
        {h.updates_pending == null ? (
          <span className="text-fg3">–</span>
        ) : (
          <>
            <span className={h.updates_pending === 0 ? "text-fg3" : "mono"}>{h.updates_pending} offen</span>
            {h.updates_security ? <div className="mono font-semibold text-crit max-md:ml-1.5 max-md:inline">{h.updates_security} Sicherheit</div> : null}
          </>
        )}
      </td>
      <td className="cell-status" data-href={`/hosts/${h.id}?cve=${h.cve_vulnerable > 0 || h.cve_fix_pending > 0 ? "open" : h.cve_reboot > 0 ? "reboot" : "fixed"}`}>
        <CveCell h={h} feedOk={feedOk} />
      </td>
      <td className="cell-status lead">
        {/* Abstand zwischen Status und Neustart-Hinweis: nebeneinander mit Luft, bei wenig Platz untereinander. */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <StatusBadge key={h.status} info={HOST_STATUS[h.status]} />
          {h.reboot_needed && h.status !== "reboot_required" ? (
            <div className="inline-flex items-center gap-1 text-xs text-warn">
              <Icon name="reboot" /> Neustart nötig
            </div>
          ) : null}
        </div>
      </td>
      <td className="mono whitespace-nowrap max-xl:hidden"><Uptime lastReportAt={h.last_report_at} seconds={h.uptime_seconds} /></td>
      <td className="mono max-wide:hidden">{h.agent_version ? `v${h.agent_version}` : "–"}</td>
    </tr>
  );
}

/** Höchstens vier sichtbare Plätze in der CVE-Zelle; bei mehr Einträgen steht auf dem vierten Platz „+N“ (siehe README, „Anzeige“). */
const CVE_SLOTS = 4;

type CveEntry = { key: string; to: string; tone: string; icon: "crit" | "warn" | "reboot" | "unknown" | "ok"; num: number | null; word: string; full: string };

/** CVE-Lage: nie "grün" bei fehlender Datenlage (Proxmox, Feed veraltet). Jede Zahl führt gefiltert zur Host-Seite. */
function CveCell({ h, feedOk }: { h: Host; feedOk: boolean }) {
  const to = (f: string) => `/hosts/${h.id}?cve=${f}`;
  // Reihenfolge nach Wichtigkeit; Einträge mit 0 entfallen.
  const entries: CveEntry[] = [];
  if (h.cve_vulnerable > 0) entries.push({ key: "v", to: to("open"), tone: "font-semibold text-crit", icon: "crit", num: h.cve_vulnerable, word: "offen", full: "offen" });
  if (h.cve_fix_pending > 0) entries.push({ key: "p", to: to("open"), tone: "text-warn", icon: "warn", num: h.cve_fix_pending, word: "Fix folgt", full: "Fix angekündigt" });
  if (h.cve_reboot > 0) entries.push({ key: "r", to: to("reboot"), tone: "text-warn", icon: "reboot", num: h.cve_reboot, word: "Neustart", full: "Neustart nötig" });
  // Gefixt zählt nie als Entwarnung für Proxmox oder bei fehlender Quelle; es steht nur als ruhige Information dabei.
  if (h.cve_fixed > 0 && !h.is_proxmox) entries.push({ key: "f", to: to("fixed"), tone: "text-fg2", icon: "ok", num: h.cve_fixed, word: "gefixt", full: "gefixt" });

  // Sicherheitsregel: Kann der Host nicht bewertet werden (Proxmox-Kernel, CVEs ohne Aussage), steht hier nie „keine offenen“.
  // Die Zahl der CVEs ohne Aussage wird nicht angezeigt; die Zelle zeigt „–“ mit Erklärung, der Status-Chip „Nicht bewertbar“.
  const notRated = h.is_proxmox || h.cve_unknown > 0;
  if (entries.length === 0) {
    if (h.status === "pending") return <span className="text-fg3">–</span>;
    if (notRated)
      return (
        <span className="text-fg3" title={h.is_proxmox ? "Nicht bewertbar: für Proxmox-Kernel gibt es keine belastbare CVE-Quelle" : "Nicht bewertbar: für einen Teil der CVEs liefert die Quelle keine Aussage"}>
          –<span className="sr-only"> nicht bewertbar</span>
        </span>
      );
    // Quelle unvollständig/veraltet/fehlerhaft: nie "keine offenen", sondern die Begründung zeigen.
    if (h.cve_source_issue)
      return (
        <span className="inline-flex items-center gap-1 text-unknown">
          <Icon name="unknown" /> {h.cve_source_issue}
        </span>
      );
    return feedOk ? (
      <span className="inline-flex items-center gap-1 text-fg2">
        <Icon name="ok" /> keine offenen
      </span>
    ) : (
      <span className="inline-flex items-center gap-1 text-unknown">
        <Icon name="unknown" /> Feed prüfen
      </span>
    );
  }

  const link = (e: CveEntry, cls = "") => (
    <Link
      key={e.key}
      href={e.to}
      title={`${e.num ?? ""} ${e.full}`.trim()}
      className={`inline-flex min-h-6 items-center gap-1.5 whitespace-nowrap text-[13px] tabular-nums no-underline hover:underline max-md:min-h-11 ${e.tone} ${cls}`}
    >
      <Icon name={e.icon} /> {e.num !== null ? <span>{e.num.toLocaleString("de-DE")}</span> : null} <span>{e.word}</span>
    </Link>
  );
  const overflow = entries.length > CVE_SLOTS;
  const shown = overflow ? entries.slice(0, CVE_SLOTS - 1) : entries;
  const rest = overflow ? entries.slice(CVE_SLOTS - 1) : [];
  return (
    // Zwei feste Spalten: die zweite beginnt in jeder Zeile an derselben Stelle.
    <div className="grid grid-cols-[repeat(2,max-content)] justify-start gap-x-3 gap-y-0 max-md:flex max-md:flex-wrap max-md:gap-x-3">
      {shown.map((e) => link(e))}
      {overflow ? (
        <Popover
          label={`Weitere CVE-Angaben für ${h.name}`}
          width={220}
          trigger={(t) => (
            <button
              type="button"
              ref={t.ref}
              aria-haspopup={t["aria-haspopup"]}
              aria-expanded={t["aria-expanded"]}
              aria-controls={t["aria-controls"]}
              title={`${rest.length} weitere Angaben: ${rest.map((e) => e.full).join(", ")}`}
              onClick={t.toggle}
              className="inline-flex min-h-6 items-center text-[13px] text-fg2 hover:text-fg max-md:min-h-11 max-md:min-w-11"
            >
              +{rest.length}
              <span className="sr-only"> weitere Angaben</span>
            </button>
          )}
        >
          <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm">
            {entries.map((e) => (
              <li key={e.key}>{link(e)}</li>
            ))}
          </ul>
        </Popover>
      ) : null}
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
