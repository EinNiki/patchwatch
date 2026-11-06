"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { prefetchApi, useApi } from "@/lib/useApi";
import { absTime } from "@/lib/format";
import { CVE_STATUS } from "@/lib/status";
import type { CveStatus, Host, HostCve, HostCvesResponse } from "@/lib/types";
import { Marker } from "@/components/DistroChip";
import { StatusBadge } from "@/components/StatusBadge";
import { Dialog } from "@/components/Dialog";
import { Mono } from "@/components/Version";
import { ErrorNote } from "@/components/States";
import { Linkified } from "@/components/Linkified";
import { Icon } from "@/components/Icons";

const LIVE = ["report_received", "host_status", "host_cve_status"] as const;
const ROW_H = 32; // dichte Zeilen (DESIGN.md): 32 px
const ROW_H_TOUCH = 64; // unter 768 px: zweizeilig (Zeile 1: ID, Status, Details mit 44-px-Flächen; Zeile 2: Fix-Stand)
const PAGE = 200;
const VIRTUAL_FROM = 100; // ab dieser Zeilenzahl wird nur der sichtbare Ausschnitt gerendert
const PROXMOX_ADVISORIES = "https://forum.proxmox.com/forums/security-advisories.26/";

/** Filter aus der Kopfzeile; `open`/`reboot`/`fixed` gehören je zu einer Spalte, `unknown`/`not_affected` zur Einzelliste. */
export type CveFilter = "open" | "reboot" | "fixed" | "unknown" | "not_affected";
const FILTER_STATUS: Record<CveFilter, string> = {
  open: "vulnerable,fix_pending",
  reboot: "fixed_installed_reboot_required",
  fixed: "fixed",
  unknown: "unknown",
  not_affected: "not_affected",
};
export function parseCveFilter(v: string | null): CveFilter | null {
  return v && v in FILTER_STATUS ? (v as CveFilter) : null;
}

/** Wahr ab 1280 px Breite (Zwei-Spalten-Ansicht); davor Tabs. */
function useWide(): boolean {
  const [wide, setWide] = useState(false);
  useEffect(() => {
    const m = window.matchMedia("(min-width: 1280px)");
    const on = () => setWide(m.matches);
    on();
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return wide;
}

/** Wahr unter 768 px (Touch-Maße). */
function useNarrow(): boolean {
  const [narrow, setNarrow] = useState(false);
  useEffect(() => {
    const m = window.matchMedia("(max-width: 767px)");
    const on = () => setNarrow(m.matches);
    on();
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return narrow;
}

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

/** Eine Zeile: was gilt, in Worten (Fix-Version und Zustand des Hosts). */
export function hostState(c: HostCve, running: string | null, proxmox: boolean): string {
  const run = running ?? "unbekannt";
  switch (c.status) {
    case "fixed":
      return c.fix_version ? `Fix ab ${c.fix_version}, läuft ${run}` : `Behoben, läuft ${run}`;
    case "fixed_installed_reboot_required":
      return `Fix installiert, Kernel läuft noch ${run}, Neustart nötig`;
    case "vulnerable":
      return c.fix_version ? `Fix ab ${c.fix_version}, läuft ${run}` : `Kein Fix bekannt, läuft ${run}`;
    case "fix_pending":
      return c.fix_version ? `Fix angekündigt ab ${c.fix_version}, läuft ${run}` : `Fix angekündigt, läuft ${run}`;
    case "not_affected":
      return `Nicht betroffen, läuft ${run}`;
    default:
      return proxmox ? "Keine belastbare Quelle, manuell prüfen" : "Quelle liefert keine Aussage";
  }
}

function query(base: { group?: string; status?: string; q: string; limit: number }): string {
  const p = new URLSearchParams();
  if (base.status) p.set("status", base.status);
  else if (base.group) p.set("group", base.group);
  if (base.q) p.set("q", base.q);
  p.set("limit", String(base.limit));
  return p.toString();
}

export function HostCves({
  host,
  initialFilter,
  feedWarning,
}: {
  host: Host;
  initialFilter: CveFilter | null;
  feedWarning: string | null;
}) {
  const wide = useWide();
  // Proxmox: es gibt nur "unbekannt, manuell prüfen"; diese Einträge stehen sofort im Blick (nie grün, kein Alarm).
  const startFilter = initialFilter ?? (host.is_proxmox ? "unknown" : null);
  const [filter, setFilter] = useState<CveFilter | null>(startFilter);
  const [tab, setTab] = useState<"open" | "fixed" | "all">(startFilter === "fixed" ? "fixed" : startFilter ? "all" : "open");
  const [text, setText] = useState("");
  const q = useDebounced(text.trim(), 250);
  const [limits, setLimits] = useState({ left: PAGE, right: PAGE, single: PAGE });
  const [detail, setDetail] = useState<HostCve | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // Welche Listen gerade gebraucht werden: Zwei Spalten (breit), Einzelliste (Tabs oder Filter auf unbekannt/nicht betroffen).
  const single = filter === "unknown" || filter === "not_affected" || (!wide && tab === "all");
  const twoCols = wide && !single;
  const leftStatus = twoCols && (filter === "open" || filter === "reboot") ? FILTER_STATUS[filter] : undefined;
  const rightStatus = twoCols && filter === "fixed" ? FILTER_STATUS.fixed : undefined;
  const base = `/hosts/${host.id}/cves?`;
  const leftPath = twoCols || (!wide && tab === "open" && !single) ? `${base}${query({ group: "open", status: leftStatus, q, limit: limits.left })}` : null;
  const rightPath = twoCols || (!wide && tab === "fixed" && !single) ? `${base}${query({ group: "fixed", status: rightStatus, q, limit: limits.right })}` : null;
  const singlePath = single ? `${base}${query({ status: filter ? FILTER_STATUS[filter] : undefined, q, limit: limits.single })}` : null;
  // Beim Tab-Wechsel bleibt der Gesamtstand sichtbar: `counts` kommt aus jeder Antwort, die Kopfzeile nimmt die jüngste.
  const left = useApi<HostCvesResponse>(leftPath, 60_000, LIVE, undefined, { keepPrevious: true });
  const right = useApi<HostCvesResponse>(rightPath, 60_000, LIVE, undefined, { keepPrevious: true });
  const solo = useApi<HostCvesResponse>(singlePath, 60_000, LIVE, undefined, { keepPrevious: true });
  const any = solo.data ?? left.data ?? right.data;
  // Die Kopfzeile bleibt über Wechsel hinweg stehen (kein Springen), solange schon Zähler da waren.
  const [lastAny, setLastAny] = useState<HostCvesResponse | undefined>(undefined);
  if (any && any !== lastAny) setLastAny(any);
  const head = any ?? lastAny;
  const counts = head?.counts;
  const issue = head?.issue ?? host.cve_source_issue ?? null;

  async function reloadAll() {
    await Promise.all([left.reload(), right.reload(), solo.reload()]);
  }

  async function toggleReview(c: HostCve, checked: boolean) {
    setBusy(c.cve_id);
    setProblem(null);
    try {
      const path = `/hosts/${host.id}/cves/${c.cve_id}/review`;
      if (checked) await api.put(path);
      else await api.del(path);
      await reloadAll();
      setDetail((d) => (d && d.cve_id === c.cve_id ? { ...d, reviewed_at: checked ? new Date().toISOString() : null, reviewed_by: checked ? d.reviewed_by : null } : d));
    } catch (e) {
      setProblem(e instanceof Error ? e.message : "Speichern fehlgeschlagen");
    } finally {
      setBusy(null);
    }
  }

  const running = head?.host.running_kernel_version ?? head?.host.running_kernel ?? host.kernel_package_version ?? host.running_kernel;
  const newest = head?.host.newest_kernel_version ?? host.newest_kernel_version;
  const open = counts ? counts.vulnerable + counts.fix_pending : 0;

  function toggle(f: CveFilter) {
    setFilter((cur) => (cur === f ? null : f));
    setTab(f === "fixed" ? "fixed" : f === "open" || f === "reboot" ? "open" : "all");
  }

  const chips: { f: CveFilter; label: string; n: number }[] = counts
    ? [
        { f: "open", label: "Offen", n: open },
        { f: "reboot", label: "Fix da, Neustart nötig", n: counts.fixed_installed_reboot_required },
        { f: "fixed", label: "Gefixt", n: counts.fixed },
        { f: "not_affected", label: "Nicht betroffen", n: counts.not_affected },
        { f: "unknown", label: "Unbekannt", n: counts.unknown },
      ]
    : [];

  return (
    <section aria-labelledby="cve" className="mb-6">
      <h2 id="cve" className="mb-2 text-lg font-semibold">
        CVE-Lage für den laufenden Kernel
      </h2>
      {host.is_proxmox ? (
        <p role="note" className="mb-2 border-l-4 border-unknown bg-unknown-soft px-3 py-1.5 text-unknown">
          <strong className="font-semibold">Proxmox-Kernel:</strong> Für -pve-Kernel gibt es keine belastbare CVE-Quelle. Jede Bewertung ist unbekannt und muss
          manuell geprüft werden:{" "}
          <a href={PROXMOX_ADVISORIES} target="_blank" rel="noopener noreferrer">
            Proxmox Security Advisories
          </a>
          . Eine Prüfung („geprüft am“) gilt nur für den Kernel, bei dem sie gesetzt wurde.
        </p>
      ) : null}
      {issue ? (
        <p role="note" className="mb-2 border-l-4 border-unknown bg-unknown-soft px-3 py-1.5 text-unknown">
          <strong className="font-semibold">Bewertung eingeschränkt:</strong> {issue}. Neue Einträge „gefixt“ oder „nicht betroffen“ entstehen erst, wenn die Quelle vollständig ist; bekannte Einträge bleiben.{" "}
          <Link href="/cves#feeds">Zur Quellen-Tabelle</Link>
        </p>
      ) : null}
      {feedWarning ? (
        <p role="note" className="mb-2 border-l-4 border-warn bg-warn-soft px-3 py-1.5 text-warn">
          <strong className="font-semibold">{feedWarning}.</strong> Die Bewertung kann veraltet sein.
        </p>
      ) : null}
      {problem ? <ErrorNote message={problem} /> : null}
      {left.error && !head ? <ErrorNote message={left.error} /> : null}

      {/* Zusammenfassung in einer Zeile; bleibt beim Scrollen der Seite stehen. */}
      <div className="sticky top-(--topbar-h) z-10 -mx-1 mb-2 flex min-h-9 flex-wrap items-center gap-x-1.5 gap-y-1 bg-bg px-1 py-1 md:top-0" role="group" aria-label="Zusammenfassung und Filter">
        {counts ? (
          chips.map(({ f, label, n }, i) => (
            <span key={f} className="inline-flex items-center gap-1.5">
              {i > 0 ? <span aria-hidden="true" className="text-fg3 max-md:hidden">·</span> : null}
              <button
                type="button"
                aria-pressed={filter === f}
                onClick={() => toggle(f)}
                className={`inline-flex h-6 items-center gap-1 rounded-xs border px-1.5 text-xs font-medium max-md:h-11 max-md:px-3 max-md:text-sm ${filter === f ? "border-accent bg-accent text-bg" : "border-line bg-sunk text-fg hover:bg-surface"} ${n === 0 && filter !== f ? "text-fg3" : ""}`}
              >
                {label} <span className="tabular-nums font-semibold">{n}</span>
              </button>
            </span>
          ))
        ) : (
          <span className="text-xs text-fg3">CVE-Lage wird geladen …</span>
        )}
        <span className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg2">
          <span>
            Läuft <Mono>{running ?? "–"}</Mono>
          </span>
          <span>
            Neuester installiert <Mono>{newest ?? "–"}</Mono>
            {head?.host.reboot_needed || host.reboot_needed ? (
              <span className="ml-1 inline-flex items-center gap-0.5 text-warn">
                <Icon name="reboot" size={14} /> Neustart nötig
              </span>
            ) : null}
          </span>
        </span>
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-2 text-xs text-fg2">
          <span className="sr-only">CVEs dieses Hosts durchsuchen</span>
          <input
            type="search"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="CVE-ID oder Text suchen"
            aria-label="CVEs dieses Hosts durchsuchen"
            className="min-h-8 w-64 max-w-full rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm text-fg placeholder:text-fg3 max-md:min-h-11"
          />
        </label>
        {filter ? (
          <button type="button" className="text-xs underline max-md:min-h-11 max-md:min-w-11" onClick={() => setFilter(null)}>
            Filter aufheben
          </button>
        ) : null}
        {!wide && !single ? (
          <div role="tablist" aria-label="CVE-Ansicht" className="ml-auto flex gap-1">
            {(
              [
                ["open", "Offen"],
                ["fixed", "Gefixt"],
                ["all", "Alle"],
              ] as const
            ).map(([t, label]) => (
              <button
                key={t}
                role="tab"
                type="button"
                aria-selected={tab === t}
                onClick={() => {
                  setTab(t);
                  if (t !== "all") setFilter(null);
                }}
                className={`min-h-8 rounded-xs px-3 text-sm font-medium max-md:min-h-11 ${tab === t ? "bg-accent text-bg" : "bg-sunk text-fg hover:bg-surface"}`}
              >
                {label}
              </button>
            ))}
          </div>
        ) : null}
        {!wide && single && !filter ? (
          <div role="tablist" aria-label="CVE-Ansicht" className="ml-auto flex gap-1">
            {(["open", "fixed", "all"] as const).map((t) => (
              <button key={t} role="tab" type="button" aria-selected={tab === t} onClick={() => setTab(t)} className={`min-h-8 rounded-xs px-3 text-sm font-medium max-md:min-h-11 ${tab === t ? "bg-accent text-bg" : "bg-sunk text-fg hover:bg-surface"}`}>
                {t === "open" ? "Offen" : t === "fixed" ? "Gefixt" : "Alle"}
              </button>
            ))}
          </div>
        ) : null}
      </div>

      {twoCols ? (
        <div className="grid grid-cols-2 gap-4">
          <CveList
            title="Offen und Neustart nötig"
            state={left}
            running={running}
            proxmox={host.is_proxmox}
            onOpen={setDetail}
            onMore={() => setLimits((l) => ({ ...l, left: l.left + PAGE }))}
            empty="Nichts offen: kein Fix fehlt und kein Neustart ist nötig."
            tall
          />
          <CveList
            title="Gefixt"
            state={right}
            running={running}
            proxmox={host.is_proxmox}
            onOpen={setDetail}
            onMore={() => setLimits((l) => ({ ...l, right: l.right + PAGE }))}
            empty="Noch keine gefixten CVEs gespeichert."
            tall
          />
        </div>
      ) : (
        <div key={`${tab}-${filter}`} className="tab-fade">
          <CveList
            title={single ? (filter ? CVE_STATUS[filter === "open" ? "vulnerable" : (FILTER_STATUS[filter] as CveStatus)].label : "Alle CVEs") : tab === "open" ? "Offen und Neustart nötig" : "Gefixt"}
            state={single ? solo : tab === "open" ? left : right}
            running={running}
            proxmox={host.is_proxmox}
            onOpen={setDetail}
            onMore={() => setLimits((l) => (single ? { ...l, single: l.single + PAGE } : tab === "open" ? { ...l, left: l.left + PAGE } : { ...l, right: l.right + PAGE }))}
            empty={host.is_proxmox ? "Setze CVEs auf die Watchlist, dann erscheinen sie hier als „manuell prüfen“." : "Keine Einträge für diese Auswahl."}
            tall={wide}
          />
        </div>
      )}

      <Dialog open={detail !== null} title={detail?.cve_id ?? "CVE"} onClose={() => setDetail(null)}>
        {detail ? <Detail c={detail} host={host} running={running} busy={busy === detail.cve_id} onReview={(v) => void toggleReview(detail, v)} /> : null}
      </Dialog>
    </section>
  );
}

function CveList({
  title,
  state,
  running,
  proxmox,
  onOpen,
  onMore,
  empty,
  tall,
}: {
  title: string;
  state: ReturnType<typeof useApi<HostCvesResponse>>;
  running: string | null;
  proxmox: boolean;
  onOpen: (c: HostCve) => void;
  onMore: () => void;
  empty: string;
  tall: boolean;
}) {
  const items = useMemo(() => state.data?.items ?? [], [state.data]);
  const total = state.data?.total ?? 0;
  const rowH = useNarrow() ? ROW_H_TOUCH : ROW_H;
  const scroller = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState(0);
  const [viewH, setViewH] = useState(480);
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => ro.disconnect();
  }, []);
  const virtual = items.length > VIRTUAL_FROM;
  const first = virtual ? Math.max(0, Math.floor(scroll / rowH) - 8) : 0;
  const last = virtual ? Math.min(items.length, Math.ceil((scroll + viewH) / rowH) + 8) : items.length;
  const rest = total - items.length;
  const loading = !state.data;

  return (
    <div className="min-w-0">
      <h3 className="mb-1 flex items-baseline gap-2 text-sm font-semibold">
        {title} <span className="tabular-nums text-xs font-normal text-fg3">{loading ? "…" : total}</span>
      </h3>
      {/* Feste Höhe passend zum Fenster; innen scrollbar (kein Seitenscroll beim Durchsehen). */}
      <div
        ref={scroller}
        onScroll={(e) => setScroll(e.currentTarget.scrollTop)}
        tabIndex={0}
        role="region"
        aria-label={`${title}, Liste`}
        className="overflow-y-auto overflow-x-hidden rounded-xs border border-line bg-surface"
        style={{ height: tall ? "clamp(17rem, calc(100dvh - 22rem), 48rem)" : "clamp(14rem, 60dvh, 36rem)" }}
      >
        {loading ? (
          <div className="p-3 text-xs text-fg3">Lädt …</div>
        ) : items.length === 0 ? (
          <p className="p-3 text-sm text-fg2">{empty}</p>
        ) : (
          <ul className="m-0 list-none p-0" style={virtual ? { position: "relative", height: items.length * rowH } : undefined}>
            {items.slice(first, last).map((c, i) => (
              <Row key={c.cve_id} c={c} h={rowH} running={running} proxmox={proxmox} onOpen={onOpen} style={virtual ? { position: "absolute", top: (first + i) * rowH, left: 0, right: 0 } : undefined} />
            ))}
          </ul>
        )}
      </div>
      {rest > 0 ? (
        <button type="button" className="mt-1 text-xs underline max-md:min-h-11 max-md:min-w-11" onClick={onMore}>
          {rest} weitere anzeigen
        </button>
      ) : null}
    </div>
  );
}

function Row({ c, h, running, proxmox, onOpen, style }: { c: HostCve; h: number; running: string | null; proxmox: boolean; onOpen: (c: HostCve) => void; style?: React.CSSProperties }) {
  const state = hostState(c, running, proxmox);
  const text = c.description ?? c.reason;
  return (
    <li style={{ height: h, ...style }} className="flex items-center gap-2 border-b border-line px-2 text-xs last:border-b-0 max-md:flex-wrap max-md:content-center max-md:gap-x-2 max-md:gap-y-0">
      <Link
        href={`/cves/${c.cve_id}`}
        className="mono inline-flex shrink-0 items-center font-medium max-md:min-h-11"
        onPointerEnter={() => prefetchApi(`/cves/${c.cve_id}`)}
        onFocus={() => prefetchApi(`/cves/${c.cve_id}`)}
      >
        {c.cve_id}
      </Link>
      {c.watched ? <Marker>Watchlist</Marker> : null}
      <span className="hidden min-w-0 flex-1 truncate text-fg3 md:block" title={text}>
        {text}
      </span>
      <span className="ml-auto min-w-0 max-w-[14rem] shrink truncate text-fg2 max-md:order-last max-md:ml-0 max-md:max-w-none max-md:basis-full max-md:text-fg3" title={state}>
        {state}
      </span>
      <span className="shrink-0 max-md:ml-auto">
        <StatusBadge info={CVE_STATUS[c.status]} label={proxmox && c.status === "unknown" ? (c.reviewed_at ? "Unbekannt: geprüft" : "Unbekannt: manuell prüfen") : shortLabel(c.status)} />
      </span>
      <button
        type="button"
        onClick={() => onOpen(c)}
        aria-label={`Details zu ${c.cve_id}`}
        className="inline-flex size-6 shrink-0 items-center justify-center rounded-xs border border-control text-fg2 hover:bg-sunk max-md:size-11"
      >
        <span aria-hidden="true">⋯</span>
      </button>
    </li>
  );
}

/** Kurze Chip-Beschriftungen für die dichte Zeile; Icon + Text, nie nur Farbe. */
function shortLabel(s: CveStatus): string {
  return s === "fixed_installed_reboot_required" ? "Neustart nötig" : CVE_STATUS[s].label;
}

function Detail({ c, host, running, busy, onReview }: { c: HostCve; host: Host; running: string | null; busy: boolean; onReview: (v: boolean) => void }) {
  return (
    <div className="space-y-3 text-sm">
      <p className="flex flex-wrap items-center gap-2">
        <StatusBadge info={CVE_STATUS[c.status]} label={host.is_proxmox && c.status === "unknown" ? "Unbekannt: manuell prüfen" : undefined} />
        <Link href={`/cves/${c.cve_id}`} className="mono">
          Zur CVE-Seite
        </Link>
        {c.level ? <span className="text-xs text-fg3">Level {c.level}/10</span> : null}
      </p>
      <p className="text-fg2">{hostState(c, running, host.is_proxmox)}</p>
      <p className="break-words">
        <Linkified text={c.reason} />
      </p>
      {c.description ? <p className="text-fg3">{c.description}</p> : null}
      {c.sources.length > 0 ? (
        <div className="max-w-full overflow-x-auto">
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
                  <td className="pr-3">
                    <Mono>{s.package}</Mono>
                  </td>
                  <td className="pr-3">{s.status}</td>
                  <td>
                    <Mono>{s.fix_version ?? "–"}</Mono>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <p className="text-xs text-fg3">
        Letzte Änderung {absTime(c.computed_at)}
        {c.source ? <> · Quelle {c.source}</> : null}
      </p>
      <label className="flex min-h-8 items-start gap-2 py-1 max-md:min-h-11 max-md:items-center">
        <input
          type="checkbox"
          className="mt-0.5 size-4 accent-[var(--accent)] max-md:mt-0 max-md:size-5"
          checked={Boolean(c.reviewed_at)}
          disabled={busy}
          onChange={(e) => onReview(e.target.checked)}
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
          <span className="block text-xs text-fg3">Gilt nur für den aktuellen Kernel; der Status ändert sich dadurch nicht.</span>
        </span>
      </label>
    </div>
  );
}
